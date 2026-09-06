#!/usr/bin/env python3
"""短字典目录/备份面探针（授权范围内）。不做百万级爆破，不自动下载大包。"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-dirbrute"
DICT_DEFAULT = ROOT / "dict" / "gambling_backup_paths.txt"

NEXT_BY_HINT = (
    ((".git", "git"), "有源码 → DeepAudit；密钥回灌假支付"),
    ((".env", "env"), "密钥打码落盘 → 假支付 / 面板"),
    (("phpmyadmin", "pma", "adminer"), "传承/宝塔台.md"),
    (("btpanel", "/bt/", "aapanel"), "传承/宝塔台.md"),
    (("actuator",), "传承/春府·关窍.md"),
    (("graphql",), "python3 炼蛊房/jwt_gql_probe.py"),
    (("swagger", "api-docs"), "python3 main.py authz-probe"),
    (("wp-admin", "wp-login"), "传承/坞·浸染.md"),
    (("wp-includes", "wp-content/uploads"), "传承/坞壳落子猎.md"),
    ((".zip", ".tar", ".sql"), "备份可读 → DeepAudit；拉库先问"),
)


def _load_paths(wordlist: Path) -> list[str]:
    out: list[str] = []
    for line in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if not s.startswith("/"):
            s = "/" + s
        out.append(s)
    extra = [
        "/graphql", "/api/graphql", "/graphiql",
        "/swagger-ui/", "/swagger-ui/index.html", "/v3/api-docs", "/swagger.json",
        "/actuator/health", "/actuator",
    ]
    for p in extra:
        if p not in out:
            out.append(p)
    return list(dict.fromkeys(out))


def _next_for(path: str) -> str:
    pl = path.lower()
    for keys, nxt in NEXT_BY_HINT:
        if any(k in pl for k in keys):
            return nxt
    return "打开确认后切对应专卡；勿加线程硬打"


def _get(sess: requests.Session, url: str, timeout: int) -> requests.Response | None:
    try:
        return sess.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def run(base_url: str, case: str, out: Path | None, wordlist: Path, workers: int) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/") + "/"
    paths = _load_paths(wordlist)
    sess = requests.Session()
    sess.headers["User-Agent"] = UA

    phantom = urljoin(base, "/__se_noexist_" + "x" * 12)
    r404 = _get(sess, phantom, 8)
    baseline_status = r404.status_code if r404 else 404
    baseline_len = len(r404.content) if r404 is not None else -1

    hits: list[dict[str, Any]] = []

    def one(path: str) -> dict[str, Any] | None:
        s = requests.Session()
        s.headers["User-Agent"] = UA
        r = _get(s, urljoin(base, path.lstrip("/")), 8)
        if r is None:
            return None
        n = len(r.content)
        interesting = r.status_code in (200, 206, 301, 302, 401, 403)
        if r.status_code == baseline_status and abs(n - baseline_len) < 24 and baseline_len >= 0:
            return None
        if not interesting:
            return None
        if r.status_code in (301, 302) and n < 80:
            loc = r.headers.get("Location", "")
            if loc.rstrip("/").endswith(path.rstrip("/")):
                return None
        return {
            "path": path,
            "status": r.status_code,
            "length": n,
            "location": r.headers.get("Location", "")[:180],
            "content_type": r.headers.get("Content-Type", "")[:80],
            "next": _next_for(path),
        }

    done = 0
    n = len(paths)
    last_print = 0
    print(f"[*] dirbrute {n} paths  workers={max(1, workers)}  req_timeout=8s", flush=True)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(one, p): p for p in paths}
        for fut in as_completed(futs):
            done += 1
            row = fut.result()
            if row:
                hits.append(row)
                print(f"  [{row['status']}] {row['path']} len={row['length']}", flush=True)
            if done - last_print >= 20 or done == n:
                print(f"  … {done}/{n} paths  hits={len(hits)}", flush=True)
                last_print = done

    hits.sort(key=lambda x: (0 if x["status"] in (200, 206) else 1, x["path"]))
    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "wordlist": str(wordlist),
        "tried": len(paths),
        "baseline_404": {"status": baseline_status, "length": baseline_len},
        "hits": hits,
        "playbook": "传承/月芒.md",
        "next": "200 备份/面板先打开；403 大面积 → IP白名单/WAF，勿加线程",
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="dirbrute", filename="surface.json",
    )
    print(json.dumps({"hits": len(hits), "tried": len(paths), "out": str(out_path)}, ensure_ascii=False))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="短字典目录/备份探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("-w", "--wordlist", type=Path, default=DICT_DEFAULT)
    ap.add_argument("-t", "--threads", type=int, default=8)
    args = ap.parse_args()
    if not args.wordlist.is_file():
        raise SystemExit(f"[err] wordlist not found: {args.wordlist}")
    run(args.url, args.case, args.out, args.wordlist, args.threads)


if __name__ == "__main__":
    main()
