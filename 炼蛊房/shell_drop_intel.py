#!/usr/bin/env python3
"""WP 高熵 PHP 马情报：ingest 清单 / 授权站猎列表 / 与 scope 重叠。

禁止：把情报域名 --grant；禁止对未授权 host hunt；禁止把随机文件名当爆破字典。
"""
from __future__ import annotations

import argparse
import json
import sys
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
from wp_drop_lib import WEB_DROP_DIRS, dump_stats, extract_drop_hrefs, parse_shell_url_dump  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-shell-drop"
FINGERPRINT = ROOT / "docs" / "intel" / "shell-drops" / "wp-11char-php.json"


def _write_fingerprint(stats: dict[str, Any]) -> None:
    FINGERPRINT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "id": "wp-mixed-11char-php",
        "updated": datetime.now(UTC).isoformat(),
        "usable_next": True,
        "rule": "11-char [A-Za-z0-9].php AND mixed case",
        "dirs_seen": stats.get("dir_prefix") or {},
        "last_ingest_n": stats.get("n"),
        "last_ingest_hosts": stats.get("hosts"),
        "not_a_wordlist": True,
        "playbook": "传承/坞壳落子猎.md",
    }
    FINGERPRINT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cmd_ingest(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text(encoding="utf-8", errors="ignore")
    rows = parse_shell_url_dump(text)
    stats = dump_stats(rows)
    overlap = [r for r in rows if in_scope(r["host"])]
    _write_fingerprint(stats)
    report = {
        "ts": datetime.now(UTC).isoformat(),
        "source": str(Path(args.file).name),
        "stats": stats,
        "overlap_in_scope": [{"host": r["host"], "path": r["path"]} for r in overlap],
        "overlap_n": len(overlap),
        "granted": False,
        "next": (
            "重叠主机走 hunt / host_ir；连马先问"
            if overlap
            else "无授权重叠；情报域名禁止 --grant；授权 WP 用 hunt"
        ),
    }
    out = write_probe_json(
        report, case=args.case or "", out=Path(args.out) if args.out else None,
        case_subdir="shell_drop", filename="ingest.json",
    )
    print(json.dumps({
        "n": stats["n"],
        "hosts": stats["hosts"],
        "drop_names": stats["drop_names"],
        "overlap_n": len(overlap),
        "fingerprint": str(FINGERPRINT.relative_to(ROOT)),
        "out": str(out),
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    host = host_of(args.url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        return 2
    base = args.url.rstrip("/") + "/"
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    hits: list[dict[str, Any]] = []
    wp = False
    try:
        r = sess.get(urljoin(base, "wp-includes/version.php"), timeout=10, verify=False, allow_redirects=True)
        if r.ok and ("$wp_version" in r.text or "wp_version" in r.text):
            wp = True
    except Exception:
        pass
    for d in WEB_DROP_DIRS:
        try:
            r = sess.get(urljoin(base, d.lstrip("/")), timeout=10, verify=False, allow_redirects=True)
        except Exception:
            continue
        if r is None or r.status_code >= 400:
            continue
        names = extract_drop_hrefs(r.text)
        if names:
            hits.append({"dir": d, "status": r.status_code, "names": names})
    report = {
        "ts": datetime.now(UTC).isoformat(),
        "base": args.url,
        "wp_hint": wp,
        "hits": hits,
        "playbook": "传承/坞壳落子猎.md",
        "next": "命中只记存在性；连蚁剑/清马先问" if hits else "无目录列表或无名；改 host_ir / 日志",
    }
    out = write_probe_json(
        report, case=args.case or "", out=Path(args.out) if args.out else None,
        case_subdir="shell_drop", filename="hunt.json",
    )
    print(json.dumps({"wp_hint": wp, "hit_dirs": len(hits), "hits": hits, "out": str(out)}, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="WP 高熵 PHP 马情报 / 授权狩猎")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_in = sub.add_parser("ingest", help="解析 shell 目录文本，只做统计+scope 重叠")
    p_in.add_argument("--file", required=True)
    p_in.add_argument("--case", default="")
    p_in.add_argument("--out", default="")
    p_h = sub.add_parser("hunt", help="授权站：列目录筛高熵 php")
    p_h.add_argument("--url", required=True)
    p_h.add_argument("--case", default="")
    p_h.add_argument("--out", default="")
    args = ap.parse_args()
    if args.cmd == "ingest":
        return cmd_ingest(args)
    return cmd_hunt(args)


if __name__ == "__main__":
    raise SystemExit(main())
