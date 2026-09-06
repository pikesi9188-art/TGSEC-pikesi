#!/usr/bin/env python3
"""WordPress JetEngine CVE-2026-66613 版本闸（授权范围内，只 GET readme）。

L1：Stable tag 存在且 <= 3.8.14。已修 3.8.14.1+ 不算。
不发送 SSTI。
"""
from __future__ import annotations

import argparse
import json
import re
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
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-jetengine"
README = "/wp-content/plugins/jet-engine/readme.txt"
AFFECTED = (3, 8, 14)


def _parse_tag(text: str) -> str:
    m = re.search(r"(?im)^stable tag:\s*([0-9.]+)", text or "")
    return m.group(1) if m else ""


def _tup(ver: str) -> tuple[int, ...]:
    parts = []
    for x in (ver or "").split("."):
        try:
            parts.append(int(x))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _affected(ver: str) -> bool:
    if not ver:
        return False
    t = _tup(ver)
    # 3.8.14 及更早中招；3.8.14.1 / 3.8.15 / 3.9 已修
    n = max(len(t), len(AFFECTED))
    a = t + (0,) * (n - len(t))
    b = AFFECTED + (0,) * (n - len(AFFECTED))
    return a <= b


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    url = urljoin(base + "/", README.lstrip("/"))
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
        text = r.text or ""
        status = r.status_code
    except Exception as e:
        print(json.dumps({"error": str(e)[:120]}, ensure_ascii=False))
        sys.exit(1)
    ver = _parse_tag(text) if status == 200 else ""
    present = status == 200 and "jetengine" in text.lower() and "stable tag" in text.lower()
    vuln = present and _affected(ver)
    level = "L1" if vuln else ("present-patched" if present else "none")
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": "L1" if vuln else "none",
        "plugin_present": present,
        "stable_tag": ver,
        "affected_le": "3.8.14",
        "vulnerable": vuln,
        "status": status,
        "playbook": "传承/坞·喷机.md",
        "next": (
            "L1 → 记版本，禁止自造 SSTI。"
            if vuln
            else "插件不在或已 ≥3.8.14.1。其它 WP 插件走 wordpress-plugin-unauth-takeover。"
        ),
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="jetengine", filename="surface.json",
    )
    print(json.dumps({"level": report["level"], "stable_tag": ver, "vulnerable": vuln, "out": str(out_path)}, ensure_ascii=False))
    if present:
        print(f"  jet-engine {ver or '?'} vuln={vuln}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="JetEngine 版本闸（只读 readme）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
