#!/usr/bin/env python3
"""WordPress xmlrpc.php 暴露面（授权范围内）。

只 GET 说明页 + 一次 system.listMethods。
不发 system.multicall 撞密，不发 pingback.ping。
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

UA = "Mozilla/5.0 大爱仙尊-wp-xmlrpc"
XMLRPC_PATHS = (
    "/xmlrpc.php",
    "/wp/xmlrpc.php",
    "/blog/xmlrpc.php",
    "/wordpress/xmlrpc.php",
)
LIST_METHODS = (
    '<?xml version="1.0"?>'
    "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"
)
INTERESTING = ("system.multicall", "pingback.ping", "wp.getusersblogs", "wp.getusers")


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
        "accepts_post": "xml-rpc server accepts post" in text.lower(),
        "xmlish": (
            text.lstrip().startswith("<?xml")
            or any(t in (r.headers.get("Content-Type") or "").lower() for t in ("text/xml", "application/xml"))
        ),
        "snip": re.sub(r"\s+", " ", text)[:160],
    }


def _list_methods(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.post(
            url,
            data=LIST_METHODS,
            headers={"Content-Type": "text/xml"},
            timeout=12,
            verify=False,
            allow_redirects=True,
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    methods = [m.lower() for m in re.findall(r"<string>([^<]+)</string>", text)]
    hits = [n for n in INTERESTING if any(n in m for m in methods)]
    return {
        "url": url,
        "status": r.status_code,
        "method_count": len(methods),
        "interesting": hits,
        "has_multicall": "system.multicall" in hits,
        "has_pingback": "pingback.ping" in hits,
        "snip": re.sub(r"\s+", " ", text)[:160],
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
    for p in XMLRPC_PATHS:
        url = urljoin(base + "/", p.lstrip("/"))
        row = _get(sess, url)
        if row.get("error"):
            continue
        listed = _list_methods(sess, url) if row.get("status") in {200, 405, 500} else {}
        alive = bool(
            row.get("accepts_post")
            or row.get("xmlish")
            or row.get("status") == 405
            or listed.get("method_count")
        )
        if not alive:
            continue
        row.update({"level": "L1", "signal": "xmlrpc-get", "path": p})
        findings.append(row)
        print(f"  L1 get {p}")
        if listed.get("method_count"):
            lvl = "L2" if listed.get("interesting") else "L1"
            listed.update({"level": lvl, "signal": "listMethods", "path": p})
            findings.append(listed)
            print(f"  {lvl} listMethods {p} n={listed['method_count']} {listed.get('interesting')}")
        break
    level = "none"
    if any(f.get("level") == "L2" for f in findings):
        level = "L2"
    elif findings:
        level = "L1"
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/坞·旧令.md",
        "next": "L2=multicall/pingback 暴露。禁止撞密与 pingback 内网。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="wp_xmlrpc", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="WordPress xmlrpc 表面（listMethods only）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
