#!/usr/bin/env python3
"""HTTP 方法 / WebDAV 表面（授权目标）。只写 marker，不删生产文件。

用法:
  python3 炼蛊房/http_method_surface_probe.py --base https://授权站 --case <案>
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
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-http-method"
MARKER_NAME = "se-http-method-marker.txt"
MARKER_BODY = "se-http-method-marker"
INTERESTING = {"PUT", "DELETE", "MOVE", "COPY", "PROPFIND", "MKCOL", "TRACE", "TRACK"}


def parse_allow(header: str) -> set[str]:
    return {x.strip().upper() for x in (header or "").split(",") if x.strip()}


def _call(sess: requests.Session, method: str, url: str, timeout: int, **kw: Any):
    try:
        return sess.request(
            method, url, timeout=timeout, verify=False, allow_redirects=False, **kw
        )
    except Exception:
        return None


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/") + "/"
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []

    opt = _call(sess, "OPTIONS", base, args.timeout)
    allow: set[str] = set()
    dav = ""
    if opt is not None:
        allow = parse_allow(opt.headers.get("Allow", ""))
        dav = opt.headers.get("DAV", "") or opt.headers.get("Public", "")
        if allow & INTERESTING or dav:
            findings.append({
                "level": "L1",
                "signal": "options-allow",
                "allow": sorted(allow),
                "dav": dav[:80],
                "status": opt.status_code,
            })

    for method in ("TRACE", "TRACK"):
        r = _call(sess, method, base, args.timeout, headers={"X-SE-Trace": "1"})
        if r is None:
            continue
        blob = (r.text or "") + str(r.headers)
        if r.status_code < 400 and ("X-SE-Trace" in blob or method in (r.text or "")):
            findings.append({"level": "L1", "signal": "trace-echo", "method": method, "status": r.status_code})
            print(f"  L1 {method} echo")

    prop = _call(
        sess,
        "PROPFIND",
        base,
        args.timeout,
        headers={"Depth": "0", "Content-Type": "text/xml"},
        data="<?xml version='1.0'?><propfind xmlns='DAV:'><prop><resourcetype/></prop></propfind>",
    )
    if prop is not None and prop.status_code in {207, 200} and (
        "DAV:" in (prop.text or "") or "multistatus" in (prop.text or "").lower()
    ):
        findings.append({"level": "L1", "signal": "propfind", "status": prop.status_code})
        print("  L1 PROPFIND")

    marker_url = urljoin(base, MARKER_NAME)
    put = _call(
        sess,
        "PUT",
        marker_url,
        args.timeout,
        data=MARKER_BODY,
        headers={"Content-Type": "text/plain"},
    )
    if put is not None and put.status_code in {200, 201, 204}:
        got = _call(sess, "GET", marker_url, args.timeout)
        if got is not None and MARKER_BODY in (got.text or ""):
            findings.append({"level": "L2", "signal": "put-persist", "url": marker_url, "status": put.status_code})
            print(f"  L2 PUT {marker_url}")
            dest = urljoin(base, "se-http-method-moved.txt")
            moved = _call(sess, "MOVE", marker_url, args.timeout, headers={"Destination": dest})
            if moved is not None and moved.status_code in {201, 204, 207}:
                chk = _call(sess, "GET", dest, args.timeout)
                if chk is not None and MARKER_BODY in (chk.text or ""):
                    findings.append({"level": "L3", "signal": "move", "url": dest})
                    print(f"  L3 MOVE → {dest}")

    level = "none"
    for want in ("L3", "L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "allow": sorted(allow),
        "findings": findings,
        "playbook": "传承/信网柜.md",
        "skill": "信网柜",
        "next": "L2=PUT marker 回读。ownCloud 走专卡。不 DELETE。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="http_method", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="HTTP 方法/WebDAV 表面（授权内，只写 marker）")
    ap.add_argument("--base", "-u", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--timeout", type=int, default=8)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
