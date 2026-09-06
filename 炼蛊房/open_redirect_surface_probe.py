#!/usr/bin/env python3
"""开放重定向表面（HITCON returnUrl / 控制字元）。

不跟随跳转。L2= Location 或 Refresh 指到外域探测 URL。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

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

UA = "Mozilla/5.0 大爱仙尊-open-redir"
PARAMS = ("next", "redirect", "returnUrl", "return_url", "url", "dest", "continue", "goto", "redirect_uri")
PATHS = ("/", "/login", "/signin", "/auth/login", "/account/login")
PROBE = "https://example.com/se-open-redirect"


def _ext(loc: str) -> bool:
    if not loc:
        return False
    if loc.lower().startswith(("https://example.com", "http://example.com")):
        return True
    host = (urlparse(loc).hostname or "").lower()
    return host == "example.com" or host.endswith(".example.com")


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
        clean = urljoin(base + "/", p.lstrip("/"))
        try:
            base_r = sess.get(clean, timeout=10, verify=False, allow_redirects=False)
        except Exception:
            continue
        base_loc = base_r.headers.get("Location") or ""
        for name in PARAMS:
            url = f"{clean}{'&' if '?' in clean else '?'}{urlencode({name: PROBE})}"
            try:
                r = sess.get(url, timeout=10, verify=False, allow_redirects=False)
            except Exception:
                continue
            loc = r.headers.get("Location") or ""
            refresh = r.headers.get("Refresh") or ""
            if r.status_code in {301, 302, 303, 307, 308} and loc and loc != base_loc:
                findings.append({"level": "L1", "signal": "redirect-param", "path": p, "param": name, "status": r.status_code})
            if _ext(loc) or _ext(refresh):
                findings.append({
                    "level": "L2",
                    "signal": "open-redirect",
                    "path": p,
                    "param": name,
                    "location": (loc or refresh)[:160],
                })
                print(f"  L2 {p}?{name}= → {loc[:80]}")
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
        "playbook": "传承/暗渡陈仓·2.md",
        "next": "L2=跳到 example.com。ATO 链可并行；不打通报厂商。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="open_redirect", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="开放重定向表面（授权内）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
