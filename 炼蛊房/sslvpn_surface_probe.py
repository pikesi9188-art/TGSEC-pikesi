#!/usr/bin/env python3
"""企业 SSL VPN 门户指纹（授权范围内，只 GET）。

网站案默认降权：只认产品，不发 1day。FortiOS 专洞走 FortiOS 卡。
针必须是产品特征，禁止用路径片段（404 回显 URI 会假阳性）。
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

UA = "Mozilla/5.0 大爱仙尊-sslvpn"
# path, product, body/cookie needles（不得是路径自身片段）
PROBES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("/+CSCOE+/logon.html", "cisco-asa", ("anyconnect", "webvpncontext", "webvpn=", "webvpnlogin")),
    ("/remote/login", "fortigate", ("fortigate", "fortinet", "svpncookie")),
    ("/vpn/index.html", "citrix-netscaler", ("citrix gateway", "netscaler", "nsc_aaa", "citrix_ns_id")),
    ("/global-protect/login.esp", "paloalto-gp", ("globalprotect", "this is globalprotect", "panos")),
    ("/dana-na/auth/url_default/welcome.cgi", "ivanti-pulse", ("pulse connect", "dsauthsession", "ive-auth", "ivanti")),
)


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    hdrs = {k.lower(): v[:200] for k, v in r.headers.items()}
    text = r.text or ""
    cookie = hdrs.get("set-cookie", "")
    return {
        "url": url,
        "status": r.status_code,
        "set_cookie": cookie[:200],
        "server": hdrs.get("server", "")[:80],
        "snip": re.sub(r"\s+", " ", text)[:180],
        "blob": (text + " " + cookie).lower(),
        "cookie": cookie.lower(),
    }


def _hit(blob: str, cookie: str, needles: tuple[str, ...]) -> bool:
    hay = (blob or "") + " " + (cookie or "")
    return any(n in hay for n in needles)


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    home = _get(sess, base + "/")
    cookie = (home.get("cookie") or "") + " " + (home.get("set_cookie") or "").lower()
    if "bigipserver" in (home.get("blob") or "") or "bigip" in cookie:
        findings.append({"level": "L1", "signal": "f5-bigip", "product": "f5"})
        print("  L1 F5 BIGip cookie")
    for path, product, needles in PROBES:
        row = _get(sess, urljoin(base + "/", path.lstrip("/")))
        st = int(row.get("status") or 0)
        if st >= 500 or row.get("error"):
            continue
        if st not in {200, 302, 401}:
            continue
        if not _hit(row.get("blob") or "", row.get("cookie") or "", needles):
            continue
        rec = {
            "level": "L1",
            "signal": "sslvpn-portal",
            "product": product,
            "path": path,
            "status": st,
        }
        if product == "fortigate":
            rec["next"] = "传承/雾门·旁路.md"
        findings.append(rec)
        print(f"  L1 {product} {path} {st}")
    level = "L1" if findings else "none"
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/雾门·辨.md",
        "next": "网站案默认降权。FortiGate 交接 FortiOS 专卡。禁止 Cisco VPN DoS。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="sslvpn", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="SSL VPN 门户指纹（只 GET）")
    ap.add_argument("-u", "--url", "--base", dest="base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
