#!/usr/bin/env python3
"""OAuth/OIDC 授权码流表面（授权目标）。不换他人 code，不打 password grant。

用法:
  python3 炼蛊房/oauth_oidc_surface_probe.py --base https://授权站 --case <案>
  python3 炼蛊房/oauth_oidc_surface_probe.py --base https://授权站 --case <案> --client-id web
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

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

UA = "Mozilla/5.0 大爱仙尊-oauth-oidc"
PROBE_REDIR = "https://example.com/se-oauth"
WELL_KNOWN = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
)


def redirect_is_external(location: str, probe: str = PROBE_REDIR) -> bool:
    if not location:
        return False
    loc = location.strip()
    if loc.lower().startswith(probe.lower()):
        return True
    host = (urlparse(loc).hostname or "").lower()
    return host == "example.com" or host.endswith(".example.com")


def _json(r) -> dict[str, Any]:
    try:
        data = r.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    auth_ep = ""
    token_ep = ""

    for path in WELL_KNOWN:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = sess.get(url, timeout=args.timeout, verify=False, allow_redirects=False)
        except Exception:
            continue
        data = _json(r) if r.status_code == 200 else {}
        if data.get("authorization_endpoint") or data.get("issuer"):
            auth_ep = str(data.get("authorization_endpoint") or "")
            token_ep = str(data.get("token_endpoint") or "")
            findings.append({
                "level": "L1",
                "signal": "oidc-discovery",
                "path": path,
                "issuer": str(data.get("issuer") or "")[:120],
            })
            print(f"  L1 discovery {path}")
            break

    if not auth_ep:
        for guess in ("/oauth/authorize", "/oauth2/authorize", "/connect/authorize", "/sso/authorize"):
            url = urljoin(base + "/", guess.lstrip("/"))
            try:
                r = sess.get(url, timeout=args.timeout, verify=False, allow_redirects=False)
            except Exception:
                continue
            if r.status_code in {200, 302, 303, 400, 401}:
                auth_ep = url
                findings.append({"level": "L1", "signal": "authorize-guess", "path": guess, "status": r.status_code})
                break

    if auth_ep and args.client_id:
        qs = (
            f"client_id={args.client_id}&response_type=code"
            f"&redirect_uri={PROBE_REDIR}&scope=openid"
        )
        url = f"{auth_ep}{'&' if '?' in auth_ep else '?'}{qs}"
        try:
            r = sess.get(url, timeout=args.timeout, verify=False, allow_redirects=False)
        except Exception:
            r = None
        loc = (r.headers.get("Location") if r is not None else "") or ""
        if redirect_is_external(loc):
            findings.append({
                "level": "L2",
                "signal": "redirect-uri-accept",
                "location": loc[:160],
            })
            print("  L2 redirect_uri → example.com")
        parsed = parse_qs(urlparse(loc).query)
        if "code" in parsed and redirect_is_external(loc):
            findings.append({"level": "L2", "signal": "code-to-external"})

        # 第一发就不带 state；若仍 200/302，state 不是硬门槛
        if r is not None and r.status_code in {200, 302, 303} and "state=" not in url.lower():
            findings.append({"level": "L1", "signal": "state-optional", "status": r.status_code})

    level = "none"
    for want in ("L3", "L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "authorization_endpoint": auth_ep,
        "token_endpoint": token_ep,
        "findings": findings,
        "playbook": "传承/托印·越权.md",
        "skill": "野炼·oauth",
        "next": "L2=redirect_uri 跳出。password grant 走另一张卡。不换他人 code。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="oauth_oidc", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="OAuth/OIDC 授权码流表面（授权内）")
    ap.add_argument("--base", "-u", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--client-id", default="", help="已知 client_id 才打 redirect_uri")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
