#!/usr/bin/env python3
"""Shopline 店铺 L1 指纹（授权范围内）。

抽 window.mainConfig，认 Cookie / 页脚。不打平台域。
可选 --reset-known / --reset-unknown 做密码重置差异（只比较状态码和长度）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from probe_http import get, post, session  # noqa: E402
from scope_lib import host_of, is_denied, require_in_scope, write_probe_json  # noqa: E402

PLATFORM = (
    "shoplineapp.com",
    "admin.shoplineapp.com",
    "cdn.shoplineapp.com",
    "shoplineimg.com",
)

CFG_RE = re.compile(r"window\.mainConfig\s*=\s*(\{.*?\});", re.DOTALL)
KEYS = (
    "merchantId",
    "handle",
    "plan",
    "recaptchaSitekey",
    "tradevanUbn",
    "currency",
    "locale",
)


def _platform(host: str) -> bool:
    h = host.lower().strip(".")
    for p in PLATFORM:
        if h == p or h.endswith("." + p):
            return True
    return False


def _extract_cfg(html: str) -> dict[str, Any] | None:
    m = CFG_RE.search(html or "")
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def probe(base: str, *, reset_known: str = "", reset_unknown: str = "") -> dict[str, Any]:
    base = base.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    host = host_of(base)
    if _platform(host) or is_denied(host):
        raise SystemExit(f"[deny] 平台/基础设施域不打: {host}")
    require_in_scope(base)

    out: dict[str, Any] = {
        "base": base,
        "host": host,
        "fingerprint": [],
        "mainconfig_keys": {},
        "l1": False,
        "reset_enum": None,
    }
    s = session()
    r = get(base + "/", sess=s, timeout=15)
    out["home_status"] = r.status
    out["home_error"] = r.error or ""
    html = r.text or ""
    cookie = " ".join(f"{k}={v}" for k, v in (r.headers or {}).items() if k.lower() == "set-cookie")
    cookie += " " + str(getattr(r.raw, "headers", {}) or "")
    if "shopline" in html.lower():
        out["fingerprint"].append("page:shopline")
    if "mainConfig" in html:
        out["fingerprint"].append("mainConfig")
    if "ng-controller" in html:
        out["fingerprint"].append("angularjs")
    if "_shop_shopline_session" in (cookie + html):
        out["fingerprint"].append("session_cookie")

    cfg = _extract_cfg(html)
    if cfg:
        for k in KEYS:
            if k in cfg and cfg[k] not in (None, ""):
                out["mainconfig_keys"][k] = cfg[k]
        out["l1"] = bool(out["mainconfig_keys"].get("merchantId") or out["mainconfig_keys"].get("handle"))

    if reset_known and reset_unknown:
        enum: dict[str, Any] = {}
        for label, email in (("known", reset_known), ("unknown", reset_unknown)):
            url = urljoin(base + "/", "api/users/password")
            pr = post(url, sess=s, json={"email": email}, timeout=12)
            if not pr.ok:
                url = urljoin(base + "/", "users/password")
                pr = post(url, sess=s, data={"user[email]": email}, timeout=12)
            enum[label] = {
                "status": pr.status,
                "len": len(pr.text or ""),
                "error": pr.error or "",
            }
        a, b = enum.get("known") or {}, enum.get("unknown") or {}
        enum["differ"] = (a.get("status") != b.get("status")) or (a.get("len") != b.get("len"))
        out["reset_enum"] = enum
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Shopline 店铺 L1 指纹（授权内）")
    ap.add_argument("--base", required=True, help="已授权店铺 https://")
    ap.add_argument("--case", default="", help="案卷名")
    ap.add_argument("--out", default="", help="JSON 输出路径")
    ap.add_argument("--reset-known", default="", help="已注册测试邮箱（只比差异）")
    ap.add_argument("--reset-unknown", default="", help="未注册对照邮箱")
    args = ap.parse_args()
    data = probe(
        args.base,
        reset_known=args.reset_known,
        reset_unknown=args.reset_unknown,
    )
    dest = Path(args.out) if args.out else None
    path = write_probe_json(
        data,
        case=args.case,
        out=dest,
        case_subdir="shopline",
        filename="shopline_l1.json",
    )
    print(json.dumps({"l1": data["l1"], "keys": list(data["mainconfig_keys"]), "out": str(path)}, ensure_ascii=False))
    return 0 if data.get("home_status") else 2


if __name__ == "__main__":
    raise SystemExit(main())
