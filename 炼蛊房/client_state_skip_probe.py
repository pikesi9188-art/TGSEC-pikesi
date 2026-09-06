#!/usr/bin/env python3
"""客户端状态窜改面（HITCON ZD-2026-00974 同类）。

L1：页面/JS 把 verified/paid/vip 当可写字段。
L2：把这些字段翻成 true 后，后端响应相对基线变长/变 200。
不改密码、不加款、不耗余额。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

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

UA = "Mozilla/5.0 大爱仙尊-client-state"
FLAGS = (
    "ispaid", "isverified", "isvip", "haspaid", "canride",
    "is_paid", "is_verified", "is_vip", "can_ride", "has_paid",
)
API_GUESSES = (
    "/api/me", "/api/user", "/api/status", "/api/verify", "/api/ride",
    "/api/order", "/api/unlock", "/api/member", "/api/profile",
)
JS_RE = re.compile(r"""(?:src|href)=['"]([^'"]+\.js[^'"]*)['"]""", re.I)
FLAG_RE = re.compile(r"\b(" + "|".join(FLAGS) + r")\b", re.I)


def looks_like_html(text: str) -> bool:
    s = (text or "")[:240].lstrip().lower()
    return s.startswith("<") or "<html" in s or "<!doctype" in s


def flip_is_l2(base_r: dict[str, Any], flip_r: dict[str, Any]) -> bool:
    """401/403→200 且不像 HTML 壳。体长差只算噪声，不当 L2。"""
    if looks_like_html(str(flip_r.get("snip") or "")):
        return False
    return flip_r.get("status") == 200 and base_r.get("status") in {401, 403}


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    return {"url": url, "status": r.status_code, "text": r.text or "", "size": len(r.text or "")}


def _post(sess: requests.Session, url: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        r = sess.post(url, json=body, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    return {"url": url, "status": r.status_code, "size": len(r.text or ""), "snip": re.sub(r"\s+", " ", r.text or "")[:120]}


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    home = _get(sess, base + "/")
    text = home.get("text") or ""
    flags = sorted({m.group(1).lower() for m in FLAG_RE.finditer(text)})
    js_hits: list[str] = []
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    for src in JS_RE.findall(text)[:8]:
        js_url = urljoin(base + "/", src)
        if urlparse(js_url).netloc and urlparse(js_url).netloc != urlparse(base).netloc:
            continue
        row = _get(sess, js_url)
        found = sorted({m.group(1).lower() for m in FLAG_RE.finditer(row.get("text") or "")})
        if found:
            js_hits.extend(found)
            flags = sorted(set(flags) | set(found))
    findings: list[dict[str, Any]] = []
    if flags:
        findings.append({"level": "L1", "signal": "client-flags", "flags": flags, "js": js_hits[:12]})
        print(f"  L1 flags {flags}")

    off = {k: False for k in ("isPaid", "isVerified", "canRide", "hasPaid")}
    on = {k: True for k in off}
    for p in API_GUESSES:
        url = urljoin(base + "/", p.lstrip("/"))
        base_r = _post(sess, url, off)
        if base_r.get("error") or base_r.get("status") in {None, 404, 405, 502, 503}:
            continue
        flip_r = _post(sess, url, on)
        if flip_r.get("error") or flip_r.get("status") in {404, 405, 502, 503}:
            continue
        if flip_is_l2(base_r, flip_r):
            findings.append({
                "level": "L2",
                "signal": "backend-honors-flip",
                "path": p,
                "base_status": base_r.get("status"),
                "flip_status": flip_r.get("status"),
                "base_size": base_r.get("size"),
                "flip_size": flip_r.get("size"),
                "snip": flip_r.get("snip"),
            })
            print(f"  L2 flip {p} {base_r.get('status')}→{flip_r.get('status')}")
            break

    level = "L2" if any(f.get("level") == "L2" for f in findings) else (
        "L1" if findings else "none"
    )
    report = {
        "target": base,
        "origin": origin,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "flags": flags,
        "findings": findings,
        "playbook": "传承/客器·跳步.md",
        "next": "L2=后端吃了客户端 verified/paid。回对象矩阵；禁止耗余额下单。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="client_state", filename="surface.json",
    )
    print(json.dumps({"level": level, "flags": flags, "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="客户端状态窜改面（授权内）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
