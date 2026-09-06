#!/usr/bin/env python3
"""大爱仙尊 CORS / CSRF 作业探针。

CORS：Origin 矩阵（反射 / null / 前后缀 / *+Credentials）。
CSRF：SameSite、表单 token；有 --post 再打无 Origin / 恶 Origin。
WP /wp-json 反射走 wp-rest-cors-ato，不要用本卡结案。

示例:
  python3 炼蛊房/cors_csrf_probe.py cors --url https://授权/api/user/info --case <案>
  python3 炼蛊房/cors_csrf_probe.py csrf --url https://授权/ --case <案>
  python3 炼蛊房/cors_csrf_probe.py csrf --url https://授权/ --post https://授权/api/profile --cookie 'sid=1' --case <案>
  python3 炼蛊房/cors_csrf_probe.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any
from urllib.parse import urlparse

OPS = __import__("pathlib").Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from probe_http import get, post, session  # noqa: E402
from scope_lib import require_in_scope, write_probe_json  # noqa: E402

EVIL = "https://evil.daaixianzun.test"
TOKEN_RX = re.compile(
    r'''name=["'](?:_token|csrf|_csrf|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token)["']''',
    re.I,
)
SESSION_RX = re.compile(
    r"(phpsessid|jsessionid|session(?:id)?|laravel_session|remember(?:_web)?|sid|jwt)=",
    re.I,
)


def grade_cors(acao: str, acac: str, sent: str) -> tuple[str, str]:
    cred = acac.strip().lower() == "true"
    if acao == sent and cred:
        return "L2", "reflect-cred"
    if acao == "*" and cred:
        return "L2", "star-cred"
    if acao == sent:
        return "L1", "reflect"
    if acao == "*":
        return "L1", "star"
    if acao == "null" and sent == "null":
        return "L2" if cred else "L1", "null"
    return "", ""


def origin_matrix(url: str) -> list[str]:
    host = urlparse(url).hostname or "target.test"
    return [
        EVIL,
        "null",
        f"https://evil.{host}",
        f"https://{host}.evil.daaixianzun.test",
        "https://daaixianzun.test",
    ]


def _h(headers: dict[str, str], name: str) -> str:
    want = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == want:
            return str(v)
    return ""


def probe_cors(url: str) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    hits = []
    for origin in origin_matrix(url):
        r = get(url, sess=s, headers={"Origin": origin}, timeout=12)
        acao = _h(r.headers, "Access-Control-Allow-Origin")
        acac = _h(r.headers, "Access-Control-Allow-Credentials")
        acah = _h(r.headers, "Access-Control-Allow-Headers")
        level, signal = grade_cors(acao, acac, origin)
        rec = {
            "origin": origin,
            "status": r.status,
            "acao": acao,
            "acac": acac,
            "acah": acah[:120],
            "level": level,
            "signal": signal,
            "error": r.error or "",
        }
        if "authorization" in acah.lower():
            rec["auth_header_allowed"] = True
            if not level:
                rec["level"] = "L1"
                rec["signal"] = "allow-authorization"
        if level or rec.get("auth_header_allowed"):
            hits.append(rec)
    levels = {h["level"] for h in hits}
    return {
        "url": url,
        "hits": hits,
        "l2": "L2" in levels,
        "l1": bool(hits),
        "playbook": "传承/借刀杀人·借窗.md",
    }


def _cookie_flags(set_cookie: str) -> dict[str, Any]:
    low = set_cookie.lower()
    return {
        "sessionish": bool(SESSION_RX.search(set_cookie)),
        "samesite": (
            "strict" if "samesite=strict" in low else "lax" if "samesite=lax" in low else "none" if "samesite=none" in low else ""
        ),
        "httponly": "httponly" in low,
        "secure": "secure" in low,
    }


def probe_csrf(url: str, *, post_url: str = "", extra_headers: dict[str, str]) -> dict[str, Any]:
    require_in_scope(url)
    if post_url:
        require_in_scope(post_url)
    s = session()
    r0 = get(url, sess=s, headers=extra_headers or None, timeout=12)
    flags = _cookie_flags(_h(r0.headers, "Set-Cookie"))
    body = r0.text or ""
    has_form = "<form" in body.lower()
    has_token = bool(TOKEN_RX.search(body))
    rec: dict[str, Any] = {
        "url": url,
        "status": r0.status,
        "cookie": flags,
        "has_form": has_form,
        "has_token": has_token,
        "posts": [],
        "playbook": "传承/借刀杀人.md",
    }
    weak_ss = flags["sessionish"] and flags["samesite"] in ("", "none")
    rec["l1"] = bool(weak_ss or (has_form and not has_token))
    if post_url:
        variants = (
            ("no-origin", {}),
            ("evil-origin", {"Origin": EVIL, "Referer": EVIL + "/"}),
        )
        for name, hdr in variants:
            h = dict(extra_headers)
            h.update(hdr)
            r = post(post_url, sess=s, headers=h or None, data=b"{}", timeout=12)
            rec["posts"].append(
                {
                    "kind": name,
                    "status": r.status,
                    "len": len(r.text or ""),
                    "error": r.error or "",
                }
            )
        rec["l2"] = any(p["status"] in (200, 201, 204) and not p["error"] for p in rec["posts"])
        if rec["l2"] and rec["posts"]:
            rec["note"] = "无 Origin / 恶 Origin 仍 2xx，还要看是不是真改了状态，不要只报状态码"
    else:
        rec["l2"] = False
        rec["note"] = "只有 L1 指纹。要 L2 加 --post 状态改变接口"
    return rec


def run_self_test() -> list[str]:
    fails: list[str] = []
    if grade_cors("https://evil.daaixianzun.test", "true", EVIL) != ("L2", "reflect-cred"):
        fails.append("reflect-cred")
    if grade_cors("*", "true", EVIL) != ("L2", "star-cred"):
        fails.append("star-cred")
    if grade_cors("*", "", EVIL) != ("L1", "star"):
        fails.append("star")
    if grade_cors("https://other.test", "true", EVIL) != ("", ""):
        fails.append("neg")
    mx = origin_matrix("https://app.victim.test/api")
    if "https://evil.app.victim.test" not in mx or "https://app.victim.test.evil.daaixianzun.test" not in mx:
        fails.append("matrix")
    flags = _cookie_flags("Set-Cookie: PHPSESSID=a; Path=/")
    if not flags["sessionish"] or flags["samesite"]:
        fails.append("cookie")
    if not TOKEN_RX.search('<input name="csrfmiddlewaretoken" value="x">'):
        fails.append("token")
    return fails


def _headers(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if raw.lower().startswith("cookie="):
            out["Cookie"] = raw.split("=", 1)[1]
            continue
        if ":" not in raw:
            raise SystemExit(f"--header 要 Name: value：{raw}")
        k, v = raw.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 CORS / CSRF")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    p_co = sub.add_parser("cors")
    p_co.add_argument("--url", required=True)
    p_co.add_argument("--case", default="")
    p_cs = sub.add_parser("csrf")
    p_cs.add_argument("--url", required=True)
    p_cs.add_argument("--post", default="", help="状态改变接口")
    p_cs.add_argument("--cookie", default="")
    p_cs.add_argument("--header", action="append", default=[])
    p_cs.add_argument("--case", default="")
    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  cors_csrf")
        return 0
    if args.cmd == "cors":
        data = probe_cors(args.url)
        path = write_probe_json(data, case=args.case, case_subdir="cors_csrf", filename="cors.json")
        print(json.dumps({"l1": data.get("l1"), "l2": data.get("l2"), "hits": data.get("hits"), "out": str(path)}, ensure_ascii=False))
        return 0 if data.get("l1") or data.get("l2") else 1
    if args.cmd == "csrf":
        extra = _headers(args.header)
        if args.cookie:
            extra["Cookie"] = args.cookie
        data = probe_csrf(args.url, post_url=args.post, extra_headers=extra)
        path = write_probe_json(data, case=args.case, case_subdir="cors_csrf", filename="csrf.json")
        slim = {k: data[k] for k in data if k != "playbook"}
        print(json.dumps({**slim, "out": str(path)}, ensure_ascii=False))
        return 0 if data.get("l1") or data.get("l2") else 1
    ap.error("需要 cors / csrf / --self-test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
