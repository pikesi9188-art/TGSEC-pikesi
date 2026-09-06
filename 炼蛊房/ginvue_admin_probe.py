#!/usr/bin/env python3
"""GIN-VUE-ADMIN / 领奖中心业务 API 探针（CORS / 未授权 / JS挖点 / HPP / 字段探测）。

对齐 Playbook：传承/锦府·赏.md
参考：docs/references/报告-GIN-VUE-ADMIN领奖中心渗透.txt

示例:
  python3 炼蛊房/ginvue_admin_probe.py recon --base http://授权:31282 --case <案卷>
  python3 炼蛊房/ginvue_admin_probe.py cors  --base http://授权:31280 --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import re
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

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-ginvue_admin_probe"

UNAUTH_PATHS = (
    "/api/base/getConfigs",
    "/api/base/getServers",
    "/api/base/getBConfigs",
    "/api/base/captcha",
    "/api/base/getName",
)

HIDDEN_API_HINTS = (
    "/breward",
    "/nreward",
    "/reward",
    "/treward",
    "/api/base/sendCReward",
    "/api/base/getConfigs",
    "/api/base/getServers",
    "/api/base/getBConfigs",
    "/api/base/getName",
    "/api/user/getUserInfo",
    "/api/base/login",
)

JS_PATH_RE = re.compile(
    r"""(?P<p>/(?:api/)?[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+){0,6})""",
)



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "ginvue"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def ssl_ctx(insecure: bool) -> ssl.SSLContext:
    return ssl._create_unverified_context() if insecure else ssl.create_default_context()


def normalize_base(base: str) -> str:
    b = base.strip().rstrip("/")
    if "://" not in b:
        b = "http://" + b
    return b


def http(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    insecure: bool = False,
    timeout: float = 20,
) -> dict[str, Any]:
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx(insecure), timeout=timeout) as resp:
            body = resp.read(2_000_000)
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body.decode("utf-8", errors="replace"),
                "url": url,
            }
    except urllib.error.HTTPError as e:
        body = e.read(2_000_000) if e.fp else b""
        return {
            "ok": False,
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            "body": body.decode("utf-8", errors="replace"),
            "url": url,
            "error": str(e),
        }
    except Exception as e:
        return {"ok": False, "status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}


def save(case: str, name: str, obj: Any) -> Path:
    p = case_dir(case) / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def cmd_unauth(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    out: dict[str, Any] = {"ts": _now(), "base": base, "hits": []}
    for path in UNAUTH_PATHS:
        url = base + path
        if path.endswith("getName"):
            payload = json.dumps(
                {"username": args.username or "admin", "serverid": args.serverid},
                ensure_ascii=False,
            ).encode()
            r = http(
                url,
                method="POST",
                data=payload,
                headers={"Content-Type": "application/json"},
                insecure=args.insecure,
            )
        else:
            r = http(url, insecure=args.insecure)
        snippet = (r.get("body") or "")[:800]
        interesting = r.get("status") == 200 and len(snippet) > 20 and "验证码" not in snippet[:40]
        # captcha endpoint returning image/json is fingerprint
        if path.endswith("captcha") and r.get("status") in (200, 201):
            interesting = True
        item = {
            "path": path,
            "status": r.get("status"),
            "interesting": interesting,
            "body_preview": snippet,
            "error": r.get("error"),
        }
        out["hits"].append(item)
        flag = "HIT" if interesting else "—"
        print(f"  [{flag}] {path} → {r.get('status')} ({len(snippet)}B)")
    path = save(args.case, "unauth.json", out)
    print(f"[ok] {path}")
    return 0


def cmd_cors(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    evil = args.origin or "http://evil.example"
    path = args.path or "/api/user/getUserInfo"
    url = base + (path if path.startswith("/") else "/" + path)
    r = http(
        url,
        method="POST",
        data=b"{}",
        headers={
            "Origin": evil,
            "Content-Type": "application/json",
        },
        insecure=args.insecure,
    )
    h = r.get("headers") or {}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    vulnerable = (acao == evil or acao == "*") and str(acac).lower() == "true"
    out = {
        "ts": _now(),
        "url": url,
        "origin": evil,
        "status": r.get("status"),
        "access-control-allow-origin": acao,
        "access-control-allow-credentials": acac,
        "vulnerable_reflect_credentials": vulnerable,
        "body_preview": (r.get("body") or "")[:400],
    }
    path_out = save(args.case, "cors.json", out)
    print(f"  ACAO={acao!r} ACAC={acac!r} → vuln={vulnerable}")
    print(f"[ok] {path_out}")
    return 0


def cmd_hpp(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    path = args.path or "/api/base/getConfigs"
    url = f"{base}{path}?ID=1&ID=50"
    r = http(url, insecure=args.insecure)
    out = {
        "ts": _now(),
        "url": url,
        "status": r.get("status"),
        "body_preview": (r.get("body") or "")[:800],
        "note": "重复参数未被拒绝即 HPP 面；需结合业务看取首/取末",
    }
    p = save(args.case, "hpp.json", out)
    print(f"  status={r.get('status')} len={len(r.get('body') or '')}")
    print(f"[ok] {p}")
    return 0


def cmd_js_mine(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    index = http(base + "/", insecure=args.insecure)
    html = index.get("body") or ""
    assets = sorted(set(re.findall(r"""(?:src|href)=["']([^"']+\.js[^"']*)["']""", html, re.I)))
    found: set[str] = set()
    scanned: list[str] = []
    for a in assets[:30]:
        u = urllib.parse.urljoin(base + "/", a)
        scanned.append(u)
        jr = http(u, insecure=args.insecure)
        body = jr.get("body") or ""
        for m in JS_PATH_RE.finditer(body):
            p = m.group("p")
            pl = p.lower()
            if any(h in pl for h in ("reward", "config", "captcha", "/api/", "login", "user")):
                found.add(p)
        for hint in HIDDEN_API_HINTS:
            if hint in body or hint.lstrip("/") in body:
                found.add(hint)
    out = {
        "ts": _now(),
        "base": base,
        "index_status": index.get("status"),
        "assets": assets[:30],
        "scanned": scanned,
        "api_candidates": sorted(found),
        "report_hints": list(HIDDEN_API_HINTS),
    }
    p = save(args.case, "js_mine.json", out)
    print(f"  assets={len(assets)} candidates={len(found)}")
    for c in sorted(found)[:40]:
        print(f"    {c}")
    print(f"[ok] {p}")
    return 0


def cmd_enum(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    url = base + "/api/base/getName"
    users = [u.strip() for u in (args.users or "admin,test,root").split(",") if u.strip()]
    rows = []
    for u in users:
        payload = json.dumps({"username": u, "serverid": args.serverid}, ensure_ascii=False).encode()
        r = http(
            url,
            method="POST",
            data=payload,
            headers={"Content-Type": "application/json"},
            insecure=args.insecure,
        )
        body = r.get("body") or ""
        rows.append({"username": u, "status": r.get("status"), "body_preview": body[:300]})
        print(f"  {u}: {r.get('status')} {body[:80]!r}")
    out = {"ts": _now(), "url": url, "rows": rows}
    p = save(args.case, "enum.json", out)
    print(f"[ok] {p}")
    return 0


def cmd_field_probe(args: argparse.Namespace) -> int:
    """用假验证码探测字段名：看「请认真填写」vs「验证码错误」。"""
    base = normalize_base(args.base)
    ensure_scope(base)
    url = base + (args.path or "/api/base/sendCReward")
    variants = [
        {
            "label": "username_field",
            "body": {
                "serverid": args.serverid,
                "username": args.account,
                "name": args.name or "probe",
                "gid": args.gid or "0",
                "configids": "1",
                "configname": "probe",
                "channel": "2",
                "captcha": "00000",
                "captchaId": "probe-id",
            },
        },
        {
            "label": "account_field",
            "body": {
                "serverid": args.serverid,
                "account": args.account,
                "name": args.name or "probe",
                "gid": args.gid or "0",
                "configids": "1",
                "configname": "probe",
                "channel": "2",
                "captcha": "00000",
                "captchaId": "probe-id",
            },
        },
    ]
    rows = []
    for v in variants:
        data = json.dumps(v["body"], ensure_ascii=False).encode()
        r = http(
            url,
            method="POST",
            data=data,
            headers={"Content-Type": "application/json"},
            insecure=args.insecure,
        )
        body = r.get("body") or ""
        hint = "unknown"
        if "认真填写" in body or "格式" in body:
            hint = "bad_field_or_format"
        elif "验证码" in body:
            hint = "format_ok_captcha_gate"  # 报告关键信号
        rows.append(
            {
                "label": v["label"],
                "status": r.get("status"),
                "hint": hint,
                "body_preview": body[:400],
            }
        )
        print(f"  {v['label']}: hint={hint} body={body[:100]!r}")
    out = {"ts": _now(), "url": url, "rows": rows}
    p = save(args.case, "field_probe.json", out)
    print(f"[ok] {p}")
    return 0


def cmd_claim_probe(args: argparse.Namespace) -> int:
    if not args.confirm:
        raise SystemExit("[refuse] 领取探测需 --confirm（可能耗业务/发奖）")
    base = normalize_base(args.base)
    ensure_scope(base)
    url = base + (args.path or "/api/base/sendCReward")
    body = {
        "serverid": args.serverid,
        "account": args.account,
        "name": args.name,
        "gid": args.gid,
        "configids": str(args.configids),
        "configname": args.configname or "",
        "channel": str(args.channel),
        "captcha": args.captcha,
        "captchaId": args.captcha_id,
    }
    r = http(
        url,
        method="POST",
        data=json.dumps(body, ensure_ascii=False).encode(),
        headers={"Content-Type": "application/json"},
        insecure=args.insecure,
    )
    out = {"ts": _now(), "url": url, "request": body, "status": r.get("status"), "body": r.get("body")}
    p = save(args.case, "claim_probe.json", out)
    print(f"  status={r.get('status')} body={(r.get('body') or '')[:200]!r}")
    print(f"[ok] {p}")
    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    """一键：unauth + cors + js-mine + hpp。"""
    base = normalize_base(args.base)
    ensure_scope(base)
    print("== unauth ==")
    cmd_unauth(args)
    print("== cors ==")
    cmd_cors(args)
    print("== js-mine ==")
    cmd_js_mine(args)
    print("== hpp ==")
    cmd_hpp(args)
    meta = {
        "ts": _now(),
        "base": base,
        "next": [
            "field-probe --account <账号>",
            "enum --users admin,test,...",
            "有验证码后再 claim-probe --confirm",
            "后台另端口再跑一遍 recon",
            "CORS 深挖 → nine-stage cors-cross-origin-misconfiguration",
            "领奖逻辑 → free_claim_bypass / business-logic-testing",
        ],
    }
    p = save(args.case, "recon_meta.json", meta)
    print(f"[ok] recon done → {case_dir(args.case)}")
    print(f"[ok] {p}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="GIN-VUE-ADMIN / 领奖中心探针")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser, *, need_case: bool = True) -> None:
        sp.add_argument("--base", required=True, help="http(s)://host:port")
        if need_case:
            sp.add_argument("--case", required=True)
        sp.add_argument("--insecure", action="store_true")
        sp.add_argument("--serverid", type=int, default=101)

    sp = sub.add_parser("recon", help="未授权+CORS+JS+HPP")
    add_common(sp)
    sp.add_argument("--username", default="admin")
    sp.add_argument("--origin", default="http://evil.example")
    sp.add_argument("--path", default="/api/user/getUserInfo", help="CORS 探测路径")
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("unauth", help="未授权 API")
    add_common(sp)
    sp.add_argument("--username", default="admin")
    sp.set_defaults(func=cmd_unauth)

    sp = sub.add_parser("cors", help="CORS 反射+credentials")
    add_common(sp)
    sp.add_argument("--origin", default="http://evil.example")
    sp.add_argument("--path", default="/api/user/getUserInfo")
    sp.set_defaults(func=cmd_cors)

    sp = sub.add_parser("hpp", help="HTTP 参数污染")
    add_common(sp)
    sp.add_argument("--path", default="/api/base/getConfigs")
    sp.set_defaults(func=cmd_hpp)

    sp = sub.add_parser("js-mine", help="前端 JS 挖隐藏 API")
    add_common(sp)
    sp.set_defaults(func=cmd_js_mine)

    sp = sub.add_parser("enum", help="getName 用户枚举差分")
    add_common(sp)
    sp.add_argument("--users", default="admin,test,root")
    sp.set_defaults(func=cmd_enum)

    sp = sub.add_parser("field-probe", help="sendCReward 字段名探测")
    add_common(sp)
    sp.add_argument("--account", required=True)
    sp.add_argument("--name", default="probe")
    sp.add_argument("--gid", default="0")
    sp.add_argument("--path", default="/api/base/sendCReward")
    sp.set_defaults(func=cmd_field_probe)

    sp = sub.add_parser("claim-probe", help="领取（需 --confirm）")
    add_common(sp)
    sp.add_argument("--account", required=True)
    sp.add_argument("--name", required=True)
    sp.add_argument("--gid", required=True)
    sp.add_argument("--configids", required=True)
    sp.add_argument("--configname", default="")
    sp.add_argument("--channel", default="2")
    sp.add_argument("--captcha", required=True)
    sp.add_argument("--captcha-id", required=True)
    sp.add_argument("--path", default="/api/base/sendCReward")
    sp.add_argument("--confirm", action="store_true")
    sp.set_defaults(func=cmd_claim_probe)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
