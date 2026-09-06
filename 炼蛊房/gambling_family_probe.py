#!/usr/bin/env python3
"""盘口家族专用表面（授权目标）。每族自己的路径/头/签名面，不靠 auto_campaign 结案。

用法:
  python3 炼蛊房/gambling_family_probe.py --family 1z --base https://授权站 --case <案>
  python3 炼蛊房/gambling_family_probe.py --list
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import UTC, datetime
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

UA = "Mozilla/5.0 大爱仙尊-gambling-family"


def _get(
    sess: requests.Session,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    try:
        r = sess.get(
            url, timeout=timeout, verify=False, allow_redirects=True, headers=headers or {}
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    data: Any = None
    try:
        data = r.json()
    except Exception:
        data = None
    cookies = ",".join(r.cookies.keys())
    set_cookie = ",".join(r.headers.get("Set-Cookie", "").split(",")[:3])
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "json": data,
        "text": text[:4000],
        "snip": re.sub(r"\s+", " ", text)[:160],
        "cookies": cookies,
        "set_cookie": set_cookie[:240],
    }


def _post_bare(
    sess: requests.Session,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        r = sess.post(
            url, timeout=10, verify=False, allow_redirects=True, headers=headers or {},
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    data: Any = None
    try:
        data = r.json()
    except Exception:
        data = None
    return {"url": url, "status": r.status_code, "json": data, "text": text[:2000], "snip": re.sub(r"\s+", " ", text)[:160]}


def _post(
    sess: requests.Session,
    url: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        r = sess.post(
            url, json=body or {}, timeout=10, verify=False, allow_redirects=True,
            headers=headers or {},
        )
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    data: Any = None
    try:
        data = r.json()
    except Exception:
        data = None
    return {"url": url, "status": r.status_code, "json": data, "text": text[:2000], "snip": re.sub(r"\s+", " ", text)[:160]}


def _has(row: dict[str, Any], *needles: str) -> bool:
    blob = " ".join(
        [
            row.get("text") or "",
            str(row.get("json") or ""),
            row.get("cookies") or "",
            row.get("set_cookie") or "",
            row.get("snip") or "",
        ]
    ).lower()
    return any(n.lower() in blob for n in needles)


def _json_ok(row: dict[str, Any]) -> bool:
    return row.get("status") == 200 and isinstance(row.get("json"), (dict, list)) and not row.get("error")


def m9_sign(udid: str, ts: str, salt: str = "jgyh,kasd") -> str:
    return hashlib.md5(f"{udid}{salt}{ts}".encode()).hexdigest()


def check_1z(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    games = _get(sess, urljoin(base + "/", "api/game/game_index_v2"))
    if _json_ok(games) or (games.get("status") == 200 and _has(games, "game", "list")):
        rows.append({"level": "L2", "signal": "game-index-unauth", "path": "/api/game/game_index_v2"})
    cap = _post(sess, urljoin(base + "/", "api/captcha/click"), {"scene": "login"})
    if _json_ok(cap) and _has(cap, "token", "sequence", "svg", "image"):
        rows.append({
            "level": "L2", "signal": "click-captcha", "path": "/api/captcha/click",
            "note": "sequence+SVG 可自破；注册要带授权域 Referer",
        })
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "qpuserapi", "click-captcha", "vS("):
        rows.append({"level": "L1", "signal": "1z-html", "path": "/"})
    return rows


def check_dingyi(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in (
        "api/core/system/frontend/support-locale-setting/get",
        "api/core/member/frontend/member-config/get",
        "api/core/server/echo",
    ):
        row = _get(sess, urljoin(base + "/", path))
        if _json_ok(row):
            rows.append({
                "level": "L2", "signal": "frontend-unauth", "path": "/" + path,
                "note": "注册即 token；登录走 verifyKey+XOR",
            })
            break
        if row.get("status") == 200 and _has(row, "siteid", "locale", "echo"):
            rows.append({"level": "L1", "signal": "frontend-surface", "path": "/" + path})
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "websdk.produce", "megagw", "vite_api_base", "dingyi"):
        rows.append({"level": "L1", "signal": "dingyi-html", "path": "/"})
    return rows


def check_gofun(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rank = _get(sess, urljoin(base + "/", "api/v1/web/rank/withdrawal"))
    if _json_ok(rank) or (rank.get("status") == 200 and _has(rank, "rank", "withdrawal")):
        rows.append({"level": "L2", "signal": "rank-leak", "path": "/api/v1/web/rank/withdrawal"})
    take = _post(sess, urljoin(base + "/", "api/v1/user/2fa/take"), {})
    if _json_ok(take) and _has(take, "secret", "google2fa", "otpauth"):
        rows.append({"level": "L2", "signal": "2fa-secret", "path": "/api/v1/user/2fa/take"})
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "aks", "gofun", "n1s168", "vite_http_singkety"):
        rows.append({"level": "L1", "signal": "aks-html", "path": "/"})
    return rows


def check_lsm(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ws = _get(sess, urljoin(base + "/", "api/member/website-settings?sub_domain=probe"))
    if _json_ok(ws) and _has(ws, "merchant", "agent", "sub_domain", "site"):
        rows.append({
            "level": "L2", "signal": "tenant-enum", "path": "/api/member/website-settings",
            "note": "sub_domain 枚举全租户；S3 公开桶走专档",
        })
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "lsmview", "mclsm", "cdnrc", "lsmplay"):
        rows.append({"level": "L1", "signal": "lsm-html", "path": "/"})
    return rows


def check_m9(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    udid = "se-probe-udid"
    ts = str(int(time.time() * 1000))
    headers = {
        "X-UDID": udid,
        "X-Timestamp": ts,
        "X-Sign": m9_sign(udid, ts),
        "X-Language": "zh-CN",
        "tenantSys": "1",
        "domainName": base,
        "os": "1",
        "Authorization": "HSBox",
    }
    guest = _post(
        sess, urljoin(base + "/", "api/user/sys/auth/touristLogin"),
        {"udid": udid}, headers=headers,
    )
    if _json_ok(guest) and _has(guest, "token", "uid"):
        rows.append({
            "level": "L2", "signal": "tourist-login", "path": "/api/user/sys/auth/touristLogin",
            "note": "X-Sign=MD5(UDID+jgyh,kasd+ts)；游客票短，先刷新再打业务",
        })
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "hsbox", "app-shell", "x-sign", "glowale"):
        rows.append({"level": "L1", "signal": "m9-html", "path": "/"})
    return rows


def check_nogle(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, signal, lvl in (
        ("players/lookup?q=admin", "user-oracle", "L2"),
        ("player/showinfo", "captcha-leak", "L2"),
        ("login/setting", "login-setting", "L1"),
        ("mothership/whitelabel/info", "whitelabel-info", "L2"),
        ("games?platform=1", "games", "L1"),
    ):
        row = _get(sess, urljoin(base + "/", path))
        if _json_ok(row) or (row.get("status") == 200 and _has(row, "uuid", "image", "whitelabel", "game")):
            rows.append({"level": lvl, "signal": signal, "path": "/" + path.split("?")[0]})
            if lvl == "L2":
                break
    return rows


def check_origami(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ext = _post(
        sess,
        urljoin(base + "/", "api/accounts/extended?base_url=API&path=https://example.com/se-ssrf"),
        {},
    )
    if ext.get("status") in {200, 400, 415} and not ext.get("error"):
        rows.append({
            "level": "L2" if ext.get("status") == 200 else "L1",
            "signal": "accounts-extended",
            "path": "/api/accounts/extended",
            "status": ext.get("status"),
            "note": "SSRF 入口；先协作域",
        })
    tok = _post(sess, urljoin(base + "/", "api/auth/token"), {})
    if tok.get("status") in {400, 401, 415, 422}:
        rows.append({"level": "L1", "signal": "auth-token", "path": "/api/auth/token"})
    return rows


def check_laravel_tma(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    bare = _get(sess, urljoin(base + "/", "api/config"))
    if _has(bare, "x-device-id", "设备id", "device"):
        rows.append({
            "level": "L1", "signal": "need-device-id", "path": "/api/config",
            "note": "缺 X-Device-Id 的 JSON 就是本族指纹",
        })
    hid = _get(sess, urljoin(base + "/", "api/config"), headers={"X-Device-Id": "00000000-0000-4000-8000-000000000001"})
    if _json_ok(hid):
        rows.append({"level": "L2", "signal": "config-with-device", "path": "/api/config"})
    return rows


def check_quant(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    inv = _get(sess, urljoin(base + "/", "api/register/invite-preview?inviteCode=TEST"))
    if _json_ok(inv) and _has(inv, "inviter", "invite", "valid"):
        rows.append({"level": "L2", "signal": "invite-preview", "path": "/api/register/invite-preview"})
    dash = _get(sess, urljoin(base + "/", "api/v1/quant/masters/1/trade-dashboard?page=1&pageSize=1"))
    if _json_ok(dash):
        rows.append({"level": "L2", "signal": "master-dashboard-unauth", "path": "/api/v1/quant/masters/1/trade-dashboard"})
    return rows


def check_pg_soft(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    idx = _get(sess, urljoin(base + "/", "api/index?keys=00000000-0000-4000-8000-000000000001"))
    if idx.get("status") == 200 and _has(idx, "pg soft", "game-launcher", "operator"):
        rows.append({
            "level": "L2" if _has(idx, "ot=", "ops=") or len(idx.get("text") or "") > 800 else "L1",
            "signal": "pg-launcher", "path": "/api/index",
            "note": "HTML 尾部 blob 解 ci/ot/ops；铸币走上游 verifyOperatorPlayerSession",
        })
    return rows


def check_m8(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "x-ca-token", "mb-device-id", "manba", "m8ty", "pc-api"):
        rows.append({"level": "L1", "signal": "m8-html", "path": "/"})
    for path in ("pc-api/user/info", "pc-api/", "h5-api/"):
        row = _post_bare(sess, urljoin(base + "/", path))
        if row.get("status") in {400, 401, 431} and _has(row, "invalid token", "x-ca", "token"):
            rows.append({
                "level": "L2",
                "signal": "x-ca-gate",
                "path": "/" + path,
                "status": row.get("status"),
                "note": "X-Ca-Token=MD5(base+syb)；空 {} 不要当 body",
            })
            break
        if row.get("status") == 431:
            rows.append({"level": "L2", "signal": "x-ca-431", "path": "/" + path})
            break
    return rows


def check_mm8(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sign = _get(sess, urljoin(base + "/", "users/sign_in"))
    if sign.get("status") == 200 and _has(sign, "user[username]", "user[password]", "ng-app", "devise"):
        rows.append({"level": "L1", "signal": "devise-sign-in", "path": "/users/sign_in"})
    if _has(sign, "_mm8bet_web_session", "mm8bet", "i-newauto"):
        rows.append({
            "level": "L2",
            "signal": "mm8-session-cookie",
            "path": "/users/sign_in",
            "note": "注册无 OTP 可开号；不要对他人号做提现",
        })
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "_mm8bet_web_session", "i-newauto", "ambbet"):
        rows.append({"level": "L1", "signal": "mm8-html", "path": "/"})
    return rows


def check_daanrox(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "__app_config__", "daanrox", "desenvolvido por daanrox", "domaininfo"):
        rows.append({
            "level": "L2" if _has(home, "__app_config__", "domaininfo") else "L1",
            "signal": "app-config",
            "path": "/",
            "note": "domainInfo 反转+b64+unquote；真会话是 Cookie token_user",
        })
    inicio = _get(sess, urljoin(base + "/", "main/inicio"))
    if inicio.get("status") == 200 and _has(inicio, "inicio", "trpc", "app_config"):
        rows.append({"level": "L1", "signal": "inicio", "path": "/main/inicio"})
    tok = _get(sess, urljoin(base + "/", "api/frontend/realtime/token"))
    if tok.get("status") in {200, 401} and (
        _json_ok(tok) or _has(tok, "token", "trpc", "auth")
    ):
        rows.append({
            "level": "L2" if _json_ok(tok) else "L1",
            "signal": "realtime-token",
            "path": "/api/frontend/realtime/token",
        })
    php = _get(sess, urljoin(base + "/", "admin/login"))
    if php.get("status") == 200 and _has(php, "senha", "_csrf", "form-acessar"):
        rows.append({"level": "L1", "signal": "php-admin", "path": "/admin/login"})
    return rows


def check_whitelabel(sess: requests.Session, base: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cfg = _get(sess, urljoin(base + "/", "runtime/app-config.js"))
    if cfg.get("status") == 200 and _has(cfg, "platform_id", "app-api", "sk_encrypt"):
        rows.append({"level": "L1", "signal": "yudao-config", "path": "/runtime/app-config.js", "next": "yudao-appapi-pentest"})
    ebet = _get(sess, urljoin(base + "/", "api/stats"))
    if _json_ok(ebet):
        rows.append({"level": "L2", "signal": "ebet-stats", "path": "/api/stats"})
    home = _get(sess, urljoin(base + "/", ""))
    if _has(home, "lsmview", "mclsm"):
        rows.append({"level": "L1", "signal": "hand-off-lsm", "next": "lsm-mclsm-gambling-pentest"})
    if _has(home, "qpuserapi", "1z"):
        rows.append({"level": "L1", "signal": "hand-off-1z", "next": "1z-gambling-family-pentest"})
    return rows


FAMILIES: dict[str, Any] = {
    "1z": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商心慈·一指",
        "fn": check_1z,
        "next": "L2=游戏目录或点选验证码。签名 SECRET 在前端 vS()；注册带 Referer。",
    },
    "dingyi": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商心慈·鼎艺",
        "fn": check_dingyi,
        "next": "L2=frontend 未授权。注册即 token；登录 verifyKey+XOR。",
    },
    "gofun": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商燕飞·果盘",
        "fn": check_gofun,
        "next": "L2=rank 或 2FA secret。优先打 register_google_verify=false 的租户。",
    },
    "lsm": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商燕飞·盘脉",
        "fn": check_lsm,
        "next": "L2=website-settings 租户枚举。S3 公开桶按专档。",
    },
    "m9": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商燕飞·盒盘",
        "fn": check_m9,
        "next": "L2=touristLogin。X-Sign 与 body 无关；os 必须是数字。",
    },
    "nogle": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商燕飞·诺盘",
        "fn": check_nogle,
        "next": "L2=players/lookup 或 mothership 租户表。",
    },
    "origami": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "墨瑶·折纸",
        "fn": check_origami,
        "next": "L2=accounts/extended SSRF 面。先协作域。",
    },
    "laravel-tma": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "花酒行者·盘口",
        "fn": check_laravel_tma,
        "next": "L1=缺设备 ID 报错；带 X-Device-Id 读 /api/config 才算 L2。",
    },
    "quant": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "马鸿运·影交易",
        "fn": check_quant,
        "next": "L2=invite-preview 或 master dashboard 未授权。",
    },
    "pg-soft": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商燕飞·软盘",
        "fn": check_pg_soft,
        "next": "L2=启动器 HTML/blob。铸币走上游 session，不耗余额。",
    },
    "whitelabel": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商心慈·白标",
        "fn": check_whitelabel,
        "next": "认到 1Z/LSM/芋道立刻交专卡，禁止停在本族。",
    },
    "m8": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商燕飞·曼巴",
        "fn": check_m8,
        "next": "L2=无签 POST 431/Invalid token。X-Ca-Token=MD5(base+syb)；空 {} 不发 body。",
    },
    "mm8": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "商心慈·曼八",
        "fn": check_mm8,
        "next": "L2=_mm8bet_web_session。注册无 OTP；不要对他人号提现。",
    },
    "daanrox": {
        "playbook": "传承/商燕飞·盘口.md",
        "skill": "商燕飞·南盘",
        "fn": check_daanrox,
        "next": "L2=__APP_CONFIG__ 或 realtime/token。真会话是 Cookie token_user。",
    },
    "br-trpc": {
        "playbook": "传承/商燕飞·盘口.md",
        "skill": "商燕飞·南域",
        "fn": check_daanrox,
        "next": "同 daanrox。Bearer 半会话不算打穿。",
    },
    "guoren": {
        "playbook": "传承/商心慈·白标.md",
        "skill": "马鸿运·国人",
        "fn": check_quant,
        "next": "L2=invite-preview 或 master dashboard 未授权。",
    },
}


def run(args: argparse.Namespace) -> dict[str, Any]:
    spec = FAMILIES[args.family]
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings = spec["fn"](sess, base)
    level = "none"
    for want in ("L3", "L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "family": args.family,
        "level": level,
        "findings": findings,
        "playbook": spec["playbook"],
        "skill": spec["skill"],
        "next": spec["next"],
    }
    out = write_probe_json(
        report, case=args.case, out=args.out, case_subdir=f"gamb_{args.family}", filename="surface.json",
    )
    print(json.dumps({"family": args.family, "level": level, "findings": len(findings), "out": str(out)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="盘口家族专用表面（授权内）")
    ap.add_argument("--family", choices=sorted(FAMILIES))
    ap.add_argument("--base", "-u", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list or not args.family:
        for name, spec in FAMILIES.items():
            print(f"{name:12} {spec['skill']}")
        if args.list:
            return
        ap.error("需要 --family")
    if not args.base:
        ap.error("需要 --base")
    run(args)


if __name__ == "__main__":
    main()
