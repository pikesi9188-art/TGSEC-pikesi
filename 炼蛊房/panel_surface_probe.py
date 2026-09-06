#!/usr/bin/env python3
"""宝塔 / phpMyAdmin / Adminer 探针（授权范围内）。默认指纹 + PMA/Adminer 短字典弱口。不改密、不拖库。"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402


def _get(sess: requests.Session, url: str) -> requests.Response | None:
    try:
        return sess.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception:
        return None


PATHS = [
    ("bt", "/login", r"宝塔|aaPanel|BT-Panel|btpanel"),
    ("pma", "/phpmyadmin/", r"phpMyAdmin|pmahomme"),
    ("pma", "/pma/", r"phpMyAdmin"),
    ("pma", "/mysql/", r"phpMyAdmin"),
    ("adminer", "/adminer.php", r"Adminer"),
    ("adminer", "/adminer/", r"Adminer"),
]

SHORT_CREDS = (
    ("root", ""),
    ("root", "root"),
    ("root", "123456"),
    ("admin", "admin"),
    ("admin", "123456"),
)


def _try_pma(sess: requests.Session, url: str, user: str, pwd: str) -> bool:
    try:
        r = sess.post(
            url, timeout=10, verify=False, allow_redirects=True,
            data={"pma_username": user, "pma_password": pwd, "server": "1"},
        )
    except Exception:
        return False
    text = (r.text or "").lower()
    if "access denied" in text or "cannot log in" in text or "login without a password is forbidden" in text:
        return False
    if "pma_username" in text and ("log in" in text or "用户名" in r.text):
        return False
    sc = r.headers.get("Set-Cookie", "")
    if "pmaUser" in sc or "phpMyAdmin" in sc:
        if "pma_username" not in text:
            return True
    if any(x in text for x in ("server_databases", "navigation.php", "sql.php", "server_status")):
        return True
    return False


def _try_adminer(sess: requests.Session, url: str, user: str, pwd: str) -> bool:
    try:
        r = sess.post(
            url, timeout=10, verify=False, allow_redirects=True,
            data={
                "auth[driver]": "server",
                "auth[server]": "127.0.0.1",
                "auth[username]": user,
                "auth[password]": pwd,
                "auth[db]": "",
            },
        )
    except Exception:
        return False
    text = (r.text or "").lower()
    if "access denied" in text or "login" in text and "auth[username]" in text:
        return False
    if "logout" in text or "sql command" in text:
        return True
    return False


def run(base_url: str, case: str, out: Path | None, weak: bool = True) -> dict[str, Any]:
    host = urlparse(base_url).hostname or ""
    if host:
        require_in_scope(host)
    base = base_url.rstrip("/") + "/"
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; 大爱仙尊-Panel/1.0)"
    findings: list[dict[str, Any]] = []
    for kind, p, pat in PATHS:
        r = _get(sess, urljoin(base, p))
        if not r or r.status_code >= 500:
            continue
        if re.search(pat, r.text, re.I) or re.search(pat, r.headers.get("Set-Cookie", ""), re.I):
            findings.append({
                "kind": kind,
                "level": "L1",
                "path": p,
                "status": r.status_code,
                "final_url": str(r.url)[:200],
            })
            if weak and kind == "pma":
                for user, pwd in SHORT_CREDS:
                    if _try_pma(sess, str(r.url), user, pwd):
                        findings.append({
                            "kind": "pma",
                            "level": "L2",
                            "path": p,
                            "signal": "weak-login",
                            "user": user,
                            "password": "(empty)" if pwd == "" else "(set)",
                            "next": "进 PMA 后读库名即可；mysqldump / 改密不要默认做",
                        })
                        break
            if weak and kind == "adminer":
                for user, pwd in SHORT_CREDS:
                    if _try_adminer(sess, str(r.url), user, pwd):
                        findings.append({
                            "kind": "adminer",
                            "level": "L2",
                            "path": p,
                            "signal": "weak-login",
                            "user": user,
                            "password": "(empty)" if pwd == "" else "(set)",
                        })
                        break
    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "findings": findings,
        "playbook": "传承/宝塔台.md",
        "note": "PMA/Adminer 默认短字典弱口；宝塔登录加密，弱口需安全入口。不拖库。",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    written: list[Path] = []
    if case:
        d = ROOT / "案卷" / case / "测绘" / "panel"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "surface.json"
        p.write_text(text, encoding="utf-8")
        written.append(p)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        written.append(out)
    if not written:
        p = Path("panel_surface.json")
        p.write_text(text, encoding="utf-8")
        written.append(p)
    out_path = written[-1] if out else written[0]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="宝塔/PMA 面板指纹")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--no-weak", action="store_true", help="只做登录页指纹，不试短字典")
    args = ap.parse_args()
    run(args.url, args.case, args.out, weak=not args.no_weak)


if __name__ == "__main__":
    main()
