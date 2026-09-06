#!/usr/bin/env python3
"""CVE-2024-4577 表面：Windows + PHP CGI（授权范围内，只 GET）。

不发送软连字符、allow_url_include、php://input。
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
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-php-cgi-4577"
PHP_PATHS = (
    "/",
    "/index.php",
    "/info.php",
    "/phpinfo.php",
    "/test.php",
    "/default.php",
)
WIN_NEEDLES = ("microsoft-iis", "asp.net", "win64", "win32", "(win64)", "windows")
PHP_NEEDLES = ("x-powered-by: php", "php/", "php-cgi")


def _headers_blob(r: requests.Response) -> str:
    parts = [f"{k}: {v}" for k, v in r.headers.items()]
    return "\n".join(parts).lower()


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    blob = _headers_blob(r)
    php_ver = ""
    m = re.search(r"x-powered-by:\s*php/?([0-9.]+)?", blob)
    if m:
        php_ver = (m.group(1) or "").strip()
    win = any(n in blob for n in WIN_NEEDLES)
    php = any(n in blob for n in PHP_NEEDLES) or bool(php_ver)
    return {
        "url": url,
        "status": r.status_code,
        "server": r.headers.get("Server", "")[:80],
        "x_powered_by": r.headers.get("X-Powered-By", "")[:80],
        "php_ver": php_ver,
        "win": win,
        "php": bool(php or php_ver or "php" in (r.headers.get("X-Powered-By") or "").lower()),
        "snip": re.sub(r"\s+", " ", r.text or "")[:120],
    }


def _cgi_diff(sess: requests.Session, url: str) -> dict[str, Any]:
    """`.php` 上比较基线 / 无关参数 / `%ADd+-n`。WAF 对两种怪查询都改体则不算。"""
    if ".php" not in url.lower():
        return {"url": url, "changed": False, "skip": "not-php-path"}
    try:
        a = sess.get(url, timeout=12, verify=False, allow_redirects=True)
        c = sess.get(url + "?se_probe=1", timeout=12, verify=False, allow_redirects=True)
        b = sess.get(url + "?%ADd+-n", timeout=12, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120], "changed": False}
    asz, csz, bsz = len(a.text or ""), len(c.text or ""), len(b.text or "")
    ad_diff = (a.status_code != b.status_code) or abs(asz - bsz) >= 80
    ctrl_diff = (a.status_code != c.status_code) or abs(asz - csz) >= 80
    changed = bool(ad_diff and not ctrl_diff)
    return {
        "url": url,
        "base_status": a.status_code,
        "ad_status": b.status_code,
        "ctrl_status": c.status_code,
        "base_size": asz,
        "ad_size": bsz,
        "changed": changed,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    win = False
    php = False
    php_ver = ""
    for p in PHP_PATHS:
        row = _get(sess, urljoin(base + "/", p.lstrip("/")))
        if row.get("error"):
            continue
        if row.get("win"):
            win = True
        if row.get("php"):
            php = True
            php_ver = php_ver or str(row.get("php_ver") or "")
        if row.get("win") and row.get("php") and row.get("status") in {200, 301, 302, 403, 500}:
            if not any(f.get("signal") == "win-php" for f in findings):
                row.update({"level": "L1", "signal": "win-php", "path": p})
                findings.append(row)
                print(f"  L1 win+php {p} server={row.get('server')}")
            if ".php" not in p:
                continue
            diff = _cgi_diff(sess, urljoin(base + "/", p.lstrip("/")))
            if diff.get("changed"):
                diff.update({"level": "L2", "signal": "cgi-soft-hyphen", "path": p})
                findings.append(diff)
                print(f"  L2 cgi-diff {p} base={diff.get('base_status')} ad={diff.get('ad_status')}")
            break
        if row.get("php") and row.get("status") in {200, 403, 500} and not any(f.get("signal") == "php-only" for f in findings):
            row.update({"level": "note", "signal": "php-only", "path": p})
            findings.append(row)
    level = "L2" if any(f.get("level") == "L2" for f in findings) else (
        "L1" if any(f.get("level") == "L1" for f in findings) else ("note" if findings else "none")
    )
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "windows": win,
        "php": php,
        "php_ver": php_ver,
        "findings": findings,
        "playbook": "传承/门廊·开天.md",
        "next": "L2=软连字符改变 CGI 行为。禁止 allow_url_include / php://input / 写马。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="php_cgi", filename="surface.json",
    )
    print(json.dumps({"level": level, "windows": win, "php": php, "php_ver": php_ver, "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="PHP-CGI CVE-2024-4577 表面（只 GET 指纹）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
