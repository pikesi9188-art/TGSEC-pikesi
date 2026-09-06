#!/usr/bin/env python3
"""大爱仙尊四维侦察：服务器 / 网站 / 域名 /（条件）人员。只做 L1。

人员维默认关。源站/FOFA/JS 密钥必须交接 origin_recon / space_search / js_secret_hunter。
目标必须在 scope。禁止把无关社交域扩权。

  python3 炼蛊房/osint_recon.py --url https://授权站 --case <案卷>
  python3 炼蛊房/osint_recon.py --url https://授权站 --people --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-osint"
LINK_RE = re.compile(r"""href=["'](https?://[^"']+)["']""", re.I)
AUTHOR_RE = re.compile(r"""<meta\s+name=["']author["']\s+content=["']([^"']+)["']""", re.I)
ABOUT_RE = re.compile(r"""href=["']([^"']*(?:about|contact|team)[^"']*)["']""", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _dns(host: str) -> dict[str, Any]:
    out: dict[str, Any] = {"a": []}
    try:
        out["a"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror as e:
        out["error"] = str(e)
    try:
        import subprocess

        r = subprocess.run(["dig", "+short", "MX", host], capture_output=True, text=True, timeout=8)
        if r.returncode == 0 and r.stdout.strip():
            out["mx"] = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()][:8]
        r = subprocess.run(["dig", "+short", "TXT", host], capture_output=True, text=True, timeout=8)
        if r.returncode == 0 and r.stdout.strip():
            out["txt"] = [ln.strip()[:200] for ln in r.stdout.splitlines() if ln.strip()][:8]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def run(url: str, *, people: bool, case: str = "") -> dict[str, Any]:
    host = require_in_scope(url)
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    try:
        r = sess.get(url, timeout=15, verify=False)
    except requests.RequestException as e:
        print(f"[!] 拉取失败: {e}", file=sys.stderr)
        sys.exit(1)
    html = r.text or ""
    headers = {k: v for k, v in r.headers.items()}
    title_m = re.search(r"<title>([^<]+)</title>", html, re.I)
    gen_m = re.search(r"""<meta\s+name=["']generator["']\s+content=["']([^"']+)""", html, re.I)
    cf = "cloudflare" in str(headers.get("Server", "")).lower()
    server = {
        "status": r.status_code,
        "server": headers.get("Server") or headers.get("server"),
        "powered": headers.get("X-Powered-By"),
        "dns": _dns(host),
    }
    site = {
        "title": (title_m.group(1).strip()[:120] if title_m else ""),
        "generator": (gen_m.group(1) if gen_m else ""),
        "waf_hint": [h for h in headers if "cf-" in h.lower() or "waf" in h.lower()] + (["cloudflare"] if cf else []),
        "ext_links": sorted(set(LINK_RE.findall(html)))[:40],
        "emails_on_page": sorted(set(EMAIL_RE.findall(html)))[:15],
    }
    case_s = case or "<案卷>"
    domain = {
        "host": host,
        "scheme": urlparse(url).scheme,
        "next": [
            f"python3 炼蛊房/origin_recon.py --domain {host} --case {case_s}",
            f"python3 tools/space-search/bin/space_search.py search --query 'domain=\"{host}\"' --engines fofa --case {case_s}",
            f"python3 炼蛊房/js_secret_hunter.py hunt -u {url} --case {case_s}",
        ],
    }
    people_blk: dict[str, Any] | None = None
    if people:
        people_blk = {
            "author": AUTHOR_RE.findall(html)[:5],
            "about_links": ABOUT_RE.findall(html)[:10],
            "emails": site["emails_on_page"],
            "note": "只汇总页面已公开信息；禁止扩无关社工目标进 scope",
        }
    dims = {
        "server": bool(server.get("server") or server["dns"].get("a")),
        "website": bool(site["title"] or site["ext_links"]),
        "domain": bool(domain["host"]),
        "people": bool(people_blk),
    }
    return {
        "ts": datetime.now(UTC).isoformat(),
        "url": url,
        "level": "L1",
        "note": "四维首页是 L1；升格必须 origin_recon / FOFA / js_secret / 核心 Web",
        "dims_done": dims,
        "server": server,
        "website": site,
        "domain": domain,
        "people": people_blk,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="OSINT 四维侦察（scope 内）")
    ap.add_argument("--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out")
    ap.add_argument("--people", action="store_true", help="开启人员维（作者/about/邮箱）")
    args = ap.parse_args()
    data = run(args.url, people=args.people, case=args.case)
    print(f"dims {data['dims_done']}  title={data['website'].get('title')}  server={data['server'].get('server')}")
    for ip in (data["server"]["dns"].get("a") or [])[:6]:
        print(f"  A {ip}")
    for cmd in data["domain"]["next"]:
        print(f"  next {cmd}")
    if args.case:
        write_probe_json(data, case=args.case, case_subdir="osint", filename="osint.json")
    if args.out:
        write_probe_json(data, out=Path(args.out))
    if not args.case and not args.out:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
