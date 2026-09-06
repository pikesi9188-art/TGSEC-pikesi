#!/usr/bin/env python3
"""测试/预发布子域枚举 — 博彩站专项。

Cloudflare 只保护主站，测试/预发布子域往往直接暴露真实 IP、无 WAF。
常见模式：test.xxx.com / staging.xxx.com / uat.xxx.com / dev.xxx.com

示例:
  python3 炼蛊房/test_subdomain_enum.py scan \
    --domain target.com --case <案卷>
  python3 炼蛊房/test_subdomain_enum.py check \
    --url https://test.target.com --case <案卷>
"""
from __future__ import annotations
import argparse
import json
import re
import socket
import sys
import concurrent.futures
from datetime import datetime, UTC
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ENGINE = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope  # noqa: E402

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "subdomains"
    d.mkdir(parents=True, exist_ok=True)
    return d

# 测试/预发布子域前缀字典
TEST_PREFIXES = [
    # 测试环境
    "test", "test1", "test2", "testing", "tst",
    "dev", "dev1", "dev2", "develop", "development",
    "staging", "stage", "stg",
    "uat", "qa", "qat",
    "beta", "beta1", "preview",
    "sandbox", "demo", "trial",
    # 中文音译
    "ceshi", "kaifa",
    # 预发布
    "pre", "preprod", "pre-prod", "pre-release",
    "release", "rc", "hotfix",
    # 版本
    "v2", "v3", "new", "next", "old", "legacy",
    # 服务类
    "api-test", "api-dev", "api-staging", "api-uat",
    "admin-test", "admin-dev", "admin-staging",
    "m-test", "h5-test", "wap-test",
    "app-test", "app-dev",
    # 博彩站常见
    "test-api", "dev-api", "stage-api",
    "test-admin", "dev-admin",
    "back-test", "back-dev",
    "management-test", "op-test",
]

# Cloudflare IP 段（用于判断是否直连）
CF_RANGES = [
    "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "172.67.", "172.68.", "172.69.",
    "162.159.", "198.41.", "188.114.",
]

def is_cloudflare_ip(ip: str) -> bool:
    return any(ip.startswith(r) for r in CF_RANGES)

def resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def check_subdomain(subdomain: str, base_domain: str, timeout: float = 8.0) -> dict | None:
    fqdn = f"{subdomain}.{base_domain}"
    ip = resolve_ip(fqdn)
    if not ip:
        return None
    is_cf = is_cloudflare_ip(ip)
    result = {
        "subdomain": fqdn,
        "ip": ip,
        "cloudflare": is_cf,
        "direct_ip": not is_cf,
        "status": None,
        "title": "",
        "server": "",
        "tech": [],
    }
    if HAS_REQUESTS:
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{fqdn}", timeout=timeout,
                                 verify=False, allow_redirects=True)
                result["status"] = r.status_code
                result["server"] = r.headers.get("Server", "")
                result["title"] = _extract_title(r.text)
                result["tech"] = _detect_tech(r.text, r.headers)
                break
            except Exception:
                continue
    return result

def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]{1,100})</title>", html, re.I)
    return m.group(1).strip() if m else ""

def _detect_tech(html: str, headers: dict) -> list:
    tech = []
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()
    html_l = html[:3000].lower()
    if "php" in server or "php" in powered: tech.append("PHP")
    if "nginx" in server: tech.append("Nginx")
    if "apache" in server: tech.append("Apache")
    if "cloudflare" in server: tech.append("Cloudflare")
    if "__vue__" in html_l or 'id="app"' in html_l: tech.append("Vue")
    if "__react" in html_l or 'id="root"' in html_l: tech.append("React")
    if "laravel" in html_l: tech.append("Laravel")
    if "thinkphp" in html_l or "think\\app" in html_l: tech.append("ThinkPHP")
    return tech

def cmd_scan(args: argparse.Namespace) -> int:
    domain = host_of(args.domain)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    print(f"[*] scanning {len(TEST_PREFIXES)} test subdomains for {domain} …", flush=True)

    results = []
    direct_hits = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(check_subdomain, pfx, domain, args.timeout): pfx
                for pfx in TEST_PREFIXES}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            if r:
                results.append(r)
                cf_mark = "[CF]" if r["cloudflare"] else "★直连"
                print(f"  [{r['status'] or '?'}] {cf_mark} {r['subdomain']} → {r['ip']}"
                      f"  {r['title'][:40]!r}  {r['tech']}")
                if r["direct_ip"] and r["status"] in (200, 302, 301, 403):
                    direct_hits.append(r)

    out = case_dir(args.case)
    report = {
        "ts": _now(), "domain": domain,
        "total_checked": len(TEST_PREFIXES),
        "found": len(results),
        "direct_hits": len(direct_hits),
        "subdomains": results,
    }
    out_json = out / "test_subdomains.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"\n[result] {len(results)} 子域存在, {len(direct_hits)} 个直连（非CF）")
    if direct_hits:
        print("\n★★★ 直连子域（无 Cloudflare 保护）:")
        for h in direct_hits:
            print(f"  {h['subdomain']} → {h['ip']}  [{h['status']}]  {h['tech']}")
        print("\n[next] 对直连子域:")
        print("  1. 用 origin_recon 确认是否是主站 PHP 同 IP")
        print("  2. 直接打后台弱口令（gambling_admin_passwords.txt）")
        print("  3. 备份文件扫描（gambling_backup_paths.txt）")
    print(f"\n[+] → {out_json}")
    return 0 if direct_hits else 1

def cmd_check(args: argparse.Namespace) -> int:
    """单独检测一个子域是否直连。"""
    domain = host_of(args.url)
    ip = resolve_ip(domain)
    print(f"IP: {ip}")
    if ip:
        print(f"Cloudflare: {is_cloudflare_ip(ip)}")
        print(f"Direct: {not is_cloudflare_ip(ip)}")
    return 0

def main() -> int:
    p = argparse.ArgumentParser(description="测试/预发布子域枚举")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan")
    sc.add_argument("--domain", required=True)
    sc.add_argument("--case", required=True)
    sc.add_argument("--concurrency", type=int, default=30)
    sc.add_argument("--timeout", type=float, default=8.0)
    sc.set_defaults(func=cmd_scan)

    ck = sub.add_parser("check")
    ck.add_argument("--url", required=True)
    ck.add_argument("--case", default="")
    ck.set_defaults(func=cmd_check)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
