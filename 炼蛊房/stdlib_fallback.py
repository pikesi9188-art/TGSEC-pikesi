#!/usr/bin/env python3
"""受限环境：有本库探针先打印本库命令，否则跑 tools/stdlib-kit 标准库脚本。"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf:
            try:
                reconf(encoding="utf-8")
            except Exception:
                pass

_utf8_stdio()

OPS = Path(__file__).resolve().parent
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
KIT = ROOT / "tools" / "stdlib-kit"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402

# 脚本名 → 优先本库命令（{url} 可替换）
PREFER: dict[str, str] = {
    "ssrf_probe": "python3 炼蛊房/ssrf_probe.py scan --base {url} --case <案卷>",
    "waf_detect": "python3 炼蛊房/waf_detect.py detect --url {url} --case <案卷>",
    "jwt_attack": "python3 炼蛊房/jwt_gql_probe.py --url {url} --case <案卷>",
    "dir_brute": "python3 炼蛊房/dirbrute_probe.py -u {url} --case <案卷>",
    "js_endpoints": "python3 炼蛊房/js_secret_hunter.py hunt -u {url} --case <案卷>",
    "port_scanner": "python3 炼蛊房/port_admin_scan.py scan --ip <IP> --case <案卷>",
    "subdomain_enum": "python3 炼蛊房/origin_recon.py --domain <域> --case <案卷>",
    "xss_detector": "python3 炼蛊房/stored_xss_probe.py scan --base {url} --case <案卷>",
    "password_spray": "python3 炼蛊房/auth_brute_probe.py -u {url} --case <案卷>",
    "sqli_detector": "python3 炼蛊房/sqlmap_kit.py cmdline --url {url} --case <案卷>",
    "linpeas_light": "python3 炼蛊房/linux_lpe_checker.py",
    "ctf_decode": "python3 炼蛊房/crypto_decode.py",
    "s3_bucket_enum": "python3 炼蛊房/bucket_probe.py scan -d <域>",
    "cache_poison_detector": "python3 炼蛊房/cache_poison_probe.py --url {url} --case <案卷>",
    "crt_find": "python3 炼蛊房/origin_recon.py --domain <域> --case <案卷>",
    "whois_lookup": "python3 炼蛊房/origin_recon.py --domain <域> --case <案卷>",
    "chain_scan": "python3 炼蛊房/usdt_attr_hijack.py chain-scan --case <案卷>",
    "chain_verify": "python3 炼蛊房/usdt_attr_hijack.py chain-verify --case <案卷> --address <T...>",
    "client_crack_cheat": "python3 炼蛊房/client_crack_cheat_probe.py replay --base {url} --case <案卷>",
}

# 本库没有对等探针，直接跑标准库副本
NATIVE = {
    "cms_fingerprint",
    "email_hunter",
    "wordlist_gen",
    "hash_id",
    "kerberoast_prep",
    "binary_scan",
    "url_phish_check",
    "idor_scanner",
    "cache_poison_detector",
    "crt_find",
    "whois_lookup",
    "chain_scan",
    "chain_verify",
}


def _url_from(passthrough: list[str]) -> str:
    for i, a in enumerate(passthrough):
        if a in ("-u", "--url", "--base", "-d", "--domain") and i + 1 < len(passthrough):
            return passthrough[i + 1]
        if a.startswith("http://") or a.startswith("https://"):
            return a
    for a in passthrough:
        if a.startswith("-"):
            continue
        if "." in a and " " not in a:
            return a
    return ""


def list_tools() -> None:
    pys = sorted(p.stem for p in KIT.glob("*.py"))
    print("name                 prefer_ops  kit")
    for name in pys:
        flag = "ops" if name in PREFER else ("kit" if name in NATIVE else "kit")
        print(f"{name:20} {flag}")


def run(name: str, passthrough: list[str], force: bool) -> int:
    script = KIT / f"{name}.py"
    if not script.is_file():
        print(f"[err] 无此工具: {name}", file=sys.stderr)
        return 2
    url = _url_from(passthrough)
    if url.startswith("http") or (url and "." in url and "://" not in url):
        require_in_scope(url if "://" in url else f"https://{url}")
    if name in PREFER and not force:
        cmd = PREFER[name].replace("{url}", url or "https://授权站")
        print(f"[prefer] 先走本库：{cmd}")
        print("[prefer] 受限环境要跑标准库副本：同样命令加 --force")
        return 0
    return subprocess.call([sys.executable, str(script), *passthrough])


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊受限环境降级")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("name", nargs="?", help="工具名；可省略 run")
    ap.add_argument("passthrough", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    if args.list or not args.name or args.name == "run":
        if args.name == "run" and args.passthrough:
            name = args.passthrough[0]
            extra = args.passthrough[1:]
            if extra and extra[0] == "--":
                extra = extra[1:]
            return run(name, extra, args.force)
        list_tools()
        return 0
    extra = list(args.passthrough)
    if extra and extra[0] == "--":
        extra = extra[1:]
    return run(args.name, extra, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
