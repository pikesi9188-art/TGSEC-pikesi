#!/usr/bin/env python3
"""实战技能包 → 专卡 / 长文路径。

不覆盖已有打站卡。
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "docs" / "learning" / "shizhan-pack" / "skills"
OURS = ROOT / "杀招"

# 目录名（leaf）→ 已有专卡。
TO_OURS: dict[str, str] = {
    "cdn-origin-tracing": "cdn-origin-tracing",
    "crlf-injection": "crlf-injection",
    "database-security": "database-security",
    "nosql-injection": "nosql-injection",
    "prototype-pollution": "prototype-pollution",
    "race-condition": "race-condition",
    "reverse-engineering": "reverse-engineering",
    "waf-detector": "waf-detector",
    "tg-cloud-control-pentest": "tg-cloud-control-pentest",
    "telegram-cloud-control-pentest": "tg-cloud-control-pentest",
    "xss-cross-site-scripting": "xss-exploit",
    "xss-testing": "xss-exploit",
    "ssrf-server-side-request-forgery": "ssrf-internal-pivoting",
    "ssrf-testing": "ssrf-internal-pivoting",
    "xxe-xml-external-entity": "xxe-exploitation",
    "xxe-testing": "xxe-exploitation",
    "sqli-sql-injection": "sqli-manual",
    "sql-injection-testing": "sqli-manual",
    "ssti-server-side-template-injection": "ssti-exploit",
    "cmdi-command-injection": "command-injection",
    "command-injection-testing": "command-injection",
    "path-traversal-lfi": "lfi-rfi-exploit",
    "file-upload-testing": "file-upload-webshell",
    "upload-insecure-files": "file-upload-webshell",
    "cors-cross-origin-misconfiguration": "cors-exploitation",
    "csrf-cross-site-request-forgery": "csrf-exploitation",
    "csrf-testing": "csrf-exploitation",
    "open-redirect": "open-redirect-chain",
    "idor-broken-object-authorization": "idor-bola-chain",
    "idor-testing": "idor-bola-chain",
    "jwt-oauth-token-attacks": "jwt-bypass-pentest",
    "api-auth-and-jwt-abuse": "jwt-bypass-pentest",
    "graphql-and-hidden-parameters": "graphql-pentest",
    "request-smuggling": "http-request-smuggling",
    "websocket-security": "websocket-pentest",
    "payment-gateway-callback": "payment-callback-forgery",
    "business-logic-vulnerabilities": "business-logic-payment",
    "business-logic-testing": "business-logic-payment",
    "business-logic-vuln": "business-logic-payment",
    "waf-bypass-techniques": "evasion",
    "linux-privilege-escalation": "linux-post-exploit",
    "windows-privilege-escalation": "windows-lpe",
    "windows-lateral-movement": "smb-lateral-movement",
    "active-directory-kerberos-attacks": "kerberos-attack",
    "active-directory-certificate-services": "adcs-pentest",
    "active-directory-lateral-movement": "ad-windows-router",
    "active-directory-acl-abuse": "ad-windows-router",
    "kubernetes-pentesting": "cloud-k8s",
    "llm-prompt-injection": "llm-security",
    "ai-llm-attack-surface": "llm-security",
    "supply-chain-attacks": "supply-chain-security",
    "deserialization-insecure": "java-deserialization",
    "deserialization-testing": "java-deserialization",
    "vite-dev-server-exploit": "vite-fs-read",
    "php-zend-heap-ctf": "binary-pwn",
    "wp-cms-known-cves": "wordpress-attack-router",
    "wp2shell-exploit": "wordpress-xmlrpc-surface",
    "507mx-fastadmin-bola": "fastadmin-shop-tenant-bola",
    "fastadmin-oss-multitenant": "fastadmin-shop-tenant-bola",
    "dujiaoka-pay-forgery": "faka-card-shop-pentest",
    "dujiao-next-pentest": "dujiao-next-1yuan-pay",
    "dujiao-next-1yuan-pay": "dujiao-next-1yuan-pay",
    "faka-family-pay-bypass": "faka-card-shop-pentest",
    "faka-lab-playbook": "faka-card-shop-pentest",
    "rainbow-pay-submit-replay": "epay-admin-pentest",
    "yudao-oauth2-cos-takeover": "yudao-daifu-mock-file-rce",
    "nextjs-sandbox-nextauth-forge": "tg-bot-nextauth-takeover",
    "hunt-nextjs": "nextjs-ssr-hunt",
    "hunt-nextjs-ssr": "nextjs-ssr-hunt",
    "nextjs-ssr-hunt": "nextjs-ssr-hunt",
    "hunt-aspnet": "aspnet-viewstate-hunt",
    "hunt-viewstate": "aspnet-viewstate-hunt",
    "aspnet-viewstate-hunt": "aspnet-viewstate-hunt",
    "hunt-grpc": "grpc-reflection-hunt",
    "grpc-reflection-hunt": "grpc-reflection-hunt",
    "hunt-ssl-vpn": "sslvpn-perimeter-fingerprint",
    "enterprise-vpn-attack": "sslvpn-perimeter-fingerprint",
    "sslvpn-perimeter-fingerprint": "sslvpn-perimeter-fingerprint",
    "encrypted-api-gateway-reversing": "encrypted-api-spa",
    "encrypted-api-gateway-reversal": "encrypted-api-spa",
    "signed-encrypted-api-reversing": "encrypted-api-spa",
    "encrypted-api-debugging": "encrypted-api-spa",
    "api-signature-bypass": "encrypted-api-spa",
    "pentest-redteam": "hypothesis-ledger",
    "skill-routing": "keyword-router",
    "api-sec": "idor-bola-chain",
    "api-security": "idor-bola-chain",
    "api-security-testing": "idor-bola-chain",
    "api-authorization-and-bola": "idor-bola-chain",
    "api-authorization-bypass": "rbac-bypass-authz",
    "api-recon-and-docs": "api-param-name-discovery",
    "auth-sec": "auth-brute",
    "auth-agent": "auth-brute",
    "password-attacks-credential-access": "auth-brute",
    "rsa-attack-techniques": "crypto-toolkit",
    "lattice-crypto-attacks": "crypto-toolkit",
    "symmetric-cipher-attacks": "crypto-toolkit",
    "hash-attack-techniques": "crypto-toolkit",
    "classical-cipher-analysis": "crypto-toolkit",
    "container-escape-techniques": "linux-post-exploit",
    "container-security-testing": "linux-post-exploit",
    "linux-security-bypass": "linux-post-exploit",
    "linux-lateral-movement": "linux-post-exploit",
    "heap-exploitation": "binary-pwn",
    "echoes-of-heap-exploit": "binary-pwn",
    "yudao-web-appapi-pentest": "yudao-appapi-pentest",
    "yudao-tma-pentest": "yudao-appapi-pentest",
    "tma-encrypted-api-reversal": "yudao-appapi-pentest",
    "injection-checking": "web-vuln-router",
    "file-access-vuln": "web-vuln-router",
    "unauthorized-access-common-services": "middleware-unauth",
    "telegram-mini-app-bot-security": "telegram-tma-gambling",
    "ios-pentesting-tricks": "mobile-reverse",
    "android-pentesting-tricks": "apk-reverse",
    "mobile-app-security-testing": "mobile-reverse",
    "mobile-ssl-pinning-bypass": "apk-reverse",
    "oauth-oidc-misconfiguration": "oauth2-password-grant-login-testing",
    "saml-sso-assertion-attacks": "identity-federation",
    "cloud-security-pentesting": "cloud-metadata-harvesting",
    "cloud-credential-leak-exploitation": "credential-harvest",
    "aws-credential-leak-exploitation": "credential-harvest",
    "insecure-source-code-management": "sensitive-dir-dump",
    "prototype-pollution-advanced": "prototype-pollution",
    "web-cache-deception": "web-cache-poisoning",
    "tunneling-and-pivoting": "internal-tunnel",
    "memory-forensics-volatility": "digital-forensics",
    "incident-response": "host-ir-check",
    "malware-sample-analysis": "malware-analysis",
    "malware-static-analysis": "malware-analysis",
    "nine-stage-fusion": "nine-stage-router",
    "recon-for-sec": "src-hunter",
    "recon-and-methodology": "attack-router",
    "fofa-proxy-search": "fofa-search",
    "proxy-pool-deployment": "egress-proxy-pool",
    "windows-av-evasion": "edr-bypass-re",
    "webshell-evasion": "file-upload-webshell",
    "reverse-shell-techniques": "host-c2-verify",
    "anti-forensics": "digital-forensics",
    "post-exploitation-framework": "linux-post-exploit",
    "cdn-origin-bypass": "cdn-origin-tracing",
    "spa-frontend-api-recon": "spa-protocol-reverse",
    "spa-frontend-reversing": "spa-protocol-reverse",
    "pentest-workflow": "attack-router",
    "target-triage": "case-triage",
}

# 本库没有同名专卡、值得落 Cursor 作业卡的缺口
PROMOTE: dict[str, tuple[str, str]] = {
    "401-403-bypass-techniques": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "clickjacking": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "http-host-header-attacks": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "jndi-injection": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/java_web_surface_probe.py",
    ),
    "type-juggling": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "ghost-bits-cast-attack": (
        "传承/隐鳞·手册.md",
        "炼蛊房/java_web_surface_probe.py",
    ),
    "ldap-injection-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "xpath-injection-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "http-parameter-pollution": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "csv-formula-injection": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "email-header-injection": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "expression-language-injection": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "subdomain-takeover": (
        "传承/空间眼.md",
        "炼蛊房/origin_recon.py",
    ),
}

SKIP_PROMOTE = {
    "windows-av-evasion",
    "webshell-evasion",
    "reverse-shell-techniques",
    "anti-forensics",
    "data-exfiltration",
    "post-exploitation-framework",
    "macos-process-injection",
    "persistence-mechanisms",
    "sandbox-escape-techniques",
    "account-opening-security",
}


def pack_path(name: str) -> Path | None:
    direct = PACK / name / "SKILL.md"
    if direct.is_file():
        return direct
    hits = list(PACK.rglob(f"{name}/SKILL.md"))
    return hits[0] if hits else None


def resolve(name: str) -> dict[str, str]:
    leaf = name.strip().strip("/").split("/")[-1]
    ours = TO_OURS.get(leaf, "")
    if (OURS / leaf).is_dir() and (OURS / leaf / "SKILL.md").is_file():
        ours = ours or leaf
    pp = pack_path(leaf)
    return {
        "name": leaf,
        "ours": ours,
        "pack": str(pp.relative_to(ROOT)) if pp else "",
        "promote": leaf in PROMOTE,
        "skip": leaf in SKIP_PROMOTE,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Route 实战技能包 names")
    ap.add_argument("--name", default="", help="skill 目录名")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        print(f"mapped={len(TO_OURS)} promote={len(PROMOTE)}")
        for k, v in sorted(TO_OURS.items()):
            print(f"  {k:42} -> {v}")
        return 0
    if not args.name:
        ap.print_help()
        return 2
    r = resolve(args.name)
    print(f"name={r['name']}")
    print(f"ours={r['ours'] or '-'}")
    print(f"pack={r['pack'] or '-'}")
    if r["skip"]:
        print("note=知识仓只读")
    elif r["promote"] and not r["ours"]:
        print("note=本库作业卡")
    elif r["ours"]:
        print("note=走本库专卡")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
