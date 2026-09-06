#!/usr/bin/env python3
"""大爱仙尊技能别名 → 专卡。对外入口：se_skill_alias.py。

  python3 炼蛊房/se_skill_alias.py --name tiandun-reversing
  python3 炼蛊房/se_skill_alias.py --signal 天盾卡密
  python3 炼蛊房/se_skill_alias.py --list
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# 别名 → 本库 skill
MAP: dict[str, str] = {
    "full-pentest": "pentest-methodology",
    "full-crack": "net-license-crack",
    "full-reverse": "reverse-engineering",
    "exploit-attack": "rce-encyclopedia",
    "vuln-scanner": "strike-probe",
    "vulnerability-research": "deepaudit-code-audit",
    "webapp-security-audit": "web-vuln-router",
    "posture-assessment": "case-triage",
    "web-pentest": "web-vuln-router",
    "web-cms-pentest": "wordpress-attack-router",
    "thinkphp-modern-pentest": "strike-probe",
    "php-security-audit": "deepaudit-code-audit",
    "php-webapp-security-audit": "deepaudit-code-audit",
    "web-ssrf": "ssrf-testing",
    "web-ssti": "ssti-exploit",
    "web-xxe": "xxe-injection-testing",
    "web-deserialization": "deserialization-testing",
    "web-graphql": "graphql-pentest",
    "jwt-attacks": "jwt-bypass-pentest",
    "oauth-attack": "oauth-oidc-flow",
    "api-security": "api-security-testing",
    "path-traversal-pentest": "lfi-rfi-exploit",
    "frontend-auth-bypass": "frontend-auth-bypass",
    "spa-api-discovery": "spa-protocol-reverse",
    "spa-frontend-recon": "spa-protocol-reverse",
    "spa-saas-api-pentest": "encrypted-api-spa",
    "saas-multitenant-pentest": "saas-signup-multitenant-testing",
    "saas-webapp-pentest": "saas-signup-multitenant-testing",
    "saas-ai-task-api-pentest": "llm-security",
    "web-crawler": "information-gathering",
    "server-getshell-playbook": "rce-encyclopedia",
    "card-shop-pentest": "faka-card-shop-pentest",
    "open-source-faka-pentest": "acg-faka",
    "smm-panel-pentest": "strike-probe",
    "tg-bot-backend-pentest": "tg-bot-webhook-hijack",
    "bot-panel-spacemapping": "fofa-search",
    "space-mapping-engine-recon": "cdn-origin-tracing",
    "gambling-pentest-nocredstuffing": "gambling-family-router",
    "gambling-platform-risk-control": "gambling-platform-odds-audit",
    "white-label-casino-pentest": "gambling-family-router",
    "white-label-pentest": "gambling-family-router",
    "wps-casino-platform-pentest": "gambling-api-crypto-reversal",
    "fintech-platform-pentest": "fund-edge-ops",
    "credential-stuffing": "auth-brute",
    "online-credential-stuffing": "auth-brute",
    "wasm-ws-protocol-crack": "spa-protocol-reverse",
    "ws-global-data-extraction": "websocket-pentest",
    "cloudflare-origin-bypass": "cdn-origin-tracing",
    "cloudflare-origin-discovery": "cdn-origin-tracing",
    "edgeone-origin-bypass": "cdn-origin-tracing",
    "c2-zero-trust-attack": "c2-zero-trust-console",
    "apk-backend-pentest": "apk-recon",
    "mobile-app-pentest": "apk-recon",
    "crack-keygen": "net-license-crack",
    "windows-binary-cracking": "net-license-crack",
    "windows-binary-reversing": "net-license-crack",
    "windows-exe-crack-methodology": "net-license-crack",
    "windows-exe-cracking": "net-license-crack",
    "tiandun-reversing": "net-license-crack",
    "nuitka-pyinstaller-crack": "net-license-crack",
    "fndata-auth-bypass": "net-license-crack",
    "auth-server-emulation": "net-license-crack",
    "fake-auth-server-redirect": "net-license-crack",
    "card-key": "net-license-crack",
    "vip-bypass": "client-state-skip",
    "dotnet-reverse": "dotnet-reverse",
    "golang-reverse": "go-rust-reverse",
    "python-reverse": "python-pack-reverse",
    "electron-app-source-recon": "thick-client",
    "codex-backend-patch": "cloud-ide-codex-rce",
    "reverse-engineering": "reverse-engineering",
    "reverse-engineering-ghidra": "ghidra-reverse",
    "reverse-engineering-ida": "reverse-engineering",
    "exploit-dev": "binary-pwn",
    "exploit-development-linux": "binary-pwn",
    "exploit-development-win": "binary-pwn",
    "binary-protect-bypass": "binary-protection-bypass",
    "anti-debug": "anti-debugging-techniques",
    "code-obfuscate": "code-obfuscation-deobfuscation",
    "zero-day-research": "autocve-cve-hunt",
    "evasion": "edr-bypass-re",
    "evasion-advanced": "edr-bypass-re",
    "malware-analysis": "digital-forensics",
    "persistence": "windows-persistence",
    "post-exploit": "linux-post-exploit",
    "privilege-escalation": "linux-privilege-escalation",
    "lateral-movement": "ad-windows-router",
    "admin-backdoor-persistence": "jwt-stateless-persist",
    "red-team": "redteam-opsec",
    "c2-development": "host-c2-verify",
    "cobalt-strike": "host-c2-verify",
    "sliver-c2": "host-c2-verify",
    "phishing-kit": "autonomous-social-engagement",
    "social-engineering": "autonomous-social-engagement",
    "exfiltration": "oob-exfil-kit",
    "data-exfil": "oob-exfil-kit",
    "proxy-chaining": "egress-proxy-pool",
    "firewall-evasion": "evasion",
    "cloud-aws": "cloud-metadata-harvesting",
    "cloud-azure": "cloud-metadata-harvesting",
    "cloud-gcp": "cloud-metadata-harvesting",
    "cloud-native-attack": "cloud-k8s",
    "kubernetes-security": "cloud-k8s",
    "docker-security": "linux-post-exploit",
    "supply-chain": "ci-cd-attack-testing",
    "network-pentest": "information-gathering",
    "wireless-attacks": "wifi-wireless",
    "wifi-advanced": "wifi-wireless",
    "wifi-wpa3": "wifi-wireless",
    "rf-hacking": "radio-sdr",
    "nfc-rfid": "hardware-security",
    "hardware-hacking": "hardware-security",
    "firmware-reverse": "firmware-pentest",
    "ics-protocol": "ot-ics",
    "scada-ics": "ot-ics",
    "voip-attacks": "sip-surface",
    "voip-sip-tools": "sip-surface",
    "printer-security": "printer-pjl-surface",
    "steganography": "steganography-techniques",
    "vpn-attacks": "sslvpn-perimeter-fingerprint",
    "password-cracking": "hash-identify",
    "crypto-tools": "wallet-app-pentest",
    "blockchain-audit": "secure-workflow-guide",
    "weak-rng-wallet-cracking": "weak-rng-wallet",
    "prng-secret-recovery": "weak-rng-wallet",
    "forensics": "digital-forensics",
    "osint": "information-gathering",
    "aiml-attacks": "llm-security",
    "android-root": "apk-reverse",
    "ios-reverse": "ios-pentest",
    "apk-reverse": "apk-reverse",
    "game-cheat": "client-crack-cheat",
    "cloud-audit-bypass": "evasion",
    "rei-fallback": "keyword-router",
    "ransomware-builder": "authorized-ransom-lab",
    "botnet-dev": "authorized-botnet-lab",
    "bootkit-rootkit": "authorized-bootkit-audit",
    "ddos-toolkit": "authorized-ddos-surface",
    "malware-dev": "digital-forensics",
    "security-skill-library": "engine-distill",
    "auto-skill-installer": "engine-distill",
    "active-directory": "ad-windows-router",
    "rce-encyclopedia": "rce-encyclopedia",
}

ALIASES = {
    "天盾": "tiandun-reversing",
    "fndata": "fndata-auth-bypass",
    "nuitka": "nuitka-pyinstaller-crack",
    "pyinstaller": "nuitka-pyinstaller-crack",
    "卡密验证": "crack-keygen",
    "假认证": "auth-server-emulation",
    "回退": "rei-fallback",
    "勒索": "ransomware-builder",
    "僵尸网": "botnet-dev",
    "bootkit": "bootkit-rootkit",
    "ddos": "ddos-toolkit",
    "技能库": "security-skill-library",
    "抢rce": "rce-encyclopedia",
    "getshell": "server-getshell-playbook",
    "edgeone": "edgeone-origin-bypass",
    "altcha": "frontend-auth-bypass",
    "弱随机": "weak-rng-wallet-cracking",
    "lcg": "weak-rng-wallet-cracking",
    "pjl": "printer-security",
    "外挂": "game-cheat",
}


def _alias_hit(alias: str, blob: str) -> bool:
    if not alias or not blob:
        return False
    if alias.isascii() and alias.isalnum() and len(alias) <= 8:
        return re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", blob) is not None
    return alias in blob


def _naming_pair() -> tuple[dict[str, str], dict[str, str]]:
    try:
        from scope_lib import repo_root

        p = repo_root(Path(__file__)) / "NAMING.json"
        if not p.is_file():
            return {}, {}
        data = json.loads(p.read_text(encoding="utf-8"))
        s2g = {str(k): str(v) for k, v in (data.get("skills") or {}).items() if k and v}
        return s2g, {v: k for k, v in s2g.items()}
    except Exception:
        return {}, {}


def _gu_name(skill: str) -> str:
    if not skill:
        return ""
    s2g, _g2s = _naming_pair()
    return s2g.get(skill) or skill


def _note(found: bool) -> str:
    if not found:
        return "未收录：走 keyword-router / css_query"
    try:
        from scope_lib import is_oss_layout

        return "大爱仙尊专卡" if is_oss_layout() else "测绘引擎专卡"
    except Exception:
        return "测绘引擎专卡"


def resolve(name: str) -> dict:
    raw = (name or "").strip()
    key = raw.lower().replace("_", "-")
    if key in ALIASES:
        key = ALIASES[key]
    if raw in MAP:
        key = raw
    skill = MAP.get(key) or MAP.get(raw)
    if not skill:
        blob = raw.lower()
        for a, dest in sorted(ALIASES.items(), key=lambda x: -len(x[0])):
            if _alias_hit(a, blob) or _alias_hit(a, key):
                skill = MAP.get(dest)
                key = dest
                break
    if not skill:
        s2g, g2s = _naming_pair()
        if raw in s2g or key in s2g:
            skill = raw if raw in s2g else key
        elif raw in g2s:
            skill = g2s[raw]
        elif key in g2s:
            skill = g2s[key]
    oss_skip_inject = False
    if skill == "se-inject":
        try:
            from scope_lib import is_oss_layout
            if is_oss_layout():
                skill = "keyword-router"
                oss_skip_inject = True
        except Exception:
            pass
    rec = {
        "query": raw,
        "alias": key if skill else "",
        "skill": skill or "keyword-router",
        "note": "开源版不带助手注入" if oss_skip_inject else _note(bool(skill)),
        "skip": False,
    }
    gu = _gu_name(rec["skill"])
    if gu and gu != rec["skill"]:
        rec["gu"] = gu
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊技能别名")
    ap.add_argument("--name", default="")
    ap.add_argument("--signal", default="")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for k, v in sorted(MAP.items()):
            print(f"{k:36} → {v}")
        return 0
    q = args.name or args.signal
    if not q:
        print("[!] --name 或 --signal", file=sys.stderr)
        return 2
    rec = resolve(q)
    if rec.get("gu"):
        rec = {**rec, "machine": rec["skill"], "skill": rec["gu"]}
    print(json.dumps(rec, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
