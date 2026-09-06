#!/usr/bin/env python3
"""批量将 thin 级 skill 升级到 kit/full。

为每个 thin skill 的 SKILL.md 末尾追加 ## 真源 章节，
引用匹配的 传承/ 文件和 炼蛊房/*.py 脚本，
使其满足 skill_catalog.py 的 kit/full 评级条件。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "杀招"

# 映射：skill名 -> (playbook相对路径, tool相对路径)
MAPPING: dict[str, tuple[str, str]] = {
    "1z-gambling-family-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "666bet-tma-pentest": (
        "传承/芋府·微域.md",
        "炼蛊房/yudao_appapi_probe.py",
    ),
    "adcs-pentest": (
        "传承/宗门·认族.md",
        "炼蛊房/ad_surface_check.py",
    ),
    "aks-gofun-gambling-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "api-param-name-discovery": (
        "传承/万我·信门.md",
        "炼蛊房/api_dispatcher_enum.py",
    ),
    "api-security": (
        "传承/万我·信门.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "attack-chain": (
        "传承/巨阳·八十万雄兵.md",
        "炼蛊房/kit_run.py",
    ),
    "binary-diff": (
        "传承/补丁对照.md",
        "炼蛊房/nday_route.py",
    ),
    "bpp-node-exploit-chain": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "br-gambling-trpc-spa-pentest": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "browser-automation": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/cf_session.py",
    ),
    "browser-reverse-mcp": (
        "传承/星念蛊.md",
        "炼蛊房/js_secret_hunter.py",
    ),
    "bt-panel-pentest": (
        "传承/宝塔台.md",
        "炼蛊房/panel_surface_probe.py",
    ),
    "cdn-origin-bypass": (
        "传承/云帷·源溯.md",
        "炼蛊房/origin_recon.py",
    ),
    "cf-rate-limit-evasion-bulk-dump": (
        "传承/隐鳞·手册.md",
        "炼蛊房/cf_backup_bypass.py",
    ),
    "crlf-injection": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "daanrox-br-gambling-pentest": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "diagram-generator": (
        "传承/春秋蝉·分案.md",
        "炼蛊房/case_report.py",
    ),
    "dingyi-whitelabel-gambling-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "docs-generator": (
        "传承/春秋蝉·分案.md",
        "炼蛊房/case_report.py",
    ),
    "dotnet-reverse": (
        "传承/补丁对照.md",
        "炼蛊房/nday_route.py",
    ),
    "dsl-vm-reverse": (
        "传承/补丁对照.md",
        "炼蛊房/nday_route.py",
    ),
    "encrypted-api-gateway-reversal": (
        "传承/星宿·秘语.md",
        "炼蛊房/hall_crypto.py",
    ),
    "epay-admin-pentest": (
        "传承/酒虫·回放.md",
        "炼蛊房/pay_matrix.py",
    ),
    "faka-card-shop-pentest": (
        "传承/秦百胜·拍卖.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "feitou-admin-framework-pentest": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "feitou-ruoyi-admin-pentest": (
        "传承/若依四海杀伤链.md",
        "炼蛊房/java_web_surface_probe.py",
    ),
    "firmware-pentest": (
        "传承/破核·基础.md",
        "炼蛊房/host_ir_check.py",
    ),
    "gambling-api-crypto-reversal": (
        "传承/星宿·秘语.md",
        "炼蛊房/hall_crypto.py",
    ),
    "gambling-deposit-chain-pentest": (
        "传承/秦百胜·假契.md",
        "炼蛊房/pay_matrix.py",
    ),
    "gambling-password-reset-ato": (
        "传承/黑楼兰·硬撼.md",
        "炼蛊房/auth_brute_probe.py",
    ),
    "gambling-platform-odds-audit": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/ws_probe.py",
    ),
    "gambling-saas-pentest-workflow": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "gen-mm8bet-gambling-family": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "gen-rails-gambling-pentest": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "guorenlianghua-quant-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "ida-reverse": (
        "传承/破核·基础.md",
        "炼蛊房/host_ir_check.py",
    ),
    "js-reverse": (
        "传承/星念蛊.md",
        "炼蛊房/js_secret_hunter.py",
    ),
    "kk8-tma-platform-pentest": (
        "传承/芋府·微域.md",
        "炼蛊房/yudao_appapi_probe.py",
    ),
    "laravel-api-auth-probing": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "laravel-gambling-tma-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "laravel-pentest": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "llm-security": (
        "传承/大灵.md",
        "炼蛊房/llm_surface_probe.py",
    ),
    "lsm-mclsm-gambling-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "m5ba-manba-family-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "m8-manba-gambling-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "m9-hsbox-gambling-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "malware-analysis": (
        "传承/破核·基础.md",
        "炼蛊房/host_ir_check.py",
    ),
    "mcp-toolkit-router": (
        "传承/凤金煌·分音.md",
        "炼蛊房/kit_run.py",
    ),
    "mm8bet-gen-whitelabel-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "network-tunneling": (
        "传承/太白云生·飞鹤游天.md",
        "炼蛊房/port_admin_scan.py",
    ),
    "nogle-mps-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "oauth2-password-grant-login-testing": (
        "传承/黑楼兰·硬撼.md",
        "炼蛊房/auth_brute_probe.py",
    ),
    "origami-tech-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "patch-diff-exploit": (
        "传承/补丁对照.md",
        "炼蛊房/nday_route.py",
    ),
    "pc28-odds-ws-intel": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/ws_probe.py",
    ),
    "pentest-workflow": (
        "传承/春秋蝉·分案.md",
        "炼蛊房/case_triage.py",
    ),
    "pentest-working-report": (
        "传承/春秋蝉·分案.md",
        "炼蛊房/case_report.py",
    ),
    "pg-operator-session-chain": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/session_pipeline.py",
    ),
    "pg-soft-launcher-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "php-debug-mode-exploitation": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "php-framework-debug-leak-pentest": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "pocketbase-horizons-recovery": (
        "传承/找回·站外.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "pwn-chain": (
        "传承/破核·基础.md",
        "炼蛊房/host_ir_check.py",
    ),
    "quake": (
        "传承/空间眼.md",
        "炼蛊房/origin_recon.py",
    ),
    "quant-copy-trading-platform-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "radare2": (
        "传承/破核·基础.md",
        "炼蛊房/host_ir_check.py",
    ),
    "recaptcha-bypass": (
        "传承/白兔·认纹.md",
        "炼蛊房/captcha_auto.py",
    ),
    "register-bypass-idor": (
        "传承/万我·信门.md",
        "炼蛊房/logic_vuln_probe.py",
    ),
    "saas-multitenant-acl-testing": (
        "传承/万我.md",
        "炼蛊房/object_matrix.py",
    ),
    "saas-multitenant-pentest": (
        "传承/万我.md",
        "炼蛊房/object_matrix.py",
    ),
    "saas-signup-multitenant-testing": (
        "传承/万我.md",
        "炼蛊房/object_matrix.py",
    ),
    "security-report-templates": (
        "传承/春秋蝉·分案.md",
        "炼蛊房/case_report.py",
    ),
    "skill-routing": (
        "传承/凤金煌·分音.md",
        "炼蛊房/kit_run.py",
    ),
    "smb-lateral-movement": (
        "传承/纵横天下.md",
        "炼蛊房/ad_surface_check.py",
    ),
    "spa-backend-api-pentest": (
        "传承/万我·信门.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "spa-frontend-reversing": (
        "传承/星念蛊.md",
        "炼蛊房/js_secret_hunter.py",
    ),
    "spa-protocol-reverse": (
        "传承/星宿·秘语.md",
        "炼蛊房/hall_crypto.py",
    ),
    "src-hunter": (
        "传承/空间眼.md",
        "炼蛊房/origin_recon.py",
    ),
    "ssrf-port-probe-classification": (
        "传承/定仙游·云骨.md",
        "炼蛊房/ssrf_probe.py",
    ),
    "supabase-pentest": (
        "传承/万我·信门.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "supabase-rls-pentest": (
        "传承/万我·信门.md",
        "炼蛊房/logic_vuln_probe.py",
    ),
    "supply-chain-security": (
        "传承/补丁对照.md",
        "炼蛊房/nday_route.py",
    ),
    "target-triage": (
        "传承/春秋蝉·分案.md",
        "炼蛊房/case_triage.py",
    ),
    "telegram-bot-discovery": (
        "传承/乐土·人情.md",
        "炼蛊房/tg_cmd_enum.py",
    ),
    "telegram-gambling-tma-pentest": (
        "传承/芋府·微域.md",
        "炼蛊房/yudao_appapi_probe.py",
    ),
    "tg-bot-pool-panel-pentest": (
        "传承/乐土·人情.md",
        "炼蛊房/tg_cloud_panel_probe.py",
    ),
    "tg-card-license-backend": (
        "传承/秦百胜·拍卖.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "tg-cloud-control-pentest": (
        "传承/乐土·人情.md",
        "炼蛊房/tg_cloud_panel_probe.py",
    ),
    "tg-marketing-saas-pentest": (
        "传承/乐土·人情.md",
        "炼蛊房/tg_social_monitor.py",
    ),
    "tg-payment-channel-pentest": (
        "传承/秦百胜·假契.md",
        "炼蛊房/pay_matrix.py",
    ),
    "tma-encrypted-api-reversal": (
        "传承/芋府·微域.md",
        "炼蛊房/hall_crypto.py",
    ),
    "tma-web-asset-discovery": (
        "传承/芋府·微域.md",
        "炼蛊房/yudao_appapi_probe.py",
    ),
    "waf-js-challenge-bypass": (
        "传承/隐鳞·手册.md",
        "炼蛊房/waf_detect.py",
    ),
    "wali-tg-tma-pentest": (
        "传承/芋府·微域.md",
        "炼蛊房/yudao_appapi_probe.py",
    ),
    "web-pentesting-ctf": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "whitelabel-gambling-pentest": (
        "传承/商心慈·白标.md",
        "炼蛊房/gambling_family_probe.py",
    ),
    "xiaolanben-equity": (
        "传承/商燕飞·盘口.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "yudao-web-appapi-pentest": (
        "传承/芋府·微域.md",
        "炼蛊房/yudao_appapi_probe.py",
    ),
    # 2026-09-05：百科 thin 卡补三件套（正文已长，缺 Playbook+工具引用）
    "api-security-testing": (
        "传承/万我·信门.md",
        "炼蛊房/api_dispatcher_enum.py",
    ),
    "business-logic-testing": (
        "传承/万我·信门.md",
        "炼蛊房/pay_matrix.py",
    ),
    "ci-cd-attack-testing": (
        "传承/工城·开天.md",
        "炼蛊房/nday_route.py",
    ),
    "cloud-ide-codex-rce": (
        "传承/红衣·壳.md",
        "炼蛊房/strike_probe.py",
    ),
    "cloud-security-audit": (
        "传承/定仙游·云骨.md",
        "炼蛊房/origin_recon.py",
    ),
    "command-injection-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "container-security-testing": (
        "传承/瓮中逃.md",
        "炼蛊房/linux_lpe_checker.py",
    ),
    "csrf-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "cyberbiz-saas-pentest": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "deserialization-testing": (
        "传承/化形.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "file-upload-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "ghost-bits-cast-attack": (
        "传承/隐鳞·手册.md",
        "炼蛊房/waf_detect.py",
    ),
    "idor-testing": (
        "传承/万我·信门.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "incident-response": (
        "传承/自我守护.md",
        "炼蛊房/host_ir_check.py",
    ),
    "information-gathering": (
        "传承/空间眼.md",
        "tools/space-search/bin/space_search.py",
    ),
    "intranet-penetration-testing": (
        "传承/纵横天下.md",
        "tools/tunnel-kit/internal_scan.py",
    ),
    "iokit-kernel-surface": (
        "ios-research/docs/内核攻击面与原语.md",
        "炼蛊房/nday_route.py",
    ),
    "ios-firmware-reverse": (
        "ios-research/docs/iOS固件逆向0day挖掘.md",
        "炼蛊房/nday_route.py",
    ),
    "ios-webkit-hunt": (
        "ios-research/docs/WebKit-GPU-Kernel攻击链研究.md",
        "炼蛊房/nday_route.py",
    ),
    "ldap-injection-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "mobile-app-security-testing": (
        "传承/安器·清单.md",
        "炼蛊房/apk_recon.py",
    ),
    "network-penetration-testing": (
        "传承/纵横天下.md",
        "tools/tunnel-kit/internal_scan.py",
    ),
    "rpc-txpool-mev": (
        "传承/凤九歌·天地歌.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "secure-code-review": (
        "传承/文审.md",
        "tools/deepaudit/bin/da_pipeline.py",
    ),
    "security-automation": (
        "传承/大爱仙尊整库蒸馏.md",
        "炼蛊房/engine_distill.py",
    ),
    "security-awareness-training": (
        "传承/凤金煌·分音.md",
        "炼蛊房/hypothesis_route.py",
    ),
    "sql-injection-testing": (
        "传承/吞库针.md",
        "炼蛊房/sqlmap_kit.py",
    ),
    "ssrf-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "vulnerability-assessment": (
        "传承/春秋蝉·分案.md",
        "炼蛊房/case_triage.py",
    ),
    "wallet-core-reverse": (
        "ios-research/docs/TronLink专项攻击技术集成.md",
        "炼蛊房/nday_route.py",
    ),
    "xpath-injection-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "xss-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
    "xxe-injection-testing": (
        "传承/薄青·岁岁索命.md",
        "炼蛊房/core_web_surface_probe.py",
    ),
}

SECTION_TEMPLATE = """\n\n## 真源\n\n- 手法：`{playbook}`\n- 工具：`python3 {tool} --help`\n"""

ALREADY_HAS_MARKERS = ("传承/", "炼蛊房/", "tools/pentest-")


def already_upgraded(text: str) -> bool:
    return any(m in text for m in ALREADY_HAS_MARKERS)


def upgrade_skill(skill_name: str, playbook: str, tool: str, dry_run: bool = False) -> str:
    skill_dir = SKILLS / skill_name
    if not skill_dir.is_dir():
        return f"SKIP  {skill_name}: 目录不存在"

    md_path = skill_dir / "SKILL.md"
    if not md_path.is_file():
        return f"SKIP  {skill_name}: SKILL.md 不存在"

    text = md_path.read_text(encoding="utf-8")

    if already_upgraded(text):
        return f"SKIP  {skill_name}: 已有真源引用"

    section = SECTION_TEMPLATE.format(playbook=playbook, tool=tool)
    new_text = text.rstrip() + section

    if dry_run:
        return f"DRY   {skill_name}: +playbook={playbook} +tool={tool}"

    md_path.write_text(new_text, encoding="utf-8")
    return f"OK    {skill_name}: +playbook={playbook} +tool={tool}"


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    if dry_run:
        print("[dry-run 模式，不写文件]\n")

    results = {"ok": 0, "skip": 0, "dry": 0}
    for skill_name, (playbook, tool) in sorted(MAPPING.items()):
        msg = upgrade_skill(skill_name, playbook, tool, dry_run=dry_run)
        print(msg)
        if msg.startswith("OK"):
            results["ok"] += 1
        elif msg.startswith("DRY"):
            results["dry"] += 1
        else:
            results["skip"] += 1

    total = len(MAPPING)
    print(f"\n{'─'*60}")
    if dry_run:
        print(f"预计升级: {results['dry']} / {total}  跳过: {results['skip']}")
    else:
        print(f"已升级: {results['ok']} / {total}  跳过: {results['skip']}")


if __name__ == "__main__":
    main()
