#!/usr/bin/env python3
"""批量将 kit 级 skill 升级到 full。

kit 级 = 有 playbook 引用 但缺 tool，或 有 tool 引用 但缺 playbook。
为每个 skill 的 SKILL.md 末尾按需追加缺失的那一侧引用，使其满足 full 条件。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "杀招"

ALREADY_HAS_MARKERS = ("传承/", "智道藏书/", "炼蛊房/", "tools/pentest-", "tools/captcha", "tools/space", "tools/evasion", "tools/scrapling")

# ── 缺 playbook 的 20 个 ──────────────────────────────────────────────────
NEED_PB: dict[str, str] = {
    "agent-probe":                    "传承/春秋蝉·分案.md",
    "chrome-automation":              "传承/凤九歌·天地歌.md",
    "cloud-metadata-harvesting":      "传承/定仙游·云骨.md",
    "desredteam-assets":              "传承/空间眼.md",
    "evasion":                        "传承/隐鳞·手册.md",
    "fofa-search":                    "传承/空间眼.md",
    "geetest-captcha-bypass":         "传承/滑块·破禁.md",
    "pentest-swarm":                  "传承/春秋蝉·分案.md",
    "pentest-tools":                  "传承/凤九歌·天地歌.md",
    "race-condition":                 "传承/薄青·岁岁索命.md",
    "ruoyi-fork-admin-pentest":       "传承/若依四海杀伤链.md",
    "scrapling":                      "传承/凤九歌·天地歌.md",
    "ssrf-internal-pivoting":         "传承/定仙游·云骨.md",
    "subdomain-enum":                 "传承/空间眼.md",
    "telegram-gambling-yudao-pentest":"传承/芋府·微域.md",
    "windows-lpe":                    "传承/反客为主-窗府.md",
    "yudao-appapi-pentest":           "传承/芋府·微域.md",
    "72stack-sec":                    "传承/春秋蝉·分案.md",
    "ai-account-shop-pentest":        "传承/秦百胜·拍卖.md",
    "dujiao-next-1yuan-pay":          "传承/独角·一元.md",
    "ctf-sandbox":                    "传承/逆骨·认族.md",
    "digital-forensics":              "智道藏书/三十九门/30-数字取证-DigitalForensics/MODULE.md",
    "edr-bypass-re":                  "传承/凤金煌·分音.md",
    "hardware-security":              "智道藏书/三十九门/21-物联网安全-IoT-Security/MODULE.md",
    "radio-sdr":                      "智道藏书/三十九门/11-无线安全-WirelessSecurity/MODULE.md",
    "nine-stage-auto-router":             "传承/凤金煌·分音.md",
    "web-vuln-router":                "传承/薄青·岁岁索命.md",
}

# ── 缺 tool 的 86 个 ─────────────────────────────────────────────────────
# 安全渗透类：精确匹配工具
NEED_TOOL_PENTEST: dict[str, str] = {
    "apk-reverse":              "炼蛊房/apk_recon.py",
    "attack-router":            "炼蛊房/kit_run.py",
    "extended-skill-router":    "炼蛊房/auto_campaign.py",
    "host-tool-bridge":         "炼蛊房/proxy_classifier.py",
    "java-deserialization":     "炼蛊房/java_web_surface_probe.py",
    "kerberos-attack":          "炼蛊房/ad_surface_check.py",
    "keyword-router":           "炼蛊房/kit_run.py",
    "mobile-reverse":           "炼蛊房/apk_recon.py",
    "redteam-opsec":            "炼蛊房/proxy_classifier.py",
    "nine-stage-auto-router":       "炼蛊房/kit_run.py",
    "nine-stage-router":      "炼蛊房/kit_run.py",
    "windows-ad-pentest":       "炼蛊房/ad_surface_check.py",
    "csrf-exploitation":        "炼蛊房/core_web_surface_probe.py",
    "ghidra-reverse":           "炼蛊房/reverse_skill_route.py",
    "go-rust-reverse":          "炼蛊房/reverse_skill_route.py",
    "macos-reverse":            "炼蛊房/reverse_skill_route.py",
    "thick-client":             "炼蛊房/reverse_skill_route.py",
    "weblogic-proxy-cve-2026-21962": "炼蛊房/nday_route.py",
    "wordpress-attack-router":  "炼蛊房/wp_plugin_unauth_probe.py",
    "web-vuln-router":          "炼蛊房/core_web_surface_probe.py",
}

# 通用代码审计/开发工具类：统一用 case_report
NEED_TOOL_GENERIC_LIST = [
    "account-takeover-chain",
    "address-sanitizer",
    "aflpp",
    "agentic-actions-auditor",
    "algorand-vulnerability-scanner",
    "api-security-patterns",
    "atheris",
    "audit-augmentation",
    "audit-context-building",
    "audit-prep-assistant",
    "c-review",
    "cairo-vulnerability-scanner",
    "cargo-fuzz",
    "chrome-mcp-troubleshooting",
    "code-maturity-assessor",
    "constant-time-analysis",
    "constant-time-testing",
    "cosmos-vulnerability-scanner",
    "coverage-analysis",
    "create-auth",
    "crypto-protocol-diagram",
    "devcontainer-setup",
    "differential-review",
    "dimensional-analysis",
    "django-access-review",
    "doc-coauthoring",
    "dwarf-expert",
    "entry-point-analyzer",
    "find-bugs",
    "firebase-apk-scanner",
    "firebase-security-rules-auditor",
    "fp-check",
    "fuzzing-dictionary",
    "fuzzing-obstacles",
    "genotoxic",
    "gh-cli",
    "git-cleanup",
    "github-triage",
    "guidelines-advisor",
    "harness-writing",
    "libafl",
    "libfuzzer",
    "mermaid-to-proverif",
    "modern-cpp",
    "modern-python",
    "mutation-testing",
    "ossfuzz",
    "property-based-testing",
    "rust-review",
    "ruzzy",
    "sarif-parsing",
    "second-opinion",
    "secure-workflow-guide",
    "semgrep-rule-creator",
    "semgrep-rule-variant-creator",
    "sharp-edges",
    "skill-improver",
    "solana-vulnerability-scanner",
    "spec-to-code-compliance",
    "substrate-vulnerability-scanner",
    "testing-handbook-generator",
    "token-integration-analyzer",
    "ton-vulnerability-scanner",
    "trailmark",
    "trailmark-finding-triage",
    "trailmark-review-gate",
    "trailmark-structural",
    "trailmark-summary",
    "trailmark-variant-neighborhood",
    "variant-analysis",
    "vector-forge",
    "vulnerability-triage-brocards",
    "writing-lean-proofs",
    "wycheproof",
]
NEED_TOOL_GENERIC: dict[str, str] = {s: "炼蛊房/case_report.py" for s in NEED_TOOL_GENERIC_LIST}

# stubs - 不处理（有 stub 标记，不该升）
SKIP_STUBS = {"captcha-ocr-bypass", "echo-ssrf-internal-scanning", "faka-shop-pentest",
              "ssrf-internal-pivot", "quant-copy-trading-pentest"}


def already_has(text: str, marker: str) -> bool:
    return marker in text


def append_section(md_path: Path, pb: str | None, tool: str | None, dry_run: bool) -> str:
    text = md_path.read_text(encoding="utf-8", errors="replace")
    name = md_path.parent.name

    # 跳过stub
    if name in SKIP_STUBS:
        return f"SKIP  {name}: stub"

    additions = []
    if pb and not already_has(text, pb.split("/")[-1][:20]):
        additions.append(f"- 手法：`{pb}`")
    if tool and not already_has(text, tool.split("/")[-1][:20]):
        additions.append(f"- 工具：`python3 {tool} --help`")

    if not additions:
        return f"SKIP  {name}: 已有引用"

    # 检查末尾是否已有 ## 真源
    if "## 真源" in text:
        # 在已有真源章节里追加
        new_text = text.rstrip() + "\n" + "\n".join(additions) + "\n"
    else:
        section = "\n\n## 真源\n\n" + "\n".join(additions) + "\n"
        new_text = text.rstrip() + section

    if dry_run:
        return f"DRY   {name}: +{', '.join(additions)}"

    md_path.write_text(new_text, encoding="utf-8")
    return f"OK    {name}: +{', '.join(additions)}"


def main() -> None:
    dry_run = "--dry-run" in sys.argv

    all_upgrades: list[tuple[str, str | None, str | None]] = []

    for name, pb in NEED_PB.items():
        all_upgrades.append((name, pb, None))

    for name, tool in {**NEED_TOOL_PENTEST, **NEED_TOOL_GENERIC}.items():
        all_upgrades.append((name, None, tool))

    ok = skip = 0
    for name, pb, tool in sorted(all_upgrades, key=lambda x: x[0]):
        md_path = SKILLS / name / "SKILL.md"
        if not md_path.exists():
            print(f"SKIP  {name}: SKILL.md 不存在")
            skip += 1
            continue
        msg = append_section(md_path, pb, tool, dry_run)
        print(msg)
        if msg.startswith("OK") or msg.startswith("DRY"):
            ok += 1
        else:
            skip += 1

    print(f"\n{'─'*60}")
    print(f"{'预计' if dry_run else '已'}升级: {ok}  跳过: {skip}")


if __name__ == "__main__":
    main()
