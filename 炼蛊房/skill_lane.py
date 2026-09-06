#!/usr/bin/env python3
"""把技能卡分成打站 / 分流 / 百科 / 库存。纸面打站卡单独列。

不扫 站点详情/、杀招/、作业入口/、呈文柜/、exports/。

  python3 炼蛊房/skill_lane.py
  python3 炼蛊房/skill_lane.py --lane attack_paper
"""
from __future__ import annotations

import argparse
from pathlib import Path

from skill_catalog import iter_skills

GENERIC_TOOLS = {
    "炼蛊房/auto_campaign.py",
    "炼蛊房/nday_route.py",
    "tools/1day-kit/od_kit.py",
}
META_TOOLS = {
    "炼蛊房/engine_distill.py",
    "炼蛊房/skill_catalog.py",
    "炼蛊房/skill_upgrade_thin.py",
    "炼蛊房/css_query.py",
    "炼蛊房/hypothesis_route.py",
    "炼蛊房/shizhan_pack_route.py",
}

ROUTER = {
    "1day-nuclei-kit",
    "ad-windows-router",
    "attack-chain",
    "attack-router",
    "campaign-router",
    "case-review",
    "case-triage",
    "cve-daily-intel",
    "cve-triage",
    "cybersecurity-catalog",
    "email-security",
    "engine-distill",
    "extended-skill-router",
    "gambling-family-router",
    "hitcon-zeroday-intel",
    "hypothesis-ledger",
    "keyword-router",
    "mcp-toolkit-router",
    "nine-stage-auto-router",
    "nine-stage-router",
    "pentest-methodology",
    "shizhan-pack-router",
    "skill-engineering",
    "web-vuln-router",
    "wordpress-attack-router",
}

ENCY_PREFIX = (
    "ios-",
    "iokit-",
    "address-sanitizer",
    "aflpp",
    "atheris",
    "cargo-fuzz",
    "libafl",
    "libfuzzer",
    "ossfuzz",
    "trailmark",
    "semgrep",
    "codeql",
    "wycheproof",
    "modern-cpp",
    "modern-python",
    "rust-review",
    "writing-lean",
    "diagramming",
    "docx",
    "pptx",
    "xlsx",
    "pdf",
    "doc-coauthoring",
)

ENCY = {
    "binary-diff",
    "binary-pwn",
    "ci-cd-attack-testing",
    "digital-forensics",
    "hardware-security",
    "iot-security-testing",
    "kernel-exploitation",
    "ot-ics",
    "patch-diff-exploit",
    "radio-sdr",
    "security-automation",
    "security-awareness-training",
    "supply-chain-security",
    "wifi-wireless",
    "wireless-security",
    "dotnet-reverse",
    "ghidra-reverse",
    "ida-reverse",
    "cyberstrike-eino-demo",
}


def _tool_name(rel: str) -> str:
    rel = (rel or "").split()[0]
    return rel


def unique_tools(rec: dict) -> list[str]:
    out = []
    for t in rec.get("tools") or []:
        t = _tool_name(t)
        if t in GENERIC_TOOLS or t in META_TOOLS:
            continue
        if t.endswith(".py"):
            out.append(t)
    return out


def lane_of(rec: dict) -> str:
    name = rec["name"]
    if rec.get("owned") or rec.get("stub"):
        return "owned" if rec.get("owned") else "stub"
    if name in ROUTER:
        return "router"
    if name in ENCY or name.startswith(ENCY_PREFIX):
        return "encyclopedia"
    tools = unique_tools(rec)
    generic_only = bool(rec.get("tools")) and not tools
    if generic_only:
        return "attack_paper"
    if tools:
        return "attack_ok"
    if rec.get("playbooks"):
        return "attack_paper"
    return "thin"


def classify() -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {
        "attack_ok": [],
        "attack_paper": [],
        "router": [],
        "encyclopedia": [],
        "owned": [],
        "stub": [],
        "thin": [],
    }
    for rec in iter_skills():
        buckets[lane_of(rec)].append(rec["name"])
    for k in buckets:
        buckets[k].sort()
    return buckets


def main() -> int:
    ap = argparse.ArgumentParser(description="打站卡 / 库存分闸")
    ap.add_argument("--lane", default="", help="只打印这一闸")
    args = ap.parse_args()
    buckets = classify()
    if args.lane:
        for name in buckets.get(args.lane, []):
            print(name)
        return 0
    print(
        "打站过关={ok}  打站纸面={paper}  分流={router}  百科={ency}  收编={owned}  stub={stub}  无入口={thin}".format(
            ok=len(buckets["attack_ok"]),
            paper=len(buckets["attack_paper"]),
            router=len(buckets["router"]),
            ency=len(buckets["encyclopedia"]),
            owned=len(buckets["owned"]),
            stub=len(buckets["stub"]),
            thin=len(buckets["thin"]),
        )
    )
    print("\n# 打站纸面（真该修，不跟 493 混刷）")
    for name in buckets["attack_paper"]:
        print(f"- {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
