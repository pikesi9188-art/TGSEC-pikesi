#!/usr/bin/env python3
"""按去留表删除已收编通用卡（只动 pack: survey-skill）。

默认删 C/D/E/F/G。只留打站专卡 + A/B + chrome-automation / stock-analysis。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "杀招"
STORE = ROOT / "docs" / "learning" / "skill-store"

KEEP_ALWAYS = {"chrome-automation", "stock-analysis"}
DROP_NAME = {"let-fate-decide", "interpreting-culture-index"}
TOB = "trailofbits/skills"
KEEP_A_NAME = {
    "webapp-testing", "ffuf", "ffuf-claude-skill", "burpsuite-project-parser",
    "firebase-apk-scanner", "firebase-security-rules-auditor",
    "django-access-review", "api-security-patterns", "find-bugs",
    "create-auth", "better-auth", "insecure-defaults", "semgrep-rule-creator",
    "semgrep-rule-variant-creator", "static-analysis", "variant-analysis",
    "sharp-edges", "codeql", "address-sanitizer", "aflpp", "atheris",
    "cargo-fuzz", "constant-time-analysis", "constant-time-testing",
    "differential-review", "audit-context-building", "audit-prep-assistant",
    "audit-augmentation", "agentic-actions-auditor", "entry-point-analyzer",
    "building-secure-contracts", "spec-to-code-compliance",
    "property-based-testing", "testing-handbook-skills",
    "antinet-security-scan", "antinet-provenance",
    "security-bluebook-builder", "defense-in-depth",
}
A_TOKEN = re.compile(
    r"(^|-)(semgrep|codeql|fuzz|sanitizer|owasp|xss|sqli|ssrf|rce|lfi|xxe|ssti|"
    r"pentest|exploit|cve-\d|unauth|takeover|kerberos|bloodhound|"
    r"vulnerability|insecure-default|webapp-testing)(-|$)",
    re.I,
)
KEEP_B_NAME = {
    "docx", "pptx", "xlsx", "pdf", "doc-coauthoring", "skill-creator",
    "mcp-builder", "antinet-doc-parse", "pdf-processing-pro",
    "paper-analysis-assistant", "contract-review", "law-to-markdown",
}
DROP_SRC_START = (
    "NVIDIA/", "ComposioHQ/", "coreyhaines31/", "LambdaTest/",
    "fal-ai-community/", "remotion-dev/", "op7418/", "zarazhangrui/",
)


def bucket(name: str, src: str) -> str:
    if name in DROP_NAME:
        return "F"
    if name in KEEP_ALWAYS:
        return "KEEP"
    if src == TOB or name in KEEP_A_NAME or A_TOKEN.search(name):
        return "A"
    if name in KEEP_B_NAME:
        return "B"
    if src.startswith("NVIDIA/"):
        return "D"
    if src.startswith("ComposioHQ/"):
        return "E"
    if src.startswith("LambdaTest/"):
        return "G"
    if any(src.startswith(p) for p in DROP_SRC_START):
        return "F"
    if src.startswith("skill-store/"):
        return "F"
    return "C"


def is_owned(skill_dir: Path) -> bool:
    md = skill_dir / "SKILL.md"
    if not md.is_file():
        return False
    head = md.read_text(encoding="utf-8", errors="replace")[:4000]
    return (
        "pack: survey-skill" in head
        or "owned: true" in head
        or "本卡已收编为大爱仙尊通用技能" in head
    )


def source_of(skill_dir: Path) -> str:
    md = skill_dir / "SKILL.md"
    if not md.is_file():
        return ""
    t = md.read_text(encoding="utf-8", errors="replace")[:4000]
    m = re.search(r"溯源（仅标记）：`([^`]+)`", t)
    return m.group(1) if m else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--drop", default="C,D,E,F,G", help="要删的桶")
    args = ap.parse_args()
    drop = {x.strip() for x in args.drop.split(",") if x.strip()}

    owned = json.loads((STORE / "owned.json").read_text(encoding="utf-8"))["skills"]
    victims = []
    kept = []
    for s in owned:
        b = bucket(s["name"], s["source"])
        if b in drop:
            victims.append(s)
        else:
            kept.append(s)

    print(f"owned={len(owned)} drop={len(victims)} keep={len(kept)} buckets={drop}")
    if not args.apply:
        print("dry-run. 加 --apply 才删。")
        return 0

    gone = 0
    for s in victims:
        name = s["name"]
        dest = SKILLS / name
        if dest.is_dir() and is_owned(dest):
            shutil.rmtree(dest)
            gone += 1
        sid = s.get("id") or ""
        store_dir = STORE / "skills" / sid
        if sid and store_dir.is_dir():
            shutil.rmtree(store_dir)
    (STORE / "owned.json").write_text(
        json.dumps(
            {"owned": True, "count": len(kept), "skills": kept},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    extra = rescan_cursor(drop)
    print(f"[+] removed_cursor={gone} rescan={extra} kept={len(kept)}")
    return 0


def rescan_cursor(drop: set[str]) -> int:
    """owned.json 已瘦身后，清掉仍留在 .cursor/skills 的 D/E/F/G。"""
    gone = 0
    for dest in SKILLS.iterdir():
        if not dest.is_dir() or dest.name in KEEP_ALWAYS:
            continue
        if not is_owned(dest):
            continue
        src = source_of(dest)
        b = bucket(dest.name, src)
        if b in drop:
            shutil.rmtree(dest)
            gone += 1
    return gone


if __name__ == "__main__":
    raise SystemExit(main())
