#!/usr/bin/env python3
"""把 skill-store 收编为大爱仙尊自己的 杀招/ 卡。

不覆盖已有打站专卡。同名多源时按优先级取一份（全文+脚本一起拷）。
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from skill_prune import KEEP_ALWAYS, bucket  # noqa: E402
STORE = ROOT / "docs" / "learning" / "skill-store"
SKILLS = ROOT / "杀招"

KEEP_ALWAYS = {"chrome-automation", "stock-analysis"}
SKIP_SRC = (
    "NVIDIA/",
    "ComposioHQ/",
    "coreyhaines31/",
    "LambdaTest/",
    "fal-ai-community/",
    "remotion-dev/",
    "op7418/",
    "zarazhangrui/",
)
SOURCE_RANK = {
    "skill-store/local": 0,
    "anthropics/skills": 1,
    "trailofbits/skills": 2,
    "microsoft/skills": 3,
    "openai/skills": 4,
    "google/skills": 5,
    "getsentry/skills": 6,
    "huggingface/skills": 7,
    "obra/superpowers": 8,
    "expo/skills": 9,
    "LambdaTest/agent-skills": 10,
}


def _slug(name: str) -> str:
    s = name.lower().replace("_", "-")
    s = re.sub(r"[^a-z0-9-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return (s or "skill")[:64]


def _rank(source: str) -> int:
    if source in SOURCE_RANK:
        return SOURCE_RANK[source]
    if source.startswith("ComposioHQ"):
        return 900
    if source.startswith("NVIDIA"):
        return 800
    return 100


def _fm_desc(text: str) -> str:
    m = re.search(r"(?ms)^description:\s*>-?\s*\n((?:[ \t]+.*\n)+)", text)
    if m:
        return " ".join(ln.strip() for ln in m.group(1).splitlines() if ln.strip())
    m = re.search(r'(?m)^description:\s*["\']?(.*?)["\']?\s*$', text)
    return (m.group(1) if m else "").strip()


def _split_fm(text: str) -> tuple[str, str]:
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)", text, re.DOTALL)
    if not m:
        return "", text
    return m.group(1), m.group(2)


def _owned_skill_md(slug: str, src_text: str, source: str) -> str:
    _, body = _split_fm(src_text)
    desc = _fm_desc(src_text) or slug
    desc = re.sub(r"\s+", " ", desc).strip()
    if desc.startswith("大爱仙尊"):
        short = desc
    else:
        short = f"大爱仙尊·{desc}"
    if len(short) > 480:
        short = short[:477] + "…"
    # 缩进 description 折叠块
    wrapped = "\n".join("  " + ln for ln in _wrap(short, 88))
    head = (
        f"---\n"
        f"name: {slug}\n"
        f"description: >-\n{wrapped}\n"
        f"owned: true\n"
        f"pack: survey-skill\n"
        f"---\n\n"
        f"# {slug}（大爱仙尊）\n\n"
        f"本卡已收编为大爱仙尊通用技能。打站 / 假支付 / Actuator / 芋道代付仍走专卡。\n\n"
        f"全文与脚本目录：`智道藏书/skill-store/skills/{slug}/`\n\n"
        f"溯源（仅标记）：`{source}`\n\n"
        f"---\n\n"
    )
    return head + body.lstrip()


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines, cur = [], ""
    for w in words:
        nxt = (cur + " " + w).strip()
        if len(nxt) > width and cur:
            lines.append(cur)
            cur = w
        else:
            cur = nxt
    if cur:
        lines.append(cur)
    return lines or [text]


def pick_winners(entries: list[dict]) -> dict[str, dict]:
    best: dict[str, dict] = {}
    for s in entries:
        slug = _slug(s.get("name") or "")
        if not slug:
            continue
        src = s.get("source") or ""
        if bucket(s.get("name") or slug, src) not in {"A", "B", "KEEP"}:
            continue
        cur = best.get(slug)
        cand = dict(s)
        cand["_slug"] = slug
        cand["_rank"] = (_rank(s.get("source") or ""), -int(s.get("files") or 0))
        if cur is None or cand["_rank"] < cur["_rank"]:
            best[slug] = cand
    return best


def main() -> int:
    cat = json.loads((STORE / "catalog.json").read_text(encoding="utf-8"))
    biz = {p.name for p in SKILLS.iterdir() if p.is_dir()}
    winners = pick_winners(cat.get("skills") or [])
    copied = skipped_biz = skipped_exist = 0
    owned = []
    for slug, s in sorted(winners.items()):
        if slug in biz:
            dest_md = SKILLS / slug / "SKILL.md"
            if dest_md.is_file() and "pack: survey-skill" not in dest_md.read_text(
                encoding="utf-8", errors="replace"
            )[:4000]:
                skipped_biz += 1
                continue
        src = STORE / "skills" / s["id"]
        if not (src / "SKILL.md").is_file():
            continue
        dest = SKILLS / slug
        if dest.is_dir() and (dest / "SKILL.md").is_file():
            raw = (dest / "SKILL.md").read_text(encoding="utf-8", errors="replace")
            if "pack: survey-skill" in raw[:4000]:
                skipped_exist += 1
                owned.append({"name": slug, "source": s.get("source"), "id": s["id"]})
                continue
            if slug in biz:
                skipped_biz += 1
                continue
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(
            src,
            dest,
            ignore=shutil.ignore_patterns("*.mp4", "*.mov", "*.zip", ".DS_Store"),
        )
        src_text = (src / "SKILL.md").read_text(encoding="utf-8", errors="replace")
        (dest / "SKILL.md").write_text(
            _owned_skill_md(slug, src_text, s.get("source") or ""),
            encoding="utf-8",
        )
        copied += 1
        owned.append({"name": slug, "source": s.get("source"), "id": s["id"]})
    manifest = {
        "owned": True,
        "copied": copied,
        "skipped_business": skipped_biz,
        "already_owned": skipped_exist,
        "count": len(owned),
        "skills": owned,
    }
    (STORE / "owned.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        f"[+] owned={len(owned)} copied={copied} "
        f"skip_biz={skipped_biz} already={skipped_exist}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
