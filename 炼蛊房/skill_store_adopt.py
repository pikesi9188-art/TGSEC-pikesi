#!/usr/bin/env python3
"""把 skill-store 从外仓目录名收成大爱仙尊自己的 slug 树。

- 目录：trailofbits--skills--codeql → codeql
- 卡内路径、owned.json、catalog.json 一起改
- 去掉外仓 Logo
- 丢掉不是作业的卡（塔罗 / 文化指数）
不覆盖打站专卡。不扫 站点详情/、exports/。
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "docs" / "learning" / "skill-store"
SKILLS = ROOT / "杀招"
DROP = {"let-fate-decide", "interpreting-culture-index"}
FOREIGN = re.compile(
    r"智道藏书/skill-store/skills/[A-Za-z0-9_.-]+--[A-Za-z0-9_.-]+--([A-Za-z0-9_.-]+)/"
)
LOGO_NAMES = ("trail-of-bits-mark.svg", "trail-of-bits-mark.png")


def _slug_of(old_id: str, name: str) -> str:
    if name:
        return name
    return old_id.split("--")[-1] if "--" in old_id else old_id


def _strip_logos(root: Path) -> int:
    n = 0
    if not root.is_dir():
        return 0
    for p in root.rglob("*"):
        if p.is_file() and p.name in LOGO_NAMES:
            p.unlink()
            n += 1
    return n


def _is_owned_card(dest: Path) -> bool:
    md = dest / "SKILL.md"
    if not md.is_file():
        return False
    head = md.read_text(encoding="utf-8", errors="replace")[:4000]
    return "pack: survey-skill" in head or "owned: true" in head


def main() -> int:
    owned_path = STORE / "owned.json"
    owned = json.loads(owned_path.read_text(encoding="utf-8"))
    skills = list(owned.get("skills") or [])
    kept = []
    dropped = renamed = patched = logos = 0

    for s in skills:
        name = s.get("name") or ""
        old_id = s.get("id") or name
        slug = _slug_of(old_id, name)
        src = STORE / "skills" / old_id
        dest_store = STORE / "skills" / slug
        cursor = SKILLS / name

        if name in DROP:
            if src.is_dir():
                shutil.rmtree(src)
            if dest_store.is_dir() and dest_store != src:
                shutil.rmtree(dest_store)
            if cursor.is_dir() and _is_owned_card(cursor):
                shutil.rmtree(cursor)
            dropped += 1
            continue

        if src.is_dir() and src.resolve() != dest_store.resolve():
            if dest_store.exists():
                shutil.rmtree(dest_store)
            src.rename(dest_store)
            renamed += 1
        elif not dest_store.is_dir() and src.is_dir():
            src.rename(dest_store)
            renamed += 1

        s["id"] = slug
        kept.append(s)

        logos += _strip_logos(dest_store)
        if cursor.is_dir() and _is_owned_card(cursor):
            logos += _strip_logos(cursor)
            md = cursor / "SKILL.md"
            raw = md.read_text(encoding="utf-8")
            new = FOREIGN.sub(
                f"智道藏书/skill-store/skills/{slug}/", raw
            )
            # 旧 id 裸路径
            new = new.replace(
                f"智道藏书/skill-store/skills/{old_id}/",
                f"智道藏书/skill-store/skills/{slug}/",
            )
            if new != raw:
                md.write_text(new, encoding="utf-8")
                patched += 1

    owned["skills"] = kept
    owned["count"] = len(kept)
    owned["adopted"] = True
    owned_path.write_text(
        json.dumps(owned, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # 清残留外仓目录
    leftover = 0
    skills_dir = STORE / "skills"
    keep_ids = {s["id"] for s in kept}
    if skills_dir.is_dir():
        for p in list(skills_dir.iterdir()):
            if p.is_dir() and p.name not in keep_ids:
                shutil.rmtree(p)
                leftover += 1

    readme = [
        "# 大爱仙尊通用技能全文仓",
        "",
        "已收编进 `杀招/`（`pack: survey-skill`）。",
        "目录名就是技能 slug，不再用 `别人家--仓库--名字`。",
        "",
        "检索：`python3 炼蛊房/skill_catalog.py store --search <词>`",
        "再收编：`python3 炼蛊房/skill_own.py`",
        "外仓命名回收：`python3 炼蛊房/skill_store_adopt.py`",
        "",
        f"现役 **{len(kept)}** 张。溯源只写在 `owned.json`，对外算大爱仙尊技能。",
        "",
        "打站仍走专卡 + `传承/` + `炼蛊房/`。这里不替代作业三件套。",
        "",
        "| slug | 溯源（仅标记） |",
        "|------|----------------|",
    ]
    for s in sorted(kept, key=lambda x: x["name"]):
        readme.append(f"| `{s['name']}` | {s.get('source') or ''} |")
    (STORE / "README.md").write_text("\n".join(readme) + "\n", encoding="utf-8")

    print(
        f"[+] kept={len(kept)} renamed={renamed} patched={patched} "
        f"dropped={dropped} leftover={leftover} logos={logos}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
