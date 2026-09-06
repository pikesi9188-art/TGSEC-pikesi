#!/usr/bin/env python3
"""雷击面：技能目录能否被检索（frontmatter + SKILL.md）。

  python3 炼蛊房/eino_skill_probe.py list
  python3 炼蛊房/eino_skill_probe.py drive --case <案>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import repo_root, write_probe_json  # noqa: E402


def scan(root: Path) -> dict:
    dirs = [root / "杀招", root / ".cursor" / "skills"]
    rows = []
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            md = p / "SKILL.md"
            if not md.is_file():
                continue
            text = md.read_text(encoding="utf-8", errors="replace")[:400]
            fm = text.startswith("---")
            rows.append({"name": p.name, "frontmatter": fm})
    return {"count": len(rows), "with_fm": sum(1 for r in rows if r["frontmatter"]), "sample": [r["name"] for r in rows[:8]]}


def main() -> int:
    ap = argparse.ArgumentParser(description="技能柜检索面")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"look": ["杀招/", ".cursor/skills/"]}, ensure_ascii=False))
        return 0
    info = scan(repo_root(Path(__file__)))
    level = "L2" if info["count"] >= 1 and info["with_fm"] >= 1 else "none"
    rec = {"skill": "cyberstrike-eino-demo", **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="eino", filename="skills.json")
    print(json.dumps({"level": level, "count": info["count"], "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
