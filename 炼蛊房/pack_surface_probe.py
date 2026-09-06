#!/usr/bin/env python3
"""实战认族 / 旁支认族 / 防务名录：挂号能否落到本仓卡。

  python3 炼蛊房/pack_surface_probe.py list
  python3 炼蛊房/pack_surface_probe.py drive --name 工控 --case <案>
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


def _naming(root: Path) -> dict[str, str]:
    p = root / "NAMING.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {str(k): str(v) for k, v in (data.get("skills") or {}).items()}


def resolve(root: Path, name: str) -> dict:
    naming = _naming(root)
    dest = naming.get(name) or name
    cursors = [
        root / "杀招" / dest / "SKILL.md",
        root / "杀招" / name / "SKILL.md",
        root / ".cursor" / "skills" / name / "SKILL.md",
        root / ".cursor" / "skills" / dest / "SKILL.md",
    ]
    hit = next((str(p.relative_to(root)) for p in cursors if p.is_file()), "")
    return {"query": name, "dest": dest, "skill_md": hit, "ok": bool(hit)}


def main() -> int:
    ap = argparse.ArgumentParser(description="挂号落到本仓卡")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--name", default="ot-ics")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    root = repo_root(Path(__file__))
    if args.cmd == "list":
        naming = _naming(root)
        print(json.dumps({"named": len(naming), "sample": list(naming.items())[:5]}, ensure_ascii=False, indent=2))
        return 0
    info = resolve(root, args.name)
    level = "L2" if info["ok"] else "none"
    rec = {"skill": "extended-skill-router", **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="pack", filename="resolve.json")
    print(json.dumps({"level": level, **info, "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
