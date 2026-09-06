#!/usr/bin/env python3
"""房睇长日更：本仓 CVE 日报是否按日落地、能否抽出编号。

  python3 炼蛊房/cve_daily_probe.py list
  python3 炼蛊房/cve_daily_probe.py drive --case <案>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import repo_root, write_probe_json  # noqa: E402

NAME_RX = re.compile(r"CVE日报-(\d{4}-\d{2}-\d{2})\.md$")
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}")


def scan(root: Path) -> dict:
    dirs = [
        root / "docs" / "intel" / "cve-daily",
        root / "传承",
        root / "docs" / "playbooks",
    ]
    files = []
    for d in dirs:
        if d.is_dir():
            files.extend(p for p in d.glob("CVE日报-*.md") if p.is_file())
    rows = []
    for p in sorted(files)[-20:]:
        m = NAME_RX.search(p.name)
        text = p.read_text(encoding="utf-8", errors="replace")
        cves = sorted(set(CVE_RX.findall(text)))
        rows.append({"name": p.name, "date": m.group(1) if m else "", "cves": len(cves), "sample": cves[:5]})
    return {"files": len(files), "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="本仓 CVE 日报面")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"need": "CVE日报-YYYY-MM-DD.md"}, ensure_ascii=False))
        return 0
    info = scan(repo_root(Path(__file__)))
    dated = [r for r in info["rows"] if r["date"] and r["cves"]]
    level = "L2" if dated else ("L1" if info["files"] else "none")
    rec = {"skill": "cve-daily-intel", **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="cve_daily", filename="daily.json")
    print(json.dumps({"level": level, "files": info["files"], "dated": len(dated), "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
