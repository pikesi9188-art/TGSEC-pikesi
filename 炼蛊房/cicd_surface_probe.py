#!/usr/bin/env python3
"""授权工坊 / 自走面：本地工作流危险模式。不改远端流水线。

  python3 炼蛊房/cicd_surface_probe.py list
  python3 炼蛊房/cicd_surface_probe.py drive --path <仓根> --case <案>
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
from scope_lib import write_probe_json  # noqa: E402

RULES = (
    ("pull_request_target", re.compile(r"pull_request_target")),
    ("issue_body_interp", re.compile(r"github\.event\.(issue|comment|pull_request)\.(body|title)")),
    ("unpinned_action", re.compile(r"uses:\s+[^\s]+@v\d")),
    ("secret_in_run", re.compile(r"run:.*\$\{\{\s*secrets\.")),
    ("curl_pipe_sh", re.compile(r"curl[^\n]+\|\s*(ba)?sh")),
    ("cron", re.compile(r"schedule:|cron:")),
)


def scan(root: Path) -> list[dict]:
    hits = []
    globs = (
        ".github/workflows/*",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".circleci/config.yml",
        "azure-pipelines.yml",
    )
    files: list[Path] = []
    for g in globs:
        files.extend(root.glob(g))
    for p in files:
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        found = [name for name, rx in RULES if rx.search(text)]
        if found:
            hits.append({"path": str(p.relative_to(root)), "rules": found})
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="授权 CI/CD 工作流面")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--path", default=".")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"rules": [n for n, _ in RULES]}, ensure_ascii=False, indent=2))
        return 0
    root = Path(args.path).resolve()
    if not root.is_dir():
        print("[!] --path 不是目录", file=sys.stderr)
        return 2
    hits = scan(root)
    level = "L2" if hits else "none"
    rec = {"skill": "ci-cd-attack-testing", "root": str(root), "hits": hits, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="cicd", filename="workflows.json")
    print(json.dumps({"level": level, "hits": len(hits), "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
