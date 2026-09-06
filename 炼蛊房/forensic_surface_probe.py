#!/usr/bin/env python3
"""授权残忆面：目录 / 包里的凭据类工件计数。不打印口令/Cookie 值。

  python3 炼蛊房/forensic_surface_probe.py list
  python3 炼蛊房/forensic_surface_probe.py drive --path <导出目录或zip> --case <案>
"""
from __future__ import annotations

import argparse
import json
import zipfile
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402

HINTS = (
    ("cookies", ("cookies.sqlite", "cookies", "cookie")),
    ("login", ("login data", "logins.json", "signons.sqlite")),
    ("keychain", ("keychain", "login.keychain")),
    ("ssh", ("id_rsa", "id_ed25519", "known_hosts")),
    ("cloud", ("credentials", ".aws/credentials", "gcloud")),
    ("hist", (".bash_history", ".zsh_history", "console.log")),
    ("plist", (".plist",)),
    ("dump", (".hprof", ".dmp", "memory.dmp")),
)


def _names(root: Path) -> list[str]:
    if root.is_file() and zipfile.is_zipfile(root):
        with zipfile.ZipFile(root) as zf:
            return [n.lower() for n in zf.namelist()[:4000]]
    out = []
    for p in root.rglob("*"):
        if p.is_file():
            out.append(str(p.relative_to(root)).lower())
        if len(out) >= 4000:
            break
    return out


def classify(names: list[str]) -> dict[str, int]:
    hits: dict[str, int] = {}
    for label, keys in HINTS:
        n = 0
        for name in names:
            if any(k in name for k in keys):
                n += 1
        if n:
            hits[label] = n
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="授权残忆工件计数")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"classes": [k for k, _ in HINTS]}, ensure_ascii=False, indent=2))
        return 0
    p = Path(args.path)
    if not p.exists():
        print("[!] --path 不存在", file=sys.stderr)
        return 2
    hits = classify(_names(p))
    level = "L2" if hits else "none"
    rec = {
        "skill": "digital-forensics",
        "path": str(p),
        "hits": hits,
        "level": level,
        "note": "只计类，不吐值",
        "ts": datetime.now(UTC).isoformat(),
    }
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="forensic", filename="triage.json")
    print(json.dumps({"level": level, "hits": hits, "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
