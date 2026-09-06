#!/usr/bin/env python3
"""授权器胚 / 补丁对照：两份二进制的哈希、段长、字符串差。

  python3 炼蛊房/binary_diff_probe.py list
  python3 炼蛊房/binary_diff_probe.py drive --old a.bin --new b.bin --case <案>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402


def _meta(raw: bytes) -> dict:
    kind = "raw"
    if raw.startswith(b"\x7fELF"):
        kind = "elf"
    elif raw[:2] == b"MZ":
        kind = "pe"
    elif raw[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        kind = "macho"
    strs = sorted({m.decode("latin-1") for m in __import__("re").findall(rb"[\x20-\x7e]{8,}", raw[: 1024 * 256])})
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "kind": kind, "strings": strs[:80]}


def diff(old: bytes, new: bytes) -> dict:
    a, b = _meta(old), _meta(new)
    sa, sb = set(a["strings"]), set(b["strings"])
    return {
        "old": {k: a[k] for k in ("size", "sha256", "kind")},
        "new": {k: b[k] for k in ("size", "sha256", "kind")},
        "same_hash": a["sha256"] == b["sha256"],
        "added": sorted(sb - sa)[:30],
        "removed": sorted(sa - sb)[:30],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="授权二进制对照")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--old", default="")
    ap.add_argument("--new", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"kinds": ["elf", "pe", "macho", "raw"]}, ensure_ascii=False, indent=2))
        return 0
    op, np = Path(args.old), Path(args.new)
    if not op.is_file() or not np.is_file():
        print("[!] --old / --new 都要是文件", file=sys.stderr)
        return 2
    info = diff(op.read_bytes(), np.read_bytes())
    level = "L2" if (not info["same_hash"]) else "none"
    rec = {"skill": "binary-diff", **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="bindiff", filename="diff.json")
    print(json.dumps({"level": level, "kind": info["new"]["kind"], "added": len(info["added"]), "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
