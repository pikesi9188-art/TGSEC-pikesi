#!/usr/bin/env python3
"""授权硬件面：固件魔数 + 调试串口字符串。不先堆喷、不写熔丝。

  python3 炼蛊房/hardware_surface_probe.py list
  python3 炼蛊房/hardware_surface_probe.py drive --path 固件.bin --case <案>
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

MAGICS = (
    (b"\x27\x05\x19\x56", "uimage"),
    (b"UBI#", "ubi"),
    (b"hsqs", "squashfs"),
    (b"sqsh", "squashfs"),
    (b"\xd0\x0d\xfe\xed", "dtb"),
    (b"ANDROID!", "android-boot"),
    (b"\x7fELF", "elf"),
    (b"IM4P", "im4p"),
    (b"IMG4", "img4"),
)

DEBUG_RX = re.compile(
    rb"(console=|jtag|uart\d|uboot|u-boot|cfi flash|root:|admin:|telnetd|dropbear)",
    re.I,
)


def classify(raw: bytes) -> dict:
    kinds = []
    window = raw[: 1024 * 64]
    for magic, name in MAGICS:
        if magic in window[:4096] or raw.startswith(magic):
            kinds.append(name)
        elif magic in raw[: 1024 * 32]:
            kinds.append(name)
    hits = sorted({m.group(0).decode("latin-1", "replace").lower() for m in DEBUG_RX.finditer(raw[: 1024 * 256])})
    return {"size": len(raw), "kinds": sorted(set(kinds)), "debug": hits[:20]}


def level_of(info: dict) -> str:
    if info.get("debug") or info.get("kinds"):
        return "L2"
    return "none"


def main() -> int:
    ap = argparse.ArgumentParser(description="授权固件 / 硬件面")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"magics": [n for _m, n in MAGICS]}, ensure_ascii=False, indent=2))
        return 0
    p = Path(args.path)
    if not p.is_file():
        print("[!] --path 固件不存在", file=sys.stderr)
        return 2
    info = classify(p.read_bytes())
    level = level_of(info)
    rec = {"skill": "hardware-security", "path": str(p), **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="hardware", filename="firmware.json")
    print(json.dumps({"level": level, "kinds": info["kinds"], "debug": info["debug"], "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
