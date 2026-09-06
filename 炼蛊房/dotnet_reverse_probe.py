#!/usr/bin/env python3
"""授权残网拆骨：PE/.NET 认形 + 配置键名。不打印连接串值。

  python3 炼蛊房/dotnet_reverse_probe.py list
  python3 炼蛊房/dotnet_reverse_probe.py drive --path 程序.exe --case <案>
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

KEY_RX = re.compile(
    rb"(ConnectionString|appSettings|machineKey|viewStateUserKey|aspnetcore|EntityFramework|NHibernate)",
    re.I,
)


def classify(raw: bytes) -> dict:
    pe = raw[:2] == b"MZ"
    clr = b"BSJB" in raw[: 1024 * 64] or b"mscoree.dll" in raw[: 1024 * 32]
    keys = sorted({m.group(0).decode("ascii", "replace") for m in KEY_RX.finditer(raw[: 1024 * 512])})
    return {"pe": pe, "dotnet": bool(pe and clr), "keys": keys[:20], "size": len(raw)}


def main() -> int:
    ap = argparse.ArgumentParser(description="授权 .NET 认形")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"signals": ["MZ", "BSJB", "ConnectionString"]}, ensure_ascii=False, indent=2))
        return 0
    p = Path(args.path)
    if not p.is_file():
        print("[!] --path 不存在", file=sys.stderr)
        return 2
    info = classify(p.read_bytes())
    level = "L2" if info["dotnet"] or info["keys"] else ("L1" if info["pe"] else "none")
    rec = {"skill": "dotnet-reverse", "path": str(p), **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="dotnet", filename="pe.json")
    print(json.dumps({"level": level, "dotnet": info["dotnet"], "keys": info["keys"], "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
