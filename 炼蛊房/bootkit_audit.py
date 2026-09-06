#!/usr/bin/env python3
"""授权主机启动链审计。默认只读。标记只写案卷，不改 MBR/UEFI。

  python3 炼蛊房/bootkit_audit.py drive --case <案>
  python3 炼蛊房/bootkit_audit.py marker --case <案>
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import evidence_root, safe_case_name, write_probe_json  # noqa: E402


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)[:80]
    return ((r.stdout or "") + (r.stderr or ""))[:800]


def collect() -> dict:
    sysname = platform.system().lower()
    rec: dict = {"os": sysname, "efi": Path("/sys/firmware/efi").exists()}
    if sysname == "darwin":
        rec["efi"] = rec["efi"] or Path("/System/Volumes/Preboot").exists()
        rec["nvram"] = _run(["nvram", "-p"])
        rec["bless"] = _run(["bless", "--info", "--getBoot"])
    elif sysname == "linux":
        rec["cmdline"] = Path("/proc/cmdline").read_text(encoding="utf-8", errors="replace")[:300] if Path("/proc/cmdline").exists() else ""
        rec["efibootmgr"] = _run(["efibootmgr", "-v"])
    rec["boot_paths"] = [str(p) for p in (Path("/boot"), Path("/System/Volumes/Preboot")) if p.exists()]
    return rec


def cmd_drive(args: argparse.Namespace) -> int:
    rec = collect()
    rec.update({"level": "L1", "ts": datetime.now(UTC).isoformat(), "skill": "胎蛊审", "next": "只读。真要写启动项先问；标记用 marker 只落案卷。"})
    out = write_probe_json(rec, case=args.case, case_subdir="bootkit", filename="surface.json")
    print(json.dumps({"level": rec["level"], "os": rec["os"], "efi": rec.get("efi"), "out": str(out)}, ensure_ascii=False))
    return 0


def cmd_marker(args: argparse.Namespace) -> int:
    case = safe_case_name(args.case)
    if not case:
        raise SystemExit("[!] 需要 --case")
    d = evidence_root() / case / "测绘" / "bootkit"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "BOOT_LAB_MARKER.txt"
    p.write_text(
        "授权启动链演练标记。不写 MBR/ESP。复原：删本文件。\n" + datetime.now(UTC).isoformat() + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"marker": str(p)}, ensure_ascii=False))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="授权启动链审计")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("drive")
    d.add_argument("--case", required=True)
    m = sub.add_parser("marker")
    m.add_argument("--case", required=True)
    args = ap.parse_args()
    if args.cmd == "drive":
        raise SystemExit(cmd_drive(args))
    raise SystemExit(cmd_marker(args))


if __name__ == "__main__":
    main()
