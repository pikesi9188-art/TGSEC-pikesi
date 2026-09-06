#!/usr/bin/env python3
"""授权听波面：本机 SDR 是否在、离线 IQ 认形。不发射。

  python3 炼蛊房/radio_sdr_probe.py list
  python3 炼蛊房/radio_sdr_probe.py doctor
  python3 炼蛊房/radio_sdr_probe.py iq --path 采样.bin --case <案>
"""
from __future__ import annotations

import argparse
import json
import shutil
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402


def doctor() -> dict:
    bins = {n: bool(shutil.which(n)) for n in ("rtl_test", "rtl_sdr", "hackrf_info", "SoapySDRUtil", "gqrx")}
    return {"bins": bins, "tx": False, "note": "有棒再采；本探针不发"}


def classify_iq(raw: bytes, name: str) -> dict:
    rec = {"size": len(raw), "kind": "unknown", "peak": 0.0}
    if name.lower().endswith(".wav") and raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
        rec["kind"] = "wav"
        rec["peak"] = 1.0
        return rec
    if len(raw) >= 8 and raw[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe"):
        rec["kind"] = "not-iq"
        return rec
    n = min(len(raw), 4096)
    if n < 16:
        return rec
    # 试 u8 IQ
    u8 = raw[:n]
    mean = sum(u8) / n
    if 90 < mean < 165:
        rec["kind"] = "u8-iq"
        rec["peak"] = max(abs(b - 127) for b in u8) / 128
        return rec
    # 试 cf32
    if n >= 32:
        vals = struct.unpack("<" + "f" * (n // 4), raw[: n // 4 * 4])
        if all(abs(v) < 20 for v in vals[:32]):
            rec["kind"] = "cf32"
            rec["peak"] = max(abs(v) for v in vals[:256]) if vals else 0
            return rec
    rec["kind"] = "raw"
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description="授权听波（不发射）")
    ap.add_argument("cmd", choices=("list", "doctor", "iq"))
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"cmds": ["doctor", "iq"], "tx": False}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "doctor":
        rec = {"skill": "radio-sdr", **doctor(), "level": "L1", "ts": datetime.now(UTC).isoformat()}
        print(json.dumps(rec, ensure_ascii=False, indent=2))
        return 0
    p = Path(args.path)
    if not p.is_file():
        print("[!] --path IQ 不存在", file=sys.stderr)
        return 2
    raw = p.read_bytes()[: 1024 * 64]
    info = classify_iq(raw, p.name)
    level = "L2" if info["kind"] in {"u8-iq", "cf32", "wav"} else "L1"
    rec = {"skill": "radio-sdr", "path": str(p), **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="sdr", filename="iq.json")
    print(json.dumps({"level": level, "kind": info["kind"], "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
