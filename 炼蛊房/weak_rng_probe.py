#!/usr/bin/env python3
"""弱 PRNG / LCG：从连续输出反推状态（授权钱包/卡密样本）。

  python3 炼蛊房/weak_rng_probe.py lcg --out 12345 --out 1406932606
  python3 炼蛊房/weak_rng_probe.py glibc --seed 1 --n 5
  python3 炼蛊房/weak_rng_probe.py drive --path dump.txt --case <案>
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

# (name, a, c, m, used_bits)
LCGs = (
    ("glibc", 1103515245, 12345, 2**31, 31),
    ("msvc", 214013, 2531011, 2**31, 31),
    ("numerical", 1664525, 1013904223, 2**32, 32),
    ("java_lcg", 25214903917, 11, 2**48, 48),
)


def lcg_next(x: int, a: int, c: int, m: int) -> int:
    return (a * x + c) % m


def lcg_prev(x: int, a: int, c: int, m: int) -> int:
    return (pow(a, -1, m) * ((x - c) % m)) % m


def recover_lcg(outputs: list[int]) -> dict:
    if len(outputs) < 2:
        return {"ok": False, "reason": "need>=2"}
    hits = []
    for name, a, c, m, bits in LCGs:
        mask = (1 << min(bits, 31)) - 1 if name in {"glibc", "msvc"} else (m - 1)
        # glibc/msvc: observed is state >> 16 or full 31-bit
        for shift in (0, 16):
            x0 = outputs[0] << shift if shift else outputs[0]
            if x0 >= m:
                continue
            pred = lcg_next(x0, a, c, m)
            obs = (pred >> shift) if shift else pred
            expect = outputs[1] & mask
            got = obs & mask
            if got == expect:
                nxt = lcg_next(pred, a, c, m)
                hits.append({
                    "family": name,
                    "a": a,
                    "c": c,
                    "m": m,
                    "shift": shift,
                    "state": pred,
                    "next": (nxt >> shift) if shift else nxt,
                    "prev": lcg_prev(x0, a, c, m),
                })
    return {"ok": bool(hits), "hits": hits[:8], "n": len(outputs)}


NUM = re.compile(r"\b(\d{2,16})\b")


def cmd_lcg(args: argparse.Namespace) -> int:
    rec = recover_lcg([int(x) for x in args.out])
    print(json.dumps(rec, ensure_ascii=False, indent=2))
    return 0 if rec.get("ok") else 1


def cmd_glibc(args: argparse.Namespace) -> int:
    a, c, m, _ = next(x for x in LCGs if x[0] == "glibc")
    x = int(args.seed)
    seq = []
    for _ in range(args.n):
        x = lcg_next(x, a, c, m)
        seq.append(x)
    print(json.dumps({"seed": args.seed, "seq": seq}, ensure_ascii=False))
    return 0


def cmd_drive(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        print(f"[!] 没有文件: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    nums = [int(x) for x in NUM.findall(text)[:40]]
    rec = recover_lcg(nums[:8]) if len(nums) >= 2 else {"ok": False, "reason": "no-pair"}
    rec.update({"path": str(args.path), "ts": datetime.now(UTC).isoformat(), "skill": "弱天机"})
    rec["level"] = "L2" if rec.get("ok") else ("L1" if nums else "none")
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="weak_rng", filename="surface.json")
    print(json.dumps({"level": rec["level"], "ok": rec.get("ok"), "out": str(out)}, ensure_ascii=False))
    return 0 if rec.get("ok") else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="弱 LCG / PRNG 反推")
    sub = ap.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("lcg")
    l.add_argument("--out", action="append", required=True)
    g = sub.add_parser("glibc")
    g.add_argument("--seed", default="1")
    g.add_argument("--n", type=int, default=5)
    d = sub.add_parser("drive")
    d.add_argument("--path", required=True)
    d.add_argument("--case", default="")
    d.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "lcg":
        raise SystemExit(cmd_lcg(args))
    if args.cmd == "glibc":
        raise SystemExit(cmd_glibc(args))
    raise SystemExit(cmd_drive(args))


if __name__ == "__main__":
    main()
