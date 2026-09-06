#!/usr/bin/env python3
"""授权样本 LSB / 追加隐写。不是隐写投毒工具。

  python3 炼蛊房/stego_lsb_probe.py drive --path img.png --case <案>
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import zlib
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402


def png_idat(data: bytes) -> bytes:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return b""
    pos = 8
    raw = b""
    while pos + 12 <= len(data):
        (ln,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + ln]
        pos += 12 + ln
        if ctype == b"IDAT":
            raw += chunk
        if ctype == b"IEND":
            break
    try:
        return zlib.decompress(raw)
    except zlib.error:
        return b""


def lsb_bytes(pixels: bytes, n: int = 64) -> bytes:
    bits = []
    for b in pixels[: n * 8]:
        bits.append(str(b & 1))
    out = []
    for i in range(0, len(bits) - 7, 8):
        out.append(int("".join(bits[i : i + 8]), 2))
    return bytes(out)


def classify(path: Path) -> dict:
    data = path.read_bytes()
    extra = {}
    level = "none"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        pix = png_idat(data)
        hidden = lsb_bytes(pix) if pix else b""
        extra = {"kind": "png", "idat": len(pix), "lsb_ascii": hidden[:32].decode("ascii", "replace")}
        if any(32 <= b < 127 for b in hidden[:16]):
            level = "L2"
        elif pix:
            level = "L1"
    elif data[:2] == b"PK":
        extra = {"kind": "zip-or-office", "size": len(data)}
        level = "L1"
    elif b"\x00" * 16 in data[-4096:]:
        extra = {"kind": "appended", "tail": data[-64:].hex()}
        level = "L1"
    extra.update({"path": str(path), "size": len(data), "level": level, "ts": datetime.now(UTC).isoformat(), "skill": "藏纹术"})
    return extra


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("drive",))
    ap.add_argument("--path", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    rec = classify(Path(args.path))
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="stego", filename="surface.json")
    print(json.dumps({"level": rec.get("level"), "out": str(out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
