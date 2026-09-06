#!/usr/bin/env python3
"""Nuitka / PyInstaller 授权包：认族 + 列 TOC / 抽嵌入串。

  python3 炼蛊房/py_pack_reverse.py drive --path <样本> --case <案>
  python3 炼蛊房/py_pack_reverse.py list --path <样本>
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402

PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
NAME_RX = re.compile(rb"[\x20-\x7e]{6,80}\.py[coz]?")


def read_sample(path: Path, head: int = 8_000_000, tail: int = 2_000_000) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size <= head + tail:
            return fh.read()
        head_b = fh.read(head)
        fh.seek(max(0, size - tail))
        return head_b + fh.read()


def find_pyinstaller(data: bytes) -> dict[str, Any]:
    idx = data.rfind(PYI_MAGIC)
    if idx < 0:
        return {"ok": False}
    tail = data[idx:]
    rec: dict[str, Any] = {"ok": True, "magic_off": hex(idx), "cookie_len": len(tail)}
    if len(tail) >= 24:
        magic, pkg_len, toc_off, toc_len, pyver = struct.unpack_from("<8sIIII", tail, 0)
        rec.update({"pkg_len": pkg_len, "toc_off": toc_off, "toc_len": toc_len, "pyver": pyver})
    names = [m.group().decode("ascii", "replace") for m in NAME_RX.finditer(data[-min(len(data), 2_000_000):])]
    rec["py_names"] = list(dict.fromkeys(names))[:40]
    rec["authish"] = [n for n in rec["py_names"] if any(x in n.lower() for x in ("licen", "auth", "vip", "card", "fndata"))]
    return rec


def find_nuitka(data: bytes) -> dict[str, Any]:
    hit = any(s in data[: min(len(data), 4_000_000)] for s in (b"NUITKA_ONEFILE", b"nuitka", b"onefile_progress"))
    if not hit:
        return {"ok": False}
    names = [m.group().decode("ascii", "replace") for m in NAME_RX.finditer(data[:2_000_000])]
    return {"ok": True, "py_names": list(dict.fromkeys(names))[:40]}


def classify(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "kind": "unknown", "level": "none", "err": "missing"}
    data = read_sample(path)
    pyi = find_pyinstaller(data)
    nu = find_nuitka(data)
    kind = "pyinstaller" if pyi.get("ok") else ("nuitka" if nu.get("ok") else "unknown")
    level = "none"
    if kind != "unknown":
        level = "L1"
    extra = (pyi.get("authish") if pyi.get("ok") else []) or []
    if extra or (kind != "unknown" and (pyi.get("py_names") or nu.get("py_names"))):
        if extra:
            level = "L2"
    return {
        "path": str(path),
        "kind": kind,
        "level": level,
        "pyinstaller": pyi,
        "nuitka": nu,
        "ts": datetime.now(UTC).isoformat(),
        "skill": "蛇蜕",
        "next": "L2=TOC/串里出现 auth/license。解出 .py 后交 net-license-crack。",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Nuitka/PyInstaller 认族")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("drive", "list"):
        p = sub.add_parser(name)
        p.add_argument("--path", required=True)
        p.add_argument("--case", default="")
        p.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    rec = classify(Path(args.path))
    if args.cmd == "drive":
        out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="py_pack", filename="surface.json")
        print(json.dumps({"level": rec["level"], "kind": rec["kind"], "out": str(out)}, ensure_ascii=False))
    else:
        print(json.dumps(rec, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
