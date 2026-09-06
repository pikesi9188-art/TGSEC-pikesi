#!/usr/bin/env python3
"""授权 OT/ICS 面：只读协议指纹。禁止写线圈 / 下装 PLC。

  python3 炼蛊房/ot_ics_probe.py list
  python3 炼蛊房/ot_ics_probe.py drive --host <IP> --case <案>
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

FAMILIES = (
    ("modbus", 502, "Modbus TCP MEI"),
    ("s7", 102, "S7 COTP CR"),
    ("enip", 44818, "EtherNet/IP ListIdentity"),
    ("dnp3", 20000, "DNP3 link"),
    ("bacnet", 47808, "BACnet Who-Is UDP"),
)


def _tcp(host: str, port: int, payload: bytes, timeout: float, udp: bool = False) -> bytes:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    s = socket.socket(socket.AF_INET, kind)
    s.settimeout(timeout)
    try:
        if udp:
            s.sendto(payload, (host, port))
            data, _ = s.recvfrom(2048)
            return data
        s.connect((host, port))
        if payload:
            s.sendall(payload)
        return s.recv(1024)
    finally:
        s.close()


def probe_modbus(host: str, timeout: float) -> dict:
    # MBAP + 0x2B MEI Read Device Identification
    body = bytes.fromhex("00010000000501012b0e0100")
    try:
        data = _tcp(host, 502, body, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    return {
        "ok": bool(data),
        "proto": len(data) >= 8 and data[7] in (0x2B, 0xAB),
        "snip": data[:80].hex(),
    }


def probe_s7(host: str, timeout: float) -> dict:
    cotp = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
    try:
        data = _tcp(host, 102, cotp, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    return {"ok": bool(data), "proto": data[:1] == b"\x03", "snip": data[:40].hex()}


def probe_enip(host: str, timeout: float) -> dict:
    # ListIdentity (0x0063)
    pkt = struct.pack("<HHIIQH", 0x0063, 0, 0, 0, 0, 0)
    try:
        data = _tcp(host, 44818, pkt, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    return {"ok": bool(data), "proto": len(data) >= 2 and data[:2] == b"\x63\x00", "snip": data[:40].hex()}


def probe_dnp3(host: str, timeout: float) -> dict:
    # DNP3 data-link reset (start 05 64)
    pkt = bytes.fromhex("056405c0000000")
    try:
        data = _tcp(host, 20000, pkt, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    return {"ok": bool(data), "proto": data[:2] == b"\x05\x64", "snip": data[:40].hex()}


def probe_bacnet(host: str, timeout: float) -> dict:
    # BVLC original-broadcast-npdu + Who-Is
    pkt = bytes.fromhex("810b000801000800")
    try:
        data = _tcp(host, 47808, pkt, timeout, udp=True)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    return {"ok": bool(data), "proto": data[:1] == b"\x81", "snip": data[:40].hex()}


PROBERS = {
    "modbus": probe_modbus,
    "s7": probe_s7,
    "enip": probe_enip,
    "dnp3": probe_dnp3,
    "bacnet": probe_bacnet,
}


def classify(rows: dict[str, dict]) -> str:
    if any(r.get("proto") for r in rows.values()):
        return "L2"
    if any(r.get("ok") for r in rows.values()):
        return "L1"
    return "none"


def main() -> int:
    ap = argparse.ArgumentParser(description="授权 OT/ICS 只读指纹")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--host", default="")
    ap.add_argument("--only", default="", help="逗号分隔：modbus,s7,enip,dnp3,bacnet")
    ap.add_argument("--timeout", type=float, default=2.5)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"families": [list(x) for x in FAMILIES]}, ensure_ascii=False, indent=2))
        return 0
    host = host_of(args.host) or args.host
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.host}", file=sys.stderr)
        return 2
    want = {x.strip() for x in args.only.split(",") if x.strip()} or set(PROBERS)
    rows = {}
    for name, fn in PROBERS.items():
        if name in want:
            rows[name] = fn(host, args.timeout)
    level = classify(rows)
    rec = {
        "skill": "ot-ics",
        "host": host,
        "rows": rows,
        "level": level,
        "note": "L2=协议魔数；禁止写线圈",
        "ts": datetime.now(UTC).isoformat(),
    }
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="ot_ics", filename="surface.json")
    print(json.dumps({"level": level, "out": str(out), "hit": [k for k, v in rows.items() if v.get("proto")]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
