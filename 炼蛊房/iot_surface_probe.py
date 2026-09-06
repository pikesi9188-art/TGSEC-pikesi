#!/usr/bin/env python3
"""授权杂器面：MQTT / SSDP / CoAP / RTSP 只读指纹。

  python3 炼蛊房/iot_surface_probe.py list
  python3 炼蛊房/iot_surface_probe.py drive --host <IP> --case <案>
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402


def _tcp(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if payload:
            s.sendall(payload)
        return s.recv(800)
    finally:
        s.close()


def _udp(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(1200)
        return data
    finally:
        s.close()


def mqtt(host: str, timeout: float) -> dict:
    # CONNECT, proto MQTT, keepalive 10, client se
    pkt = bytes.fromhex("101000044d5154540402000a00027365")
    try:
        data = _tcp(host, 1883, pkt, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    return {"ok": bool(data), "proto": len(data) >= 2 and data[0] == 0x20, "snip": data[:20].hex()}


def ssdp(host: str, timeout: float) -> dict:
    req = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
    ).encode()
    try:
        data = _udp(host, 1900, req, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    text = data.decode("latin-1", "replace")
    return {"ok": bool(data), "proto": "HTTP/1.1" in text and "LOCATION" in text.upper(), "snip": text[:200]}


def coap(host: str, timeout: float) -> dict:
    # GET /.well-known/core  CON GET mid=0x1234
    pkt = bytes.fromhex("40011234bb2e77656c6c2d6b6e6f776e04636f7265")
    try:
        data = _udp(host, 5683, pkt, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    return {"ok": bool(data), "proto": len(data) >= 1 and (data[0] >> 6) == 1, "snip": data[:40].hex()}


def rtsp(host: str, timeout: float) -> dict:
    req = f"OPTIONS rtsp://{host}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
    try:
        data = _tcp(host, 554, req, timeout)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    text = data.decode("latin-1", "replace")
    return {"ok": bool(data), "proto": text.startswith("RTSP/1.0"), "snip": text[:160]}


def main() -> int:
    ap = argparse.ArgumentParser(description="授权 IoT 只读指纹")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--host", default="")
    ap.add_argument("--timeout", type=float, default=2.5)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"families": ["mqtt:1883", "ssdp:1900", "coap:5683", "rtsp:554"]}, ensure_ascii=False, indent=2))
        return 0
    host = host_of(args.host) or args.host
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.host}", file=sys.stderr)
        return 2
    rows = {
        "mqtt": mqtt(host, args.timeout),
        "ssdp": ssdp(host, args.timeout),
        "coap": coap(host, args.timeout),
        "rtsp": rtsp(host, args.timeout),
    }
    level = "L2" if any(r.get("proto") for r in rows.values()) else ("L1" if any(r.get("ok") for r in rows.values()) else "none")
    rec = {"skill": "iot-security-testing", "host": host, "rows": rows, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="iot", filename="surface.json")
    print(json.dumps({"level": level, "hit": [k for k, v in rows.items() if v.get("proto")], "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
