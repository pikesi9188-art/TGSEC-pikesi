#!/usr/bin/env python3
"""授权打印机：9100 PJL / 631 IPP 面。

  python3 炼蛊房/printer_pjl_probe.py drive --host <IP> --case <案>
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

PJL = b"\x1b%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n\x1b%-12345X"


def pjl_info(host: str, port: int = 9100, timeout: float = 3.0) -> dict:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(PJL)
        data = b""
        while len(data) < 4096:
            try:
                chunk = s.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    finally:
        s.close()
    text = data.decode("latin-1", "replace")
    return {"ok": bool(data), "size": len(data), "snip": text[:300], "has_pjl": "@PJL" in text or "READY" in text.upper()}


def ipp_probe(host: str, port: int = 631, timeout: float = 3.0) -> dict:
    req = (
        b"GET /ipp/print HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode()
    )
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(req)
        data = s.recv(800)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    finally:
        s.close()
    return {"ok": bool(data), "snip": data[:200].decode("latin-1", "replace")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("drive",))
    ap.add_argument("--host", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    host = host_of(args.host) or args.host
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.host}", file=sys.stderr)
        raise SystemExit(2)
    pjl = pjl_info(host)
    ipp = ipp_probe(host)
    level = "L2" if pjl.get("has_pjl") else ("L1" if pjl.get("ok") or ipp.get("ok") else "none")
    rec = {"host": host, "pjl": pjl, "ipp": ipp, "level": level, "ts": datetime.now(UTC).isoformat(), "skill": "印机面"}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="printer", filename="surface.json")
    print(json.dumps({"level": level, "out": str(out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
