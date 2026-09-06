#!/usr/bin/env python3
"""授权 SIP/VoIP 面：OPTIONS 指纹。禁止 INVITE 轰炸。

  python3 炼蛊房/sip_surface_probe.py drive --host <IP> --case <案>
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


def sip_options(host: str, port: int = 5060, timeout: float = 3.0) -> dict:
    body = (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-se\r\n"
        f"From: <sip:se@{host}>;tag=se\r\n"
        f"To: <sip:se@{host}>\r\n"
        f"Call-ID: se@127.0.0.1\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(body, (host, port))
        data, _ = s.recvfrom(2048)
    except OSError as exc:
        return {"ok": False, "err": str(exc)[:80]}
    finally:
        s.close()
    text = data.decode("latin-1", "replace")
    return {"ok": True, "snip": text[:400], "sip": text.startswith("SIP/2.0")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("drive",))
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5060)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    host = host_of(args.host) or args.host
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.host}", file=sys.stderr)
        raise SystemExit(2)
    row = sip_options(host, args.port)
    level = "L2" if row.get("sip") else ("L1" if row.get("ok") else "none")
    rec = {"host": host, "port": args.port, "row": row, "level": level, "ts": datetime.now(UTC).isoformat(), "skill": "话音面"}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="sip", filename="surface.json")
    print(json.dumps({"level": level, "out": str(out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
