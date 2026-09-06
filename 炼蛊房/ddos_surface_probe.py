#!/usr/bin/env python3
"""授权可用性面：反射器指纹 + 限速小流量。禁止 SYN/DNS 放大发送。

  python3 炼蛊房/ddos_surface_probe.py amp --host <授权IP> --case <案>
  python3 炼蛊房/ddos_surface_probe.py load --url https://授权站/ --n 10 --rps 2 --case <案>
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    requests = None  # type: ignore

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

MAX_N = 30
MAX_RPS = 5


def _need(host: str) -> str:
    h = host_of(host) or host
    if not h or not in_scope(h):
        print(f"[!] 不在 scope：{h}", file=sys.stderr)
        sys.exit(2)
    return h


def udp_probe(host: str, port: int, payload: bytes, timeout: float = 1.2) -> dict:
    fam = socket.AF_INET6 if ":" in host and "." not in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(512)
        return {"port": port, "ok": True, "n": len(data)}
    except OSError as exc:
        return {"port": port, "ok": False, "err": str(exc)[:60]}
    finally:
        s.close()


def cmd_amp(args: argparse.Namespace) -> int:
    host = _need(args.host)
    rows = [
        udp_probe(host, 53, b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"),
        udp_probe(host, 123, b"\x1b" + b"\x00" * 47),
        udp_probe(host, 19, b"x"),
    ]
    openish = [r for r in rows if r.get("ok")]
    rec = {
        "host": host,
        "rows": rows,
        "level": "L2" if openish else "L1",
        "ts": datetime.now(UTC).isoformat(),
        "skill": "潮面探",
        "note": "只探是否像反射器。禁止用它打别人。",
    }
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="ddos", filename="amp.json")
    print(json.dumps({"level": rec["level"], "open": [r["port"] for r in openish], "out": str(out)}, ensure_ascii=False))
    return 0


def cmd_load(args: argparse.Namespace) -> int:
    if requests is None:
        print("[!] pip install requests", file=sys.stderr)
        return 2
    host = _need(args.url)
    n = min(max(int(args.n), 1), MAX_N)
    rps = min(max(float(args.rps), 0.2), MAX_RPS)
    codes = []
    for _ in range(n):
        try:
            r = requests.get(args.url, timeout=8, verify=False)
            codes.append(r.status_code)
        except Exception:
            codes.append(0)
        time.sleep(1.0 / rps)
    rec = {
        "url": args.url,
        "host": host,
        "n": n,
        "rps": rps,
        "codes": codes,
        "level": "L1",
        "ts": datetime.now(UTC).isoformat(),
        "skill": "潮面探",
        "note": f"硬顶 n<={MAX_N} rps<={MAX_RPS}，不是洪水",
    }
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="ddos", filename="load.json")
    print(json.dumps({"n": n, "codes": codes[:8], "out": str(out)}, ensure_ascii=False))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="授权可用性面（非洪水）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("amp")
    a.add_argument("--host", required=True)
    a.add_argument("--case", default="")
    a.add_argument("--out", type=Path, default=None)
    l = sub.add_parser("load")
    l.add_argument("--url", required=True)
    l.add_argument("--n", type=int, default=8)
    l.add_argument("--rps", type=float, default=2)
    l.add_argument("--case", default="")
    l.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "amp":
        raise SystemExit(cmd_amp(args))
    raise SystemExit(cmd_load(args))


if __name__ == "__main__":
    main()
