#!/usr/bin/env python3
"""授权无线面：离线 beacon 解析 + 本机接口盘点。不发 deauth，不跑握手爆破。

  python3 炼蛊房/wireless_surface_probe.py list
  python3 炼蛊房/wireless_surface_probe.py doctor
  python3 炼蛊房/wireless_surface_probe.py pcap --path 抓包.pcap --case <案>
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


def parse_beacons(pcap: bytes, limit: int = 40) -> list[dict]:
    if pcap[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return []
    swapped = pcap[:4] == b"\xa1\xb2\xc3\xd4"
    endian = ">" if swapped else "<"
    off = 24
    found: list[dict] = []
    seen: set[str] = set()
    while off + 16 <= len(pcap) and len(found) < limit:
        ts_sec, ts_usec, incl, orig = struct.unpack_from(endian + "IIII", pcap, off)
        off += 16
        rec = pcap[off : off + incl]
        off += incl
        if len(rec) < 24:
            continue
        # 尽力跳过 radiotap
        body = rec
        if rec[:2] == b"\x00\x00" and len(rec) >= 4:
            rt_len = struct.unpack_from("<H", rec, 2)[0]
            if 8 <= rt_len < len(rec):
                body = rec[rt_len:]
        if len(body) < 36:
            continue
        fctl = struct.unpack_from("<H", body, 0)[0]
        if (fctl & 0xFC) != 0x80:  # beacon
            continue
        bssid = body[16:22].hex(":")
        tagged = body[36:]
        ssid = ""
        wps = False
        privacy = bool(body[34] & 0x10) if len(body) > 34 else False
        i = 0
        while i + 2 <= len(tagged):
            tag, tlen = tagged[i], tagged[i + 1]
            val = tagged[i + 2 : i + 2 + tlen]
            i += 2 + tlen
            if tag == 0:
                ssid = val.decode("utf-8", "replace")
            if tag == 221 and val[:4] == bytes.fromhex("0050f204"):
                wps = True
        key = f"{bssid}|{ssid}"
        if key in seen:
            continue
        seen.add(key)
        found.append({"bssid": bssid, "ssid": ssid, "privacy": privacy, "wps": wps})
    return found


def doctor() -> dict:
    bins = {n: bool(shutil.which(n)) for n in ("iw", "iwconfig", "airport", "tcpdump", "tshark")}
    return {"bins": bins, "hint": "离线走 pcap；本机抓包先问授权信道"}


def main() -> int:
    ap = argparse.ArgumentParser(description="授权无线面（离线 beacon）")
    ap.add_argument("cmd", choices=("list", "doctor", "pcap"))
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"cmds": ["doctor", "pcap"], "note": "不发 deauth"}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "doctor":
        rec = {"skill": "wifi-wireless", **doctor(), "level": "L1", "ts": datetime.now(UTC).isoformat()}
        print(json.dumps(rec, ensure_ascii=False, indent=2))
        return 0
    p = Path(args.path)
    if not p.is_file():
        print("[!] --path 抓包不存在", file=sys.stderr)
        return 2
    aps = parse_beacons(p.read_bytes())
    level = "L2" if aps else "none"
    rec = {
        "skill": "wifi-wireless",
        "path": str(p),
        "aps": aps,
        "level": level,
        "note": "L2=解析到 beacon；不破解握手",
        "ts": datetime.now(UTC).isoformat(),
    }
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="wireless", filename="beacons.json")
    print(json.dumps({"level": level, "aps": len(aps), "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
