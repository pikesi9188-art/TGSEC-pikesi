#!/usr/bin/env python3
"""授权样本：网络验证 / 卡密 / Nuitka·PyInstaller / 天盾·fndata 面。

  python3 炼蛊房/net_license_probe.py drive --path <样本> --case <案>
  python3 炼蛊房/net_license_probe.py format --sample XXXX-XXXX --sample YYYY-YYYY
  python3 炼蛊房/net_license_probe.py xor --plain a.bin --cipher b.bin
  python3 炼蛊房/net_license_probe.py patch-plan --path <PE>
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402

PACKER_SIGS = {
    "UPX": [b"UPX0", b"UPX1", b"UPX!"],
    "Themida": [b"Themida", b"Oreans"],
    "VMProtect": [b".vmp0", b".vmp1", b"VMProtect"],
    "Enigma": [b".enigma1", b"Enigma Protector"],
    "Nuitka": [b"nuitka", b"NUITKA_ONEFILE", b"onefile_progress"],
    "PyInstaller": [b"MEI\x0c\x0b\x0a\x0b\x0e", b"PyInstaller", b"PYZ-00.pyz"],
    "fndata": [b"fndata", b"FNData", b"fn_data"],
    "tiandun": [b"tiandun", b"TianDun", "天盾".encode("utf-8"), b"0xc000041d"],
}

LICENSE_RX = re.compile(
    rb"(checkLicense|verifyKey|validateSerial|isVip|isPremium|isPro|"
    rb"license\.example|activate|auth_server|card[_-]?key)",
    re.I,
)
URL_RX = re.compile(rb"https?://[A-Za-z0-9._:-]{4,80}(?:/[A-Za-z0-9_./?=&%-]{0,80})?")
RSA_HDR = b"-----BEGIN PUBLIC KEY-----"
JE = re.compile(rb"\x74[\x02-\x7f]")  # short JE


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values() if c)


def xor_keystream(plain: bytes, cipher: bytes) -> bytes:
    return bytes(p ^ c for p, c in zip(plain, cipher))


def infer_pattern(sample: str) -> str:
    out = []
    for ch in sample:
        if ch.isalpha():
            out.append("A")
        elif ch.isdigit():
            out.append("N")
        else:
            out.append(ch)
    return "".join(out)


def recover_serial_format(samples: list[str]) -> dict[str, Any]:
    samples = [s.strip() for s in samples if s and s.strip()]
    if not samples:
        return {"ok": False, "reason": "no-samples"}
    seps: set[str] = set()
    charset: set[str] = set()
    for s in samples:
        for ch in s:
            (seps if not ch.isalnum() else charset).add(ch)
    pats = {infer_pattern(s) for s in samples}
    return {
        "ok": True,
        "n": len(samples),
        "lengths": sorted({len(s) for s in samples}),
        "separators": sorted(seps),
        "charset_size": len(charset),
        "patterns": sorted(pats),
        "same_pattern": len(pats) == 1,
    }


def detect_packers(data: bytes) -> list[str]:
    hit = []
    low = data[: min(len(data), 8_000_000)]
    for name, sigs in PACKER_SIGS.items():
        if any(s in low for s in sigs):
            hit.append(name)
    return hit


def extract_urls(data: bytes) -> list[str]:
    urls = []
    for m in URL_RX.finditer(data[:4_000_000]):
        u = m.group().decode("ascii", "replace")
        host = (urlparse(u).hostname or "").lower()
        if any(x in u.lower() or x in host for x in ("licen", "activ", "auth", "verify", "card", "vip", "fndata")):
            urls.append(u)
    return list(dict.fromkeys(urls))[:20]


def license_hits(data: bytes) -> list[str]:
    return sorted({m.group().decode("ascii", "replace") for m in LICENSE_RX.finditer(data[:4_000_000])})[:30]


def je_sites(data: bytes, limit: int = 12) -> list[int]:
    if not data.startswith(b"MZ"):
        return []
    return [m.start() for m in JE.finditer(data[: min(len(data), 2_000_000)])][:limit]


def classify(path: Path, data: bytes) -> dict[str, Any]:
    packers = detect_packers(data)
    urls = extract_urls(data)
    lic = license_hits(data)
    rsa = RSA_HDR in data
    je = je_sites(data)
    kind = "unknown"
    if data[:2] == b"MZ":
        kind = "pe"
    elif data[:4] == b"\x7fELF":
        kind = "elf"
    elif data[:2] == b"PK" and (b"AndroidManifest.xml" in data[:8000] or path.suffix.lower() == ".apk"):
        kind = "apk"
    elif path.suffix.lower() in {".py", ".pyc"}:
        kind = "python"
    rec = {
        "path": str(path),
        "size": len(data),
        "kind": kind,
        "entropy": round(entropy(data[:65536]), 3),
        "packers": packers,
        "license_syms": lic,
        "auth_urls": urls,
        "rsa_pem": rsa,
        "je_off": [hex(x) for x in je],
        "ts": datetime.now(UTC).isoformat(),
    }
    level = "none"
    if packers or lic or urls:
        level = "L1"
    packed_auth = ("Nuitka" in packers or "PyInstaller" in packers) and bool(lic)
    if (urls and (rsa or lic)) or packed_auth:
        level = "L2"
    if urls and (rsa or "fndata" in packers or "tiandun" in packers):
        level = "L2"
    rec["level"] = level
    rec["skill"] = "net-license-crack"
    rec["next"] = "L2=认证 URL+RSA/符号，或 Nuitka/PyInstaller+校验名。假服务器/补丁只打授权样本。改生产超管密先问。"
    return rec


def cmd_drive(args: argparse.Namespace) -> int:
    p = Path(args.path)
    if not p.is_file():
        print("[!] 需要本地授权样本文件", file=sys.stderr)
        return 2
    data = p.read_bytes()
    rec = classify(p, data)
    if args.sample:
        rec["serial"] = recover_serial_format(args.sample)
        if rec["serial"].get("same_pattern"):
            rec["level"] = "L2"
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="net_license", filename="surface.json")
    print(json.dumps({"level": rec["level"], "packers": rec["packers"], "urls": rec["auth_urls"][:4], "out": str(out)}, ensure_ascii=False))
    return 0


def cmd_format(args: argparse.Namespace) -> int:
    print(json.dumps(recover_serial_format(args.sample), ensure_ascii=False, indent=2))
    return 0


def cmd_xor(args: argparse.Namespace) -> int:
    plain = Path(args.plain).read_bytes()
    cipher = Path(args.cipher).read_bytes()
    ks = xor_keystream(plain, cipher)
    print(json.dumps({"keystream_hex": ks.hex()[:128], "n": len(ks)}, ensure_ascii=False))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    body = args.body.encode()

    class H(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            self.do_GET()

        def log_message(self, fmt: str, *a: object) -> None:
            print(fmt % a)

    httpd = ThreadingHTTPServer((args.host, args.port), H)
    print(json.dumps({"listen": f"{args.host}:{args.port}", "note": "只给授权样本 /etc/hosts 指过来"}, ensure_ascii=False))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


def cmd_patch_plan(args: argparse.Namespace) -> int:
    data = Path(args.path).read_bytes()
    rec = {
        "je_to_jmp": "74 XX → EB XX（短跳过校验，授权样本+备份）",
        "sites": [hex(x) for x in je_sites(data, 20)],
        "note": "默认只出计划。--apply 才写盘，必须 --case 且先备份 .bak",
    }
    if args.apply:
        if not args.case:
            print("[!] --apply 必须带 --case", file=sys.stderr)
            return 2
        if not data.startswith(b"MZ") or not rec["sites"]:
            print("[!] 没有可计划的短 JE", file=sys.stderr)
            return 1
        dest = Path(args.path)
        bak = dest.with_suffix(dest.suffix + ".bak")
        if not bak.exists():
            bak.write_bytes(data)
        buf = bytearray(data)
        off = int(rec["sites"][0], 16)
        if buf[off] == 0x74:
            buf[off] = 0xEB
            dest.write_bytes(buf)
            rec["applied"] = hex(off)
            rec["level"] = "L3"
        write_probe_json(rec, case=args.case, case_subdir="net_license", filename="patch.json")
    print(json.dumps(rec, ensure_ascii=False, indent=2))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="授权样本网络验证/卡密面")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("drive")
    d.add_argument("--path", required=True)
    d.add_argument("--sample", action="append", default=[])
    d.add_argument("--case", default="")
    d.add_argument("--out", type=Path, default=None)
    f = sub.add_parser("format")
    f.add_argument("--sample", action="append", required=True)
    x = sub.add_parser("xor")
    x.add_argument("--plain", required=True)
    x.add_argument("--cipher", required=True)
    p = sub.add_parser("patch-plan")
    p.add_argument("--path", required=True)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--case", default="")
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--body", default='{"status":"valid","expires":"2099-12-31","vip":true}')
    args = ap.parse_args()
    if args.cmd == "drive":
        raise SystemExit(cmd_drive(args))
    if args.cmd == "format":
        raise SystemExit(cmd_format(args))
    if args.cmd == "xor":
        raise SystemExit(cmd_xor(args))
    if args.cmd == "serve":
        raise SystemExit(cmd_serve(args))
    raise SystemExit(cmd_patch_plan(args))


if __name__ == "__main__":
    main()
