#!/usr/bin/env python3
"""授权白凝冰 / 器核面：IPA·固件·WebKit·IOKit 认形。不依赖 ios-research 柜。

  python3 炼蛊房/ios_surface_probe.py list
  python3 炼蛊房/ios_surface_probe.py ipa --path 包.ipa --case <案>
  python3 炼蛊房/ios_surface_probe.py fw --path 固件.img4 --case <案>
  python3 炼蛊房/ios_surface_probe.py webkit --path Payload/App.app --case <案>
  python3 炼蛊房/ios_surface_probe.py iokit --path 二进制 --case <案>
  python3 炼蛊房/ios_surface_probe.py lab --path aks_oob.log --case <案>
"""
from __future__ import annotations

import argparse
import json
import plistlib
import re
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402

WK_RX = re.compile(rb"(WKWebView|JSContext|JavaScriptCore|webkit.messageHandlers|evaluateJavaScript)")
IO_RX = re.compile(rb"(IOUserClient|IOService|IOConnectCall|AppleKeyStore|IOSurface|AGXAccelerator)")
def _plist_from_zip(zf: zipfile.ZipFile) -> dict:
    names = zf.namelist()
    cand = [n for n in names if n.endswith(".app/Info.plist")]
    if not cand:
        return {}
    raw = zf.read(cand[0])
    try:
        return plistlib.loads(raw)
    except Exception:
        return {}


def scan_ipa(path: Path) -> dict:
    if not zipfile.is_zipfile(path):
        return {"ipa": False}
    with zipfile.ZipFile(path) as zf:
        info = _plist_from_zip(zf)
        blob = b""
        for n in zf.namelist():
            if "/MacOS/" in n or n.endswith(".dylib"):
                try:
                    blob += zf.read(n)[: 64 * 1024]
                except Exception:
                    pass
                if len(blob) > 512 * 1024:
                    break
    ats = info.get("NSAppTransportSecurity") or {}
    schemes = []
    for item in info.get("CFBundleURLTypes") or []:
        schemes.extend(item.get("CFBundleURLSchemes") or [])
    return {
        "ipa": True,
        "bundle": info.get("CFBundleIdentifier", ""),
        "ats_arbitrary": bool(ats.get("NSAllowsArbitraryLoads")),
        "schemes": schemes[:20],
        "entitlements_hint": bool(info.get("UIBackgroundModes")),
        "webkit": bool(WK_RX.search(blob)),
        "iokit": bool(IO_RX.search(blob)),
    }


def scan_fw(raw: bytes) -> dict:
    kinds = []
    if b"IMG4" in raw[:64] or raw[4:8] == b"IMG4":
        kinds.append("img4")
    if b"IM4P" in raw[:64] or raw[4:8] == b"IM4P":
        kinds.append("im4p")
    if b"iBoot" in raw[: 64 * 1024]:
        kinds.append("iboot")
    return {"kinds": kinds, "size": len(raw)}


def scan_bytes(raw: bytes, rx: re.Pattern[bytes]) -> list[str]:
    return sorted({m.group(0).decode("ascii") for m in rx.finditer(raw[: 1024 * 512])})[:30]


def scan_lab(text: str) -> dict:
    build = re.search(r"\b(\d{2}[A-Z]\d{2,3}[a-z]?)\b", text)
    slide = "kaslr" in text.lower() or "slide" in text.lower()
    aks = "applekeystore" in text.lower() or "aks" in text.lower()
    return {"build": build.group(1) if build else "", "slide_talk": slide, "aks": aks}


def main() -> int:
    ap = argparse.ArgumentParser(description="授权 iOS 应用/固件面")
    ap.add_argument("cmd", choices=("list", "ipa", "fw", "webkit", "iokit", "lab"))
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"cmds": ["ipa", "fw", "webkit", "iokit", "lab"]}, ensure_ascii=False, indent=2))
        return 0
    p = Path(args.path)
    if not p.exists():
        print("[!] --path 不存在", file=sys.stderr)
        return 2
    skill = {
        "ipa": "ios-pentest",
        "fw": "ios-firmware-reverse",
        "webkit": "ios-webkit-hunt",
        "iokit": "iokit-kernel-surface",
        "lab": "ios-kernel-exploitation",
    }[args.cmd]
    if args.cmd == "ipa":
        info = scan_ipa(p)
        level = "L2" if info.get("bundle") or info.get("schemes") or info.get("webkit") else "none"
    elif args.cmd == "fw":
        info = scan_fw(p.read_bytes() if p.is_file() else b"")
        level = "L2" if info.get("kinds") else "none"
    elif args.cmd == "lab":
        info = scan_lab(p.read_text(encoding="utf-8", errors="replace") if p.is_file() else "")
        level = "L2" if info.get("build") or info.get("aks") else "none"
    else:
        raw = b""
        if p.is_file():
            raw = p.read_bytes()[: 1024 * 1024]
        else:
            for f in p.rglob("*"):
                if f.is_file() and f.stat().st_size < 8 * 1024 * 1024:
                    raw += f.read_bytes()[: 64 * 1024]
                if len(raw) > 1024 * 1024:
                    break
        rx = WK_RX if args.cmd == "webkit" else IO_RX
        hits = scan_bytes(raw, rx)
        info = {"hits": hits}
        level = "L2" if hits else "none"
    rec = {"skill": skill, "path": str(p), "cmd": args.cmd, **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="ios", filename=f"{args.cmd}.json")
    print(json.dumps({"level": level, "skill": skill, "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
