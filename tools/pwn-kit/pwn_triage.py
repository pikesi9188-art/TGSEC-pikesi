#!/usr/bin/env python3
"""二进制初筛：file/字符串/保护位/ROP gadget 摘要（包装 arsenal）。

示例:
  python3 tools/pwn-kit/pwn_triage.py doctor
  python3 tools/pwn-kit/pwn_triage.py triage --bin ./vuln --case <案卷>
  python3 tools/pwn-kit/pwn_triage.py gadgets --bin ./vuln --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

def _kit_ops_dir(start: Path) -> Path:
    here = start.resolve()
    if here.is_file():
        here = here.parent
    for p in (here, *here.parents):
        fang = p / "炼蛊房"
        if (fang / "scope_lib.py").is_file():
            return fang
        ops = p / "tools" / "ops"
        if (ops / "scope_lib.py").is_file():
            return ops
    return here

ENGINE = Path(__file__).resolve().parents[2]
ARSENAL_BIN = ENGINE / "tools" / "arsenal" / "bin"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "pwn"
    d.mkdir(parents=True, exist_ok=True)
    return d


def tool(name: str) -> str | None:
    for p in (ARSENAL_BIN / name, Path(shutil.which(name) or "")):
        if p and Path(p).is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def cmd_doctor(_: argparse.Namespace) -> int:
    names = ("file", "strings", "readelf", "objdump", "gdb", "ROPgadget", "checksec")
    miss = []
    for n in names:
        p = tool(n)
        print(f"[{'ok' if p else 'missing'}] {n}: {p or '-'}")
        if not p and n in ("file", "strings", "objdump"):
            miss.append(n)
    try:
        import pwn  # noqa: F401

        print("[ok] pwntools")
    except ImportError:
        print("[missing] pwntools — pip install 'pwntools==4.15.0'")
        miss.append("pwntools")
    print("[ok] pwn-kit ready" if not miss else "[warn] 基础工具有缺，可 source scripts/arsenal-env.sh")
    return 0 if not miss else 1


def is_macho(file_out: str) -> bool:
    return "mach-o" in file_out.lower()


def parse_protections(readelf_out: str, file_out: str) -> dict:
    prot = {
        "nx": "unknown",
        "pie": "unknown",
        "relro": "unknown",
        "canary": "unknown",
        "arch": "unknown",
        "format": "unknown",
    }
    file_low = file_out.lower()
    readelf_low = readelf_out.lower()

    # --- 格式 ---
    if is_macho(file_out):
        prot["format"] = "macho"
        # Mach-O 保护位由系统/codesign 控制，readelf 无效
        prot["pie"] = "n/a (mach-o)"
        prot["nx"] = "n/a (mach-o)"
        prot["relro"] = "n/a (mach-o)"
    elif "elf" in file_low:
        prot["format"] = "elf"
    elif "pe32" in file_low or "pe64" in file_low:
        prot["format"] = "pe"

    # --- 架构 ---
    combined_low = file_low + "\n" + readelf_low
    if "x86-64" in combined_low or "x86_64" in combined_low:
        prot["arch"] = "amd64"
    elif "aarch64" in combined_low or "arm64" in combined_low:
        prot["arch"] = "arm64"
    elif "i386" in combined_low or "x86-32" in combined_low:
        prot["arch"] = "i386"
    elif "mips" in combined_low:
        prot["arch"] = "mips"

    if prot["format"] != "elf":
        # canary 字符串检测对所有格式均可尝试
        if "__stack_chk_fail" in readelf_out or "stack_chk" in combined_low:
            prot["canary"] = "enabled"
        return prot

    # --- ELF 专用保护位检测 ---
    # PIE: ELF shared object (LSB/MSB shared object) 表示 PIE；plain executable 表示无 PIE
    if "lsb shared object" in file_low or "msb shared object" in file_low or "pie executable" in file_low:
        prot["pie"] = "enabled"
    elif "executable" in file_low:
        prot["pie"] = "disabled"

    # NX: readelf -l 中 GNU_STACK flags RW（无 E）= NX 启用；RWE = 禁用
    if "gnu_stack" in readelf_low:
        after = readelf_low.split("gnu_stack")[-1][:120]
        # flags 列顺序：R E W 或出现 rwe/rw
        prot["nx"] = "disabled" if "rwe" in after or " rwx" in after else "enabled"

    # Canary
    if "__stack_chk_fail" in readelf_out or "stack_chk" in combined_low:
        prot["canary"] = "enabled"

    # RELRO
    if "gnu_relro" in readelf_low:
        prot["relro"] = "full" if "bind_now" in readelf_low else "partial"

    return prot


def interesting_strings(text: str, limit: int = 40) -> list[str]:
    keys = (
        "flag",
        "passwd",
        "password",
        "secret",
        "/bin/sh",
        "system",
        "execve",
        "gets",
        "strcpy",
        "scanf",
        "printf",
        "mmap",
        "mprotect",
        "win",
        "backdoor",
    )
    hits: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if len(s) < 4 or len(s) > 200:
            continue
        low = s.lower()
        if any(k in low for k in keys):
            hits.append(s)
        if len(hits) >= limit:
            break
    return hits


def cmd_triage(args: argparse.Namespace) -> int:
    path = Path(args.bin).expanduser().resolve()
    if not path.is_file():
        raise SystemExit(f"[err] 不存在: {path}")
    file_bin = tool("file") or "file"
    strings_bin = tool("strings") or "strings"
    readelf_bin = tool("readelf")
    _, file_out = run([file_bin, str(path)])
    _, str_out = run([strings_bin, "-n", "6", str(path)], timeout=120)
    readelf_out = ""
    if readelf_bin:
        _, readelf_out = run([readelf_bin, "-lW", str(path)])
        _, dyn = run([readelf_bin, "-dW", str(path)])
        readelf_out += "\n" + dyn
        _, sym = run([readelf_bin, "-sW", str(path)])
        if "stack_chk" in sym:
            readelf_out += "\n__stack_chk_fail"
    prot = parse_protections(readelf_out, file_out)
    result = {
        "ts": _now(),
        "bin": str(path),
        "file": file_out.strip(),
        "protections": prot,
        "interesting_strings": interesting_strings(str_out),
        "next": [],
    }
    fmt = prot.get("format", "unknown")
    if fmt == "macho":
        result["next"].append("Mach-O（macOS）→ 分析前传到 Linux 环境或用 otool/gdb 本地调试")
    else:
        if prot.get("canary") not in ("enabled",):
            result["next"].append("无/未知 canary → 可尝试栈溢出")
        if prot.get("nx") == "disabled":
            result["next"].append("NX off → shellcode 可行")
        elif prot.get("nx") == "enabled":
            result["next"].append("NX on → ret2libc / ROP")
        # nx unknown 时不做假设
        if prot.get("pie") == "enabled":
            result["next"].append("PIE → 先泄露基址再 ROP")
        elif prot.get("pie") == "disabled":
            result["next"].append("PIE off → 固定地址 ROP / ret2libc")
    if any("/bin/sh" in s or "system" in s.lower() for s in result["interesting_strings"]):
        result["next"].append("命中 system/sh 字符串 → 查 GOT/PLT")
    result["next"].append("业务链若为 Node/.node/BPP → 切 bpp-node-exploit-chain")
    if args.case:
        out = case_dir(args.case) / f"triage_{path.name}.json"
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (case_dir(args.case) / f"strings_{path.name}.txt").write_text(str_out[:200000], encoding="utf-8")
        result["evidence"] = str(out)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_gadgets(args: argparse.Namespace) -> int:
    path = Path(args.bin).expanduser().resolve()
    rop = tool("ROPgadget")
    if not rop:
        raise SystemExit("[err] 无 ROPgadget；pip install ROPgadget==7.7 或装 arsenal")
    cmd = [rop, "--binary", str(path)]
    if args.only:
        cmd += ["--only", args.only]
    rc, out = run(cmd, timeout=180)
    # 摘要：保留 pop rdi / system / syscall 等
    keep_re = re.compile(r"(pop rdi|pop rsi|pop rdx|pop rax|syscall|: ret$|xchg rax)", re.I)
    lines = [ln for ln in out.splitlines() if keep_re.search(ln)]
    summary = {
        "ts": _now(),
        "bin": str(path),
        "rc": rc,
        "gadget_hits": lines[:80],
        "total_lines": len(out.splitlines()),
    }
    if args.case:
        outp = case_dir(args.case) / f"gadgets_{path.name}.json"
        outp.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (case_dir(args.case) / f"gadgets_{path.name}.txt").write_text(out[:500000], encoding="utf-8")
        summary["evidence"] = str(outp)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if rc == 0 else rc


def main() -> int:
    p = argparse.ArgumentParser(description="二进制 Pwn 初筛")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    t = sub.add_parser("triage")
    t.add_argument("--bin", required=True)
    t.add_argument("--case")
    t.set_defaults(func=cmd_triage)

    g = sub.add_parser("gadgets")
    g.add_argument("--bin", required=True)
    g.add_argument("--case")
    g.add_argument("--only", default="pop|ret|syscall")
    g.set_defaults(func=cmd_gadgets)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
