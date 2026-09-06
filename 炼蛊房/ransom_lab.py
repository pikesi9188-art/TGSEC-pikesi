#!/usr/bin/env python3
"""授权案卷内勒索演练：只加密 case 目录 inbox，钥落盘，可解密。

禁止对 / /etc / 用户家目录动手。不是对外发放的勒索构建器。

  python3 炼蛊房/ransom_lab.py init --case <案>
  python3 炼蛊房/ransom_lab.py encrypt --case <案>
  python3 炼蛊房/ransom_lab.py decrypt --case <案>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import evidence_root, safe_case_name  # noqa: E402

SKIP_NAMES = {"SE_RANSOM_LAB.txt", "key.json", "decrypt.sh", "NOTE.txt"}


def lab_root(case: str) -> Path:
    case = safe_case_name(case)
    if not case:
        raise SystemExit("[!] --case 必须是案卷名")
    root = evidence_root() / case / "测绘" / "ransom_lab"
    ev = evidence_root().resolve()
    try:
        root.resolve().relative_to(ev)
    except ValueError:
        raise SystemExit("[!] 拒绝离开案卷根")
    return root


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _stream(key: bytes, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out.extend(hashlib.sha256(key + i.to_bytes(8, "big")).digest())
        i += 1
    return bytes(out[:n])


def xor_bytes(data: bytes, key: bytes) -> bytes:
    ks = _stream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def cmd_init(args: argparse.Namespace) -> int:
    root = lab_root(args.case)
    inbox = root / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    marker = inbox / "SE_RANSOM_LAB.txt"
    if not marker.exists():
        marker.write_text("大爱仙尊授权勒索演练标记，只许待在本目录。\n", encoding="utf-8")
    key_path = root / "key.json"
    if not key_path.exists():
        key_path.write_text(
            json.dumps({"key_hex": secrets.token_hex(32), "ts": datetime.now(UTC).isoformat()}, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps({"inbox": str(inbox), "key": str(key_path)}, ensure_ascii=False))
    return 0


def _load_key(root: Path) -> bytes:
    path = root / "key.json"
    if not path.is_file():
        raise SystemExit("[!] 没有 key.json，先 init")
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
        return bytes.fromhex(rec["key_hex"])
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        raise SystemExit(f"[!] key.json 坏了: {exc}") from exc


def cmd_encrypt(args: argparse.Namespace) -> int:
    root = lab_root(args.case)
    inbox = root / "inbox"
    if not inbox.is_dir():
        print("[!] 先 init", file=sys.stderr)
        return 2
    key = _load_key(root)
    done = []
    targets = [p for p in inbox.rglob("*") if p.is_file()]
    for p in targets:
        if p.name.endswith(".seenc") or p.name in SKIP_NAMES:
            continue
        if not _inside(p, inbox):
            continue
        dest = p.with_name(p.name + ".seenc")
        if dest.exists():
            print(f"[!] 跳过已存在 {dest.name}", file=sys.stderr)
            continue
        dest.write_bytes(xor_bytes(p.read_bytes(), key))
        p.unlink()
        done.append(dest.name)
    note = root / "NOTE.txt"
    note.write_text(
        "授权恢复演练。钥在 key.json。解密：ransom_lab.py decrypt --case <案>。\n",
        encoding="utf-8",
    )
    dec = root / "decrypt.sh"
    repo = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
    dec.write_text(
        f"#!/bin/sh\nexec python3 '{repo / 'tools' / 'ops' / 'ransom_lab.py'}' decrypt --case '{args.case}'\n",
        encoding="utf-8",
    )
    os.chmod(dec, 0o755)
    print(json.dumps({"n": len(done), "files": done, "decryptor": str(dec)}, ensure_ascii=False))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    root = lab_root(args.case)
    inbox = root / "inbox"
    if not inbox.is_dir():
        print("[!] 没有 inbox，先 init / encrypt", file=sys.stderr)
        return 2
    key = _load_key(root)
    done = []
    targets = [p for p in inbox.rglob("*.seenc") if p.is_file()]
    for p in targets:
        if not _inside(p, inbox):
            continue
        dest = p.with_name(p.name[: -len(".seenc")])
        if dest.exists():
            print(f"[!] 跳过已存在 {dest.name}", file=sys.stderr)
            continue
        dest.write_bytes(xor_bytes(p.read_bytes(), key))
        p.unlink()
        done.append(dest.name)
    print(json.dumps({"n": len(done), "files": done}, ensure_ascii=False))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="授权案卷勒索演练")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "encrypt", "decrypt"):
        p = sub.add_parser(name)
        p.add_argument("--case", required=True)
    args = ap.parse_args()
    if os.geteuid() == 0 and args.cmd == "encrypt":
        print("[!] 拒绝 root 加密，防止扫到系统盘", file=sys.stderr)
        raise SystemExit(2)
    if args.cmd == "init":
        raise SystemExit(cmd_init(args))
    if args.cmd == "encrypt":
        raise SystemExit(cmd_encrypt(args))
    raise SystemExit(cmd_decrypt(args))


if __name__ == "__main__":
    main()
