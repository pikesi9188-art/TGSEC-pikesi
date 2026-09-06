#!/usr/bin/env python3
"""哈希族识别（授权样本/库转储）。不是爆破。

  python3 炼蛊房/hash_identify.py --hash '$2a$10$...' 
  python3 炼蛊房/hash_identify.py --path hashes.txt --case <案>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}$")),
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")),
    ("md5_crypt", re.compile(r"^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$")),
    ("sha256_crypt", re.compile(r"^\$5\$")),
    ("sha512_crypt", re.compile(r"^\$6\$")),
    ("argon2", re.compile(r"^\$argon2")),
    ("php_md5", re.compile(r"^\$P\$")),
    ("ntlm_hex", re.compile(r"^[A-Fa-f0-9]{32}$")),
    ("sha1_hex", re.compile(r"^[A-Fa-f0-9]{40}$")),
    ("sha256_hex", re.compile(r"^[A-Fa-f0-9]{64}$")),
    ("sha512_hex", re.compile(r"^[A-Fa-f0-9]{128}$")),
]


def identify(h: str) -> list[str]:
    h = (h or "").strip()
    return [name for name, rx in RULES if rx.search(h)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hash", default="")
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    args = ap.parse_args()
    items = []
    def _clip(s: str) -> str:
        return s if len(s) <= 24 else s[:24] + "…"

    if args.hash:
        items.append({"hash": _clip(args.hash), "kinds": identify(args.hash)})
    if args.path:
        p = Path(args.path)
        if not p.is_file():
            print(f"[!] 没有文件: {p}", file=sys.stderr)
            return 2
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                items.append({"hash": _clip(line), "kinds": identify(line)})
    rec = {"n": len(items), "items": items[:50], "skill": "认纹"}
    if args.case:
        write_probe_json(rec, case=args.case, case_subdir="hash_id", filename="surface.json")
    print(json.dumps(rec, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
