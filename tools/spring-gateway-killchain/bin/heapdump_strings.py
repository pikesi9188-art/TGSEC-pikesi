#!/usr/bin/env python3
"""Scan hprof / binary dump for high-value keywords (authorized offline analysis)."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_NEEDLES = [
    b"jasypt.encryptor.password",
    b"jasypt.encryptor",
    b"spring.redis.password",
    b"spring.datasource",
    b"jdbc:mysql",
    b"jdbc:postgresql",
    b"ENC(",
    b"nacos",
    b"Nacos",
    b"secret-key",
    b"accessKey",
    b"secretKey",
    b"Authorization",
    b"Bearer ",
    b"BEGIN PRIVATE KEY",
    b"BEGIN DSA PRIVATE",
    b"BEGIN RSA PRIVATE",
    b"security.dsa.privateKey",
    b"security.rsa.privateKey",
    b"password=",
    b"PASSWORD",
    b"redis://",
    b"amqp://",
    b"mongodb://",
    b"DataSourceProperties",
    b"DruidDataSourceWrapper",
    b"CookieRememberMeManager",
    b"encryptionCipherKey",
    b"RedisStandaloneConfiguration",
    b"ProcessEnvironment",
    b"OriginTrackedMapPropertySource",
    b"ConsulPropertySource",
    b"password.thePassword",
    b"Cookie:",
]

ENC_RE = re.compile(rb"ENC\([A-Za-z0-9+/=]{8,}\)")
PRINTABLE = re.compile(rb"[\x20-\x7e]{8,}")


def extract_around(blob: bytes, idx: int, radius: int = 120) -> str:
    a = max(0, idx - radius)
    b = min(len(blob), idx + radius)
    chunk = blob[a:b]
    return "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hprof", help="path to .hprof or dump sample")
    ap.add_argument("--out", default="", help="write hits to file")
    ap.add_argument("--max-hits", type=int, default=200)
    ap.add_argument("--chunk-mb", type=int, default=64, help="read chunk size MB")
    args = ap.parse_args()
    path = Path(args.hprof)
    if not path.is_file():
        raise SystemExit(f"missing {path}")

    chunk = args.chunk_mb * 1024 * 1024
    hits: list[str] = []
    encs: set[str] = set()
    offset = 0
    with path.open("rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            # overlap window for cross-chunk matches
            window = data
            for needle in DEFAULT_NEEDLES:
                start = 0
                while True:
                    i = window.find(needle, start)
                    if i < 0:
                        break
                    hits.append(f"@{offset+i} needle={needle.decode('latin1')} :: {extract_around(window, i)}")
                    start = i + 1
                    if len(hits) >= args.max_hits:
                        break
                if len(hits) >= args.max_hits:
                    break
            for m in ENC_RE.finditer(window):
                encs.add(m.group().decode("ascii", "replace"))
            offset += len(data)
            if len(hits) >= args.max_hits:
                break
            # progress
            if offset % (chunk * 4) == 0:
                print(f"[*] scanned {offset/1024/1024:.1f} MB hits={len(hits)} enc={len(encs)}", file=sys.stderr)

    lines = hits + [f"ENC_CANDIDATE {e}" for e in sorted(encs)]
    text = "\n".join(lines) + ("\n" if lines else "")
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"[=] wrote {args.out} lines={len(lines)}")
    else:
        sys.stdout.write(text)
    print(f"[=] hits={len(hits)} unique_ENC={len(encs)}", file=sys.stderr)


if __name__ == "__main__":
    main()
