#!/usr/bin/env python3
"""大爱仙尊编解码入口：禁止靠直觉猜编码。

解码只到 L1；JWT/支付 sign 明文立刻交接对应专卡。
对照过 VulnClaw crypto_tools（MIT），已改成本库 CLI。

  python3 炼蛊房/crypto_decode.py --list
  python3 炼蛊房/crypto_decode.py auto --input 'TnNTY1RmLnBocA=='
  python3 炼蛊房/crypto_decode.py jwt_decode --input '<JWT>'
  python3 炼蛊房/crypto_decode.py aes_decrypt --input '<b64>' --key 16byte-secret!!
"""
from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import hashlib
import hmac
import html
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any
from collections.abc import Callable

_OPS_DIR = Path(__file__).resolve().parent

MORSE_ENC = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
}
MORSE_DEC = {v: k for k, v in MORSE_ENC.items()}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _ok(result: Any) -> dict[str, Any]:
    return {"ok": True, "result": result}


def _err(msg: str) -> dict[str, Any]:
    return {"ok": False, "error": msg}


def _b64pad(s: str, n: int = 4) -> str:
    s = s.strip()
    miss = len(s) % n
    return s + ("=" * (n - miss) if miss else "")


def op_base64_encode(s: str, **_) -> dict[str, Any]:
    return _ok(base64.b64encode(s.encode()).decode("ascii"))


def op_base64_decode(s: str, **_) -> dict[str, Any]:
    cleaned = s.strip()
    kw: dict[str, Any] = {"validate": True}
    if any(c in cleaned for c in "-_"):
        kw["altchars"] = b"-_"
    try:
        return _ok(base64.b64decode(_b64pad(cleaned), **kw).decode("utf-8", "replace"))
    except (ValueError, binascii.Error) as e:
        return _err(f"base64: {e}")


def op_base32_encode(s: str, **_) -> dict[str, Any]:
    return _ok(base64.b32encode(s.encode()).decode("ascii"))


def op_base32_decode(s: str, **_) -> dict[str, Any]:
    try:
        return _ok(base64.b32decode(_b64pad(s.strip().upper(), 8)).decode("utf-8", "replace"))
    except (ValueError, binascii.Error) as e:
        return _err(f"base32: {e}")


def op_base58_encode(s: str, **_) -> dict[str, Any]:
    raw = s.encode()
    num = int.from_bytes(raw, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = B58[rem] + out
    for b in raw:
        if b == 0:
            out = "1" + out
        else:
            break
    return _ok(out or "1")


def op_base58_decode(s: str, **_) -> dict[str, Any]:
    try:
        num = 0
        for ch in s.strip():
            num = num * 58 + B58.index(ch)
        lead = 0
        for ch in s.strip():
            if ch == "1":
                lead += 1
            else:
                break
        raw = (num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b"") + b""
        raw = b"\x00" * lead + raw
        return _ok(raw.decode("utf-8", "replace"))
    except (ValueError, binascii.Error) as e:
        return _err(f"base58: {e}")


def op_hex_encode(s: str, **_) -> dict[str, Any]:
    return _ok(s.encode().hex())


def op_hex_decode(s: str, **_) -> dict[str, Any]:
    cleaned = s.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace(" ", "")
    try:
        return _ok(bytes.fromhex(cleaned).decode("utf-8", "replace"))
    except ValueError as e:
        return _err(f"hex: {e}")


def op_url_encode(s: str, **_) -> dict[str, Any]:
    return _ok(urllib.parse.quote(s, safe=""))


def op_url_decode(s: str, **_) -> dict[str, Any]:
    return _ok(urllib.parse.unquote(s.strip()))


def op_html_encode(s: str, **_) -> dict[str, Any]:
    return _ok(html.escape(s, quote=True))


def op_html_decode(s: str, **_) -> dict[str, Any]:
    return _ok(html.unescape(s.strip()))


def op_unicode_encode(s: str, **_) -> dict[str, Any]:
    return _ok(s.encode("unicode_escape").decode("ascii"))


def op_unicode_decode(s: str, **_) -> dict[str, Any]:
    try:
        return _ok(s.strip().encode("ascii", "ignore").decode("unicode_escape"))
    except (UnicodeDecodeError, ValueError) as e:
        return _err(f"unicode: {e}")


def op_rot13(s: str, **_) -> dict[str, Any]:
    return _ok(codecs.encode(s, "rot_13"))


def _caesar(s: str, shift: int) -> str:
    out = []
    for ch in s:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def op_caesar_encode(s: str, shift: int = 3, **_) -> dict[str, Any]:
    return _ok(_caesar(s, int(shift)))


def op_caesar_decode(s: str, shift: int | None = None, **_) -> dict[str, Any]:
    if shift is not None:
        return _ok(_caesar(s, -int(shift)))
    lines = [f"shift={i}: {_caesar(s, -i)}" for i in range(1, 26)]
    return _ok("\n".join(lines))


def op_morse_encode(s: str, **_) -> dict[str, Any]:
    parts = []
    for ch in s.upper():
        if ch == " ":
            parts.append("/")
        else:
            parts.append(MORSE_ENC.get(ch, "?"))
    return _ok(" ".join(parts))


def op_morse_decode(s: str, **_) -> dict[str, Any]:
    words = []
    for word in s.strip().split("/"):
        letters = [MORSE_DEC.get(tok, "?") for tok in word.split() if tok]
        words.append("".join(letters))
    return _ok(" ".join(words).strip())


def op_md5(s: str, **_) -> dict[str, Any]:
    return _ok(hashlib.md5(s.encode()).hexdigest())


def op_sha1(s: str, **_) -> dict[str, Any]:
    return _ok(hashlib.sha1(s.encode()).hexdigest())


def op_sha256(s: str, **_) -> dict[str, Any]:
    return _ok(hashlib.sha256(s.encode()).hexdigest())


def op_sha512(s: str, **_) -> dict[str, Any]:
    return _ok(hashlib.sha512(s.encode()).hexdigest())


def op_jwt_decode(s: str, **_) -> dict[str, Any]:
    parts = s.strip().split(".")
    if len(parts) < 2:
        return _err("JWT 至少要有 header.payload")
    decoded: dict[str, Any] = {}
    for i, name in enumerate(("header", "payload")):
        raw = _b64pad(parts[i])
        try:
            decoded[name] = json.loads(base64.urlsafe_b64decode(raw))
        except (json.JSONDecodeError, ValueError, binascii.Error) as e:
            return _err(f"jwt {name}: {e}")
    decoded["sig_present"] = len(parts) > 2 and bool(parts[2])
    return _ok(decoded)


def op_jwt_encode(s: str, secret: str = "", algorithm: str = "HS256", **_) -> dict[str, Any]:
    try:
        payload = json.loads(s)
    except json.JSONDecodeError as e:
        return _err(f"payload JSON: {e}")
    header = {"alg": algorithm, "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    signing = f"{h}.{p}"
    if algorithm.upper() == "NONE":
        return _ok(signing + ".")
    if algorithm.upper() != "HS256":
        return _err("本工具只签 HS256 / none；RS256 走 jwt_gql_probe")
    if not secret:
        return _err("HS256 需要 --key")
    sig = hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
    return _ok(signing + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode())


def _aes_key(key: str) -> bytes | None:
    raw = key.encode()
    if len(raw) in (16, 24, 32):
        return raw
    return None


def op_aes_encrypt(s: str, key: str = "", iv: str = "", **_) -> dict[str, Any]:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        return _err("需要 pycryptodome：pip install pycryptodome")
    kb = _aes_key(key)
    if kb is None:
        return _err("AES 密钥必须是 16/24/32 字节")
    ivb = (iv.encode() if iv else kb)[:16]
    if len(ivb) < 16:
        ivb = ivb.ljust(16, b"\x00")
    cipher = AES.new(kb, AES.MODE_CBC, ivb)
    return _ok(base64.b64encode(cipher.encrypt(pad(s.encode(), 16))).decode())


def op_aes_decrypt(s: str, key: str = "", iv: str = "", **_) -> dict[str, Any]:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        return _err("需要 pycryptodome：pip install pycryptodome")
    kb = _aes_key(key)
    if kb is None:
        return _err("AES 密钥必须是 16/24/32 字节")
    ivb = (iv.encode() if iv else kb)[:16]
    if len(ivb) < 16:
        ivb = ivb.ljust(16, b"\x00")
    try:
        cipher = AES.new(kb, AES.MODE_CBC, ivb)
        pt = unpad(cipher.decrypt(base64.b64decode(s.strip())), 16)
        return _ok(pt.decode("utf-8", "replace"))
    except (ValueError, binascii.Error) as e:
        return _err(f"aes: {e}")


def op_auto(s: str, **_) -> dict[str, Any]:
    hits: list[str] = []
    raw = s.strip()
    if "%" in raw:
        d = urllib.parse.unquote(raw)
        if d != raw:
            hits.append(f"[url] {d}")
    if "&" in raw and (";" in raw or "#" in raw):
        d = html.unescape(raw)
        if d != raw:
            hits.append(f"[html] {d}")
    if "\\u" in raw:
        try:
            hits.append(f"[unicode] {raw.encode('ascii', 'ignore').decode('unicode_escape')}")
        except (UnicodeDecodeError, ValueError):
            pass
    if "." in raw and raw.count(".") == 2:
        jwt = op_jwt_decode(raw)
        if jwt.get("ok"):
            hits.append("[jwt] " + json.dumps(jwt["result"], ensure_ascii=False))
    if re.fullmatch(r"[A-Za-z0-9+/_-]+=*", raw) and len(raw) >= 4:
        b = op_base64_decode(raw)
        if b.get("ok") and any(c.isprintable() for c in str(b["result"])):
            hits.append(f"[base64] {b['result']}")
    hx = raw[2:] if raw.lower().startswith("0x") else raw.replace(" ", "")
    if re.fullmatch(r"[0-9a-fA-F]+", hx) and len(hx) % 2 == 0 and 2 <= len(hx) <= 4096:
        d = op_hex_decode(hx)
        if d.get("ok") and any(c.isprintable() for c in str(d["result"])):
            hits.append(f"[hex] {d['result']}")
    if set(raw) <= {".", "-", " ", "/"} and ("." in raw or "-" in raw):
        hits.append(f"[morse] {op_morse_decode(raw)['result']}")
    jwt_hit = any(h.startswith("[jwt]") for h in hits)
    if raw.isalpha() and not jwt_hit:
        hits.append(f"[rot13] {codecs.encode(raw, 'rot_13')}")
    if jwt_hit:
        hits[:] = [h for h in hits if not h.startswith("[base64]")]
    if not hits:
        return _err("无法自动识别编码")
    return _ok(hits)


OPS: dict[str, Callable[..., dict[str, Any]]] = {
    "base64_encode": op_base64_encode,
    "base64_decode": op_base64_decode,
    "base32_encode": op_base32_encode,
    "base32_decode": op_base32_decode,
    "base58_encode": op_base58_encode,
    "base58_decode": op_base58_decode,
    "hex_encode": op_hex_encode,
    "hex_decode": op_hex_decode,
    "url_encode": op_url_encode,
    "url_decode": op_url_decode,
    "html_encode": op_html_encode,
    "html_decode": op_html_decode,
    "unicode_encode": op_unicode_encode,
    "unicode_decode": op_unicode_decode,
    "rot13_encode": op_rot13,
    "rot13_decode": op_rot13,
    "caesar_encode": op_caesar_encode,
    "caesar_decode": op_caesar_decode,
    "morse_encode": op_morse_encode,
    "morse_decode": op_morse_decode,
    "md5": op_md5,
    "sha1": op_sha1,
    "sha256": op_sha256,
    "sha512": op_sha512,
    "jwt_decode": op_jwt_decode,
    "jwt_encode": op_jwt_encode,
    "aes_encrypt": op_aes_encrypt,
    "aes_decrypt": op_aes_decrypt,
    "auto": op_auto,
}

ALIASES = {
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
    "sha512_hash": "sha512",
    "auto_decode": "auto",
}


def execute(op: str, text: str, **kw: Any) -> dict[str, Any]:
    name = ALIASES.get(op, op)
    fn = OPS.get(name)
    if not fn:
        return _err(f"未知操作 {op}。--list 看全部")
    return fn(text, **kw)


def main() -> int:
    ap = argparse.ArgumentParser(description="编解码 / 哈希 / JWT / AES")
    ap.add_argument("op", nargs="?", help="操作名，或 auto")
    ap.add_argument("--input", "-i", default="", help="待处理字符串")
    ap.add_argument("--file", help="从文件读输入")
    ap.add_argument("--key", default="", help="AES / JWT HS256 密钥")
    ap.add_argument("--iv", default="", help="AES IV")
    ap.add_argument("--shift", type=int, help="Caesar 位移")
    ap.add_argument("--alg", default="HS256", help="JWT 算法 HS256/none")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--case", default="", help="写入 案卷/crypto_decode/last.json")
    args = ap.parse_args()
    if args.list or not args.op:
        print("\n".join(sorted(OPS)))
        return 0
    text = args.input
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()
    if not text:
        print("[!] 需要 --input / --file / stdin", file=sys.stderr)
        return 2
    kw: dict[str, Any] = {"key": args.key, "iv": args.iv, "secret": args.key, "algorithm": args.alg}
    if args.shift is not None:
        kw["shift"] = args.shift
    data = execute(args.op, text.rstrip("\n"), **kw)
    if args.case:
        if str(_OPS_DIR) not in sys.path:
            sys.path.insert(0, str(_OPS_DIR))
        from scope_lib import write_probe_json  # noqa: E402

        write_probe_json(
            {"op": args.op, "level": "L1" if data.get("ok") else "L0", **data},
            case=args.case,
            case_subdir="crypto_decode",
            filename="last.json",
        )
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif data.get("ok"):
        r = data["result"]
        print(json.dumps(r, ensure_ascii=False, indent=2) if isinstance(r, (dict, list)) else r)
    else:
        print(f"[!] {data.get('error')}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
