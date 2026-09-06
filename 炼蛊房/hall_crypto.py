#!/usr/bin/env python3
"""大厅/OSS 加密协议自解 — Jf 移位自己推，AES 默认 thanks,pig4cloud。

这套栈（pig4cloud / 开元大厅 / ossGetSiteUrlConfig / config_data.json）反复出现：
  1. JS 字符串用 Jf 移位混淆。checksum 在 bundle 里，移位 = checksum % 94
     （yzgj666：checksum=107760 → shift=36）。推不出来就对高位字符串暴力 1–94。
  2. OSS 二层配置 AES-128-ECB + PKCS7，Um 密钥几乎总是 `thanks,pig4cloud`。
  3. API 请求体 `{"encryptString":"<b64>"}`：AES-128-CBC，
     key = md5(staticToken+md5(staticToken))[2:18]，IV 常为 `5421698523412578`。

看到密文/Jf/checksum/encryptString 就跑本脚本，别等人工解。

示例:
  python3 炼蛊房/hall_crypto.py doctor
  python3 炼蛊房/hall_crypto.py derive --js /tmp/commonChunk.js
  python3 炼蛊房/hall_crypto.py oss --in config_data.enc.txt --case <案卷>
  python3 炼蛊房/hall_crypto.py auto --js app.js --in config_data.enc.txt --case <案卷>
  python3 炼蛊房/hall_crypto.py req --decrypt <b64> --token <staticToken>
  python3 炼蛊房/hall_crypto.py req --encrypt '{"username":"x"}' --token <staticToken>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, UTC
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
UM_DEFAULT = "thanks,pig4cloud"
IV_DEFAULT = b"5421698523412578"
MODULI = (94, 95, 96, 126)

KEYWORDS = (
    "pig4cloud", "thanks", "encrypt", "decrypt", "staticToken",
    "ossDecrypt", "CryptoJS", "AES", "hall/api", "encryptString",
    "getSiteInfo", "x-data-mode", "json_cipher",
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "hall_crypto"
    d.mkdir(parents=True, exist_ok=True)
    return d


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def k1(token: str) -> str:
    return md5(token + md5(token))[2:18]


def _aes():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        return AES, pad, unpad
    except ImportError as exc:
        raise SystemExit("需要 pycryptodome：pip install pycryptodome") from exc


def jf_decode(s: str, shift: int) -> str:
    out = []
    for ch in s:
        out.append(chr((ord(ch) - shift) & 0xFFFF))
    return "".join(out)


def _looks_garbled(s: str) -> bool:
    if len(s) < 8:
        return False
    hi = sum(1 for c in s if ord(c) > 126)
    return hi >= max(3, len(s) // 4)


def _score_plain(s: str) -> int:
    if not s or any(ord(c) < 9 for c in s[:80]):
        return -1
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\r\t")
    if printable < len(s) * 0.7:
        return -1
    score = printable
    low = s.lower()
    for kw in KEYWORDS:
        if kw.lower() in low:
            score += 80
    return score


def derive_shift(js: str) -> dict:
    """从 bundle 自己推移位：显式减法 → checksum%94 → 暴力 1–94。"""
    hits: list[dict] = []

    for m in re.finditer(r"charCodeAt\([^)]*\)\s*([+-])\s*(\d{1,3})", js):
        sign, n = m.group(1), int(m.group(2))
        shift = n if sign == "-" else -n
        if 1 <= abs(shift) <= 126:
            hits.append({"how": "charCodeAt", "shift": shift, "score": 200})

    windows = []
    for m in re.finditer(r"charCodeAt", js):
        windows.append(js[max(0, m.start() - 400) : m.end() + 400])
    blob = "\n".join(windows) or js[:20000]
    for m in re.finditer(r"\b(\d{5,7})\b", blob):
        checksum = int(m.group(1))
        for mod in MODULI:
            shift = checksum % mod
            if 1 <= shift <= 126:
                hits.append({
                    "how": f"checksum%{mod}",
                    "shift": shift,
                    "checksum": checksum,
                    "score": 120 if mod == 94 else 80,
                })

    samples = [s for s in re.findall(r"['\"]([^'\"\\]{8,80})['\"]", js) if _looks_garbled(s)]
    samples = samples[:80]
    brute_best: dict | None = None
    for shift in range(1, 95):
        score = 0
        decoded = []
        for s in samples:
            p = jf_decode(s, shift)
            sc = _score_plain(p)
            if sc > 0:
                score += sc
                if any(k.lower() in p.lower() for k in KEYWORDS):
                    decoded.append(p[:80])
        if score > 0 and (brute_best is None or score > brute_best["score"]):
            brute_best = {"how": "brute", "shift": shift, "score": score, "decoded": decoded[:5]}
    if brute_best:
        hits.append(brute_best)

    # 去重，高分优先
    best: dict[int, dict] = {}
    for h in hits:
        sh = int(h["shift"])
        if sh not in best or h["score"] > best[sh]["score"]:
            best[sh] = h
    ranked = sorted(best.values(), key=lambda x: -x["score"])
    return {
        "shift": ranked[0]["shift"] if ranked else None,
        "candidates": ranked[:8],
    }


def recover_strings(js: str, shift: int, limit: int = 40) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in re.findall(r"['\"]([^'\"\\]{6,120})['\"]", js):
        if not _looks_garbled(s):
            continue
        p = jf_decode(s, shift)
        if _score_plain(p) < 40:
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= limit:
            break
    return out


def oss_decrypt(blob: str, key: str = UM_DEFAULT) -> str:
    AES, _pad, unpad = _aes()
    raw = blob.strip()
    if raw.startswith("{") and "encrypt" not in raw[:40].lower():
        raise ValueError("already json")
    b64 = re.sub(r"\s+", "", raw)
    pad_n = (-len(b64)) % 4
    data = base64.b64decode(b64 + ("=" * pad_n))
    key_b = key.encode("utf-8")[:16].ljust(16, b"\0")
    pt = unpad(AES.new(key_b, AES.MODE_ECB).decrypt(data), 16)
    return pt.decode("utf-8")


def req_decrypt(b64: str, token: str, iv: bytes = IV_DEFAULT) -> str:
    AES, _pad, unpad = _aes()
    key_b = k1(token).encode()[:16]
    pad_n = (-len(b64)) % 4
    data = base64.b64decode(b64 + ("=" * pad_n))
    pt = unpad(AES.new(key_b, AES.MODE_CBC, iv[:16]).decrypt(data), 16)
    return pt.decode("utf-8")


def req_encrypt(obj, token: str, iv: bytes = IV_DEFAULT) -> str:
    AES, pad, _unpad = _aes()
    key_b = k1(token).encode()[:16]
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
    ct = AES.new(key_b, AES.MODE_CBC, iv[:16]).encrypt(pad(raw, 16))
    return base64.b64encode(ct).decode()


def _try_oss(blob: str, keys: list[str]) -> tuple[str, str] | None:
    for key in keys:
        try:
            pt = oss_decrypt(blob, key)
        except Exception:
            continue
        if pt.lstrip().startswith("{") or "api_domain" in pt or "siteCode" in pt:
            return key, pt
    return None


def cmd_doctor(_args: argparse.Namespace) -> int:
    print("大厅/OSS 协议（自己解，别问人）")
    print(f"  Jf 移位: checksum % 94   例 107760 % 94 = {107760 % 94}")
    print(f"  OSS AES-128-ECB Um: {UM_DEFAULT}")
    print(f"  API CBC IV: {IV_DEFAULT.decode()}")
    print("  API key: md5(staticToken+md5(staticToken))[2:18]")
    print("  入口: ossGetSiteUrlConfig / cocos/config_data.json / encryptString")
    print("  刀: python3 炼蛊房/hall_crypto.py auto --js <bundle> --in <密文> --case <案卷>")
    return 0


def cmd_derive(args: argparse.Namespace) -> int:
    js = Path(args.js).read_text(encoding="utf-8", errors="replace")
    info = derive_shift(js)
    shift = info["shift"]
    print(json.dumps(info, ensure_ascii=False, indent=2))
    if shift is None:
        print("未推出移位。仍可直接 oss 解：Um=thanks,pig4cloud")
        return 1
    rec = recover_strings(js, shift)
    if rec:
        print("\n解码命中:")
        for s in rec[:20]:
            print(" ", s[:120])
    return 0


def cmd_oss(args: argparse.Namespace) -> int:
    if not args.input:
        print("需要 --in <密文文件>（Telegram 无 stdin，别等管道）")
        return 1
    blob = Path(args.input).read_text(encoding="utf-8", errors="replace")
    keys = [UM_DEFAULT]
    if args.key:
        keys.insert(0, args.key)
    got = _try_oss(blob, keys)
    if not got:
        print("OSS 解密失败。确认是 AES-ECB 密文，或换 --key")
        return 1
    key, pt = got
    print(f"Um={key}")
    if args.case:
        out = case_dir(args.case) / "oss_decrypted.json"
        out.write_text(pt, encoding="utf-8")
        print(f"写入 {out}")
    print(pt[:4000])
    return 0


def cmd_req(args: argparse.Namespace) -> int:
    token = args.token
    if not token:
        print("需要 --token staticToken")
        return 1
    print(f"k1={k1(token)}")
    if args.encrypt:
        obj = json.loads(args.encrypt)
        print(req_encrypt(obj, token))
        return 0
    if args.decrypt:
        print(req_decrypt(args.decrypt, token))
        return 0
    print("给 --encrypt JSON 或 --decrypt b64")
    return 1


def cmd_auto(args: argparse.Namespace) -> int:
    report: dict = {"ts": _now(), "um": UM_DEFAULT, "shift": None, "oss_ok": False}
    keys = [UM_DEFAULT]

    if args.js:
        js = Path(args.js).read_text(encoding="utf-8", errors="replace")
        info = derive_shift(js)
        report["shift"] = info["shift"]
        report["shift_how"] = (info["candidates"][0]["how"] if info["candidates"] else None)
        print(f"Jf shift={info['shift']} ({report['shift_how']})")
        if info["shift"]:
            rec = recover_strings(js, info["shift"])
            report["decoded"] = rec[:20]
            for s in rec:
                if "pig4cloud" in s.lower() or (len(s) in (16, 24, 32) and s.isascii()):
                    keys.append(s.strip())
                m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s, re.I)
                if m:
                    report["staticToken"] = m.group(0)
                    report["k1"] = k1(m.group(0))

    if args.input:
        blob = Path(args.input).read_text(encoding="utf-8", errors="replace")
        got = _try_oss(blob, list(dict.fromkeys(keys)))
        if got:
            key, pt = got
            report["oss_ok"] = True
            report["um_used"] = key
            try:
                report["preview"] = json.loads(pt)
            except json.JSONDecodeError:
                report["preview"] = pt[:1500]
            if args.case:
                out = case_dir(args.case) / "oss_decrypted.json"
                out.write_text(pt, encoding="utf-8")
                report["out"] = str(out)
            print(f"OSS 已解 Um={key}")
        else:
            print("OSS 解密失败")

    text = json.dumps(report, ensure_ascii=False, indent=2, default=str)
    print(text[:5000])
    if args.case:
        (case_dir(args.case) / "hall_crypto.json").write_text(text, encoding="utf-8")
    return 0 if (not args.input or report["oss_ok"]) else 1


def main() -> int:
    p = argparse.ArgumentParser(description="大厅/OSS 加密自解（Jf 移位 + pig4cloud AES）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    dv = sub.add_parser("derive", help="从 JS 自己推移位并解码字符串")
    dv.add_argument("--js", required=True)
    dv.set_defaults(func=cmd_derive)

    o = sub.add_parser("oss", help="AES-ECB 解 ossGetSiteUrlConfig / config_data")
    o.add_argument("--in", dest="input", default="")
    o.add_argument("--key", default="")
    o.add_argument("--case", default="")
    o.set_defaults(func=cmd_oss)

    r = sub.add_parser("req", help="API encryptString 加/解密")
    r.add_argument("--token", default="")
    r.add_argument("--encrypt", default="")
    r.add_argument("--decrypt", default="")
    r.set_defaults(func=cmd_req)

    a = sub.add_parser("auto", help="推移位 + 解 OSS 一条龙")
    a.add_argument("--js", default="")
    a.add_argument("--in", dest="input", default="")
    a.add_argument("--case", default="")
    a.set_defaults(func=cmd_auto)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
