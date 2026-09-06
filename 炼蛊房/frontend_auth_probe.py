#!/usr/bin/env python3
"""前端认证面：Altcha PoW + RSA 加密登录（授权站）。

  python3 炼蛊房/frontend_auth_probe.py drive --base https://授权站 --case <案>
  python3 炼蛊房/frontend_auth_probe.py altcha --challenge <hex> --salt <s> --max 200000
  python3 炼蛊房/frontend_auth_probe.py rsa --n <hex> --e 10001 --text 'pass'
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-frontend-auth"
ALTCHA_JSON = re.compile(r"\{[^{}]{0,400}?(?:challenge|maxnumber|algorithm)[^{}]{0,400}?\}", re.I)
PUB_PEM = re.compile(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)
N_HEX = re.compile(r"""(?:modulus|rsaN|n)\s*[:=]\s*['\"]?(?:0x)?([0-9a-fA-F]{64,})['\"]?""")
E_HEX = re.compile(r"""(?:exponent|rsaE|e)\s*[:=]\s*['\"]?(?:0x)?([0-9a-fA-F]{2,8})['\"]?""")
CHALLENGE_PATHS = (
    "/altcha",
    "/api/altcha",
    "/api/captcha/altcha",
    "/challenge",
    "/api/challenge",
    "/api/publicKey",
    "/api/rsa/public",
)


def solve_altcha(challenge: str, salt: str, maxnumber: int = 500_000, algorithm: str = "SHA-256") -> int | None:
    algo = (algorithm or "SHA-256").replace("-", "").lower()
    hfn = getattr(hashlib, algo, hashlib.sha256)
    ch = (challenge or "").lower()
    salt = salt or ""
    for n in range(int(maxnumber) + 1):
        if hfn(f"{salt}{n}".encode()).hexdigest() == ch:
            return n
    return None


def parse_pubexp(s: str) -> int:
    """10001 当十六进制；65537/3/17 当十进制，避免把常用 e 解错。"""
    raw = (s or "").strip().lower()
    if raw.startswith("0x"):
        return int(raw, 16)
    if raw in {"65537", "3", "17"}:
        return int(raw, 10)
    return int(raw, 16)


def rsa_pkcs1_encrypt(n: int, e: int, msg: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(msg) > k - 11:
        raise ValueError("明文太长")
    pad_len = k - len(msg) - 3
    ps = bytes((i % 254) + 1 for i in range(pad_len))
    em = b"\x00\x02" + ps + b"\x00" + msg
    m = int.from_bytes(em, "big")
    c = pow(m, e, n)
    return c.to_bytes(k, "big")


def _require(url: str) -> str:
    host = host_of(url) or ""
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or url}", file=sys.stderr)
        sys.exit(2)
    return host


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception as exc:
        return {"url": url, "status": 0, "text": "", "err": str(exc)[:80]}
    return {"url": url, "status": r.status_code, "text": r.text or "", "ct": r.headers.get("content-type", "")}


def extract_challenge(text: str) -> dict[str, Any]:
    for m in ALTCHA_JSON.finditer(text or ""):
        try:
            obj = json.loads(m.group())
        except json.JSONDecodeError:
            continue
        if obj.get("challenge") and (obj.get("salt") is not None or obj.get("maxnumber")):
            return obj
    return {}


def cmd_altcha(args: argparse.Namespace) -> int:
    n = solve_altcha(args.challenge, args.salt, args.max, args.algo)
    print(json.dumps({"number": n, "ok": n is not None}, ensure_ascii=False))
    return 0 if n is not None else 1


def cmd_rsa(args: argparse.Namespace) -> int:
    n = int(args.n, 16) if args.n else 0
    e = parse_pubexp(args.e) if args.e else 65537
    if not n:
        print("[!] 需要 --n", file=sys.stderr)
        return 2
    c = rsa_pkcs1_encrypt(n, e, args.text.encode())
    print(json.dumps({"cipher_hex": c.hex(), "n_bits": n.bit_length()}, ensure_ascii=False))
    return 0


def cmd_drive(args: argparse.Namespace) -> int:
    _require(args.base)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    home = _get(sess, base)
    blob = home.get("text") or ""
    ch = extract_challenge(blob)
    if ch.get("challenge"):
        n = solve_altcha(str(ch.get("challenge")), str(ch.get("salt") or ""), int(ch.get("maxnumber") or 200000), str(ch.get("algorithm") or "SHA-256"))
        findings.append({"level": "L2" if n is not None else "L1", "signal": "altcha-html", "number": n})
    pems = PUB_PEM.findall(blob)
    if pems:
        findings.append({"level": "L1", "signal": "rsa-pem-html", "n": len(pems)})
    if N_HEX.search(blob):
        findings.append({"level": "L1", "signal": "rsa-n-js"})
    for path in CHALLENGE_PATHS:
        row = _get(sess, urljoin(base + "/", path.lstrip("/")))
        body = row.get("text") or ""
        ch2 = extract_challenge(body)
        if not ch2:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict) and obj.get("challenge"):
                    ch2 = obj
            except json.JSONDecodeError:
                pass
        if ch2.get("challenge"):
            n = solve_altcha(str(ch2["challenge"]), str(ch2.get("salt") or ""), int(ch2.get("maxnumber") or 200000), str(ch2.get("algorithm") or "SHA-256"))
            findings.append({"level": "L2" if n is not None else "L1", "signal": "altcha-api", "path": path, "number": n})
        if PUB_PEM.search(body) or "BEGIN PUBLIC KEY" in body:
            findings.append({"level": "L1", "signal": "rsa-pem-api", "path": path})
    level = "none"
    for want in ("L2", "L1"):
        if any(f.get("level") == want for f in findings):
            level = want
            break
    rec = {
        "target": base,
        "level": level,
        "findings": findings,
        "ts": datetime.now(UTC).isoformat(),
        "skill": "门前破印",
        "next": "L2=算出 Altcha number。登录 POST 用 rsa 子命令加密密码再打。验证码图走 captcha-ocr。",
    }
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="frontend_auth", filename="surface.json")
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out)}, ensure_ascii=False))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Altcha PoW + RSA 登录面")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("drive")
    d.add_argument("--base", "-u", required=True)
    d.add_argument("--case", default="")
    d.add_argument("--out", type=Path, default=None)
    a = sub.add_parser("altcha")
    a.add_argument("--challenge", required=True)
    a.add_argument("--salt", default="")
    a.add_argument("--max", type=int, default=200000)
    a.add_argument("--algo", default="SHA-256")
    r = sub.add_parser("rsa")
    r.add_argument("--n", required=True)
    r.add_argument("--e", default="10001")
    r.add_argument("--text", required=True)
    args = ap.parse_args()
    if args.cmd == "altcha":
        raise SystemExit(cmd_altcha(args))
    if args.cmd == "rsa":
        raise SystemExit(cmd_rsa(args))
    raise SystemExit(cmd_drive(args))


if __name__ == "__main__":
    main()
