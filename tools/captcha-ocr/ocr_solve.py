#!/usr/bin/env python3
"""授权范围内的图形验证码 OCR（ddddocr）。

示例:
  python3 tools/captcha-ocr/ocr_solve.py file --path captcha.png
  python3 tools/captcha-ocr/ocr_solve.py url  --url https://授权站/captcha --case <案卷>
  python3 tools/captcha-ocr/ocr_solve.py doctor
"""
from __future__ import annotations

import argparse
import base64
import json
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

OPS = _kit_ops_dir(Path(__file__))
ENGINE = Path(__file__).resolve().parents[2]
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "captcha_ocr"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def get_ocr(beta: bool = False):
    try:
        import ddddocr  # type: ignore
    except ImportError as e:
        raise SystemExit(
            "[err] 未安装 ddddocr。先执行: bash tools/captcha-ocr/install.sh"
        ) from e
    if beta:
        return ddddocr.DdddOcr(det=False, ocr=True, show_ad=False, beta=True)
    return ddddocr.DdddOcr(det=False, ocr=True, show_ad=False)


def classify_hint(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return "empty"
    if t.isdigit():
        return "digits"
    if t.isalpha():
        return "alpha"
    if t.isalnum():
        return "alnum"
    return "mixed"


def solve_bytes(data: bytes, beta: bool = False) -> dict:
    ocr = get_ocr(beta=beta)
    text = (ocr.classification(data) or "").strip()
    return {
        "ok": bool(text),
        "text": text,
        "hint": classify_hint(text),
        "bytes": len(data),
        "engine": "ddddocr-beta" if beta else "ddddocr",
        "ts": _now(),
    }


def cmd_doctor(_: argparse.Namespace) -> int:
    try:
        import importlib.metadata as _im
        import ddddocr  # type: ignore

        try:
            ver = _im.version("ddddocr")
        except Exception:
            ver = "?"
        print("[ok] ddddocr", ver)
    except ImportError:
        print("[missing] ddddocr — bash tools/captcha-ocr/install.sh")
        return 1
    try:
        from PIL import Image  # noqa: F401

        print("[ok] Pillow")
    except ImportError:
        print("[missing] Pillow")
        return 1
    print("[ok] captcha-ocr ready")
    return 0


def cmd_file(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser().resolve()
    if not path.is_file():
        raise SystemExit(f"[err] 文件不存在: {path}")
    data = path.read_bytes()
    result = solve_bytes(data, beta=args.beta)
    result["source"] = str(path)
    if args.case:
        out = case_dir(args.case) / f"file_{path.stem}.json"
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result["evidence"] = str(out)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


def cmd_url(args: argparse.Namespace) -> int:
    import requests

    ensure_scope(args.url)
    headers = {}
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.ua:
        headers["User-Agent"] = args.ua
    try:
        r = requests.get(args.url, headers=headers, timeout=args.timeout, verify=not args.insecure)
        r.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise SystemExit(f"[err] 无法拉取验证码 URL: {exc}") from exc
    ctype = (r.headers.get("Content-Type") or "").lower()
    data = r.content
    if "json" in ctype or data[:1] in (b"{", b"["):
        try:
            j = r.json()
            b64 = None
            for k in ("img", "image", "captcha", "data", "base64"):
                v = j.get(k) if isinstance(j, dict) else None
                if isinstance(v, str) and len(v) > 32:
                    b64 = v
                    break
            if b64 and "," in b64:
                b64 = b64.split(",", 1)[1]
            if b64:
                data = base64.b64decode(b64)
        except Exception:
            pass
    result = solve_bytes(data, beta=args.beta)
    result["source"] = args.url
    result["http_status"] = r.status_code
    result["content_type"] = ctype
    out_dir = case_dir(args.case)
    img_path = out_dir / "last_captcha.bin"
    img_path.write_bytes(data)
    result["saved_image"] = str(img_path)
    out = out_dir / "url_solve.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result["evidence"] = str(out)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


def cmd_b64(args: argparse.Namespace) -> int:
    raw = args.data.strip()
    if "," in raw and raw.lower().startswith("data:"):
        raw = raw.split(",", 1)[1]
    data = base64.b64decode(raw)
    result = solve_bytes(data, beta=args.beta)
    result["source"] = "base64"
    if args.case:
        out = case_dir(args.case) / "b64_solve.json"
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result["evidence"] = str(out)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


def main() -> int:
    p = argparse.ArgumentParser(description="图形验证码 OCR（授权闸门）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="检查 ddddocr/Pillow")
    d.set_defaults(func=cmd_doctor)

    f = sub.add_parser("file", help="本地图片识别")
    f.add_argument("--path", required=True)
    f.add_argument("--case")
    f.add_argument("--beta", action="store_true", help="ddddocr beta 模型")
    f.set_defaults(func=cmd_file)

    u = sub.add_parser("url", help="拉取授权站验证码图并识别")
    u.add_argument("--url", required=True)
    u.add_argument("--case", required=True)
    u.add_argument("--cookie")
    u.add_argument("--ua", default="大爱仙尊-captcha-ocr/1.0")
    u.add_argument("--timeout", type=float, default=20.0)
    u.add_argument("--insecure", action="store_true")
    u.add_argument("--beta", action="store_true")
    u.set_defaults(func=cmd_url)

    b = sub.add_parser("b64", help="base64 / data-URL 识别")
    b.add_argument("--data", required=True)
    b.add_argument("--case")
    b.add_argument("--beta", action="store_true")
    b.set_defaults(func=cmd_b64)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
