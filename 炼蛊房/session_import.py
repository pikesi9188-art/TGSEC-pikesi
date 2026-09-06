#!/usr/bin/env python3
"""校验并导入浏览器 Cookie → Playwright storage_state。

解决 tghaopf 类问题：USER_SESSION 粘贴丢失 JWT 点号 / payload 损坏后仍被误用。

示例:
  python3 炼蛊房/session_import.py \\
    --domain 授权站 \\
    --input /path/cookies.json \\
    --out 案卷/<案卷>/接管/session

  python3 炼蛊房/session_import.py --domain 授权站 --stdin --out ./session
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import unquote


JWT_NAME_DEFAULTS = ("USER_SESSION", "user_session", "token", "Authorization")


def b64url_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad)


def validate_jwt(value: str) -> dict[str, Any]:
    """返回 {ok, errors, parts, header, payload, dot_count, hints}。"""
    raw = unquote(value.strip())
    info: dict[str, Any] = {
        "ok": False,
        "errors": [],
        "hints": [],
        "dot_count": raw.count("."),
        "raw_len": len(raw),
        "header": None,
        "payload": None,
        "parts": [],
    }
    if info["dot_count"] != 2:
        info["errors"].append(
            f"JWT 必须恰好 2 个英文句点 '.'，当前 {info['dot_count']} 个（常见：表格粘贴丢点）"
        )
        # 尝试识别疑似双编码 payload
        if "ZlEuZXlK" in raw or (raw.startswith("eyJ") and "ZXlK" in raw[20:]):
            info["hints"].append(
                "值里出现 header 与 base64(payload) 粘连痕迹，请从浏览器重新复制完整 Cookie"
            )
        return info

    parts = raw.split(".")
    info["parts"] = [f"len={len(p)}" for p in parts]
    try:
        header = json.loads(b64url_decode(parts[0]))
        info["header"] = header
    except Exception as e:
        info["errors"].append(f"header 无法解码: {e}")
        return info
    try:
        payload_bytes = b64url_decode(parts[1])
        # payload 应为 JSON；二进制则损坏
        payload = json.loads(payload_bytes)
        info["payload"] = payload
    except Exception as e:
        info["errors"].append(f"payload 无法解码为 JSON: {e}（粘贴损坏或双编码）")
        info["hints"].append("不要手修 JWT；浏览器 Application → Cookies 重新导出")
        return info

    if not parts[2]:
        info["errors"].append("signature 段为空")
        return info

    info["ok"] = True
    return info


def parse_cookie_input(text: str) -> list[dict[str, Any]]:
    """支持: JSON 数组/对象、Netscape、Name\\tValue 行、Cookie 请求头。"""
    text = text.strip()
    if not text:
        return []

    # JSON
    if text[0] in "[{":
        data = json.loads(text)
        if isinstance(data, dict):
            # {name: value} 或 Playwright storage / 单对象
            if "cookies" in data and isinstance(data["cookies"], list):
                return [_norm_cookie(c) for c in data["cookies"]]
            if "name" in data and "value" in data:
                return [_norm_cookie(data)]
            return [_norm_cookie({"name": k, "value": str(v)}) for k, v in data.items()]
        if isinstance(data, list):
            return [_norm_cookie(c) for c in data]
        raise ValueError("无法识别的 JSON Cookie 结构")

    cookies: list[dict[str, Any]] = []
    # Cookie: a=b; c=d
    if "\n" not in text and "=" in text and ("Cookie:" in text or "; " in text):
        line = re.sub(r"(?i)^cookie:\s*", "", text)
        for part in line.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            n, _, v = part.partition("=")
            cookies.append(_norm_cookie({"name": n.strip(), "value": v.strip()}))
        return cookies

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Netscape: domain\tflag\tpath\tsecure\texpiry\tname\tvalue
        if line.startswith(".") or "\t" in line:
            cols = line.split("\t")
            if len(cols) >= 7 and cols[5] and cols[6] is not None:
                cookies.append(
                    _norm_cookie(
                        {
                            "name": cols[5],
                            "value": cols[6],
                            "domain": cols[0],
                            "path": cols[2] or "/",
                            "secure": cols[3].upper() == "TRUE",
                            "httpOnly": False,
                        }
                    )
                )
                continue
            if len(cols) == 2:
                cookies.append(_norm_cookie({"name": cols[0], "value": cols[1]}))
                continue
            if len(cols) >= 3 and cols[0] and cols[1]:
                # EditThisCookie TSV-ish: name value domain ...
                cookies.append(
                    _norm_cookie(
                        {
                            "name": cols[0],
                            "value": cols[1],
                            "domain": cols[2] if len(cols) > 2 else "",
                            "path": cols[3] if len(cols) > 3 else "/",
                        }
                    )
                )
                continue
        if "=" in line:
            n, _, v = line.partition("=")
            cookies.append(_norm_cookie({"name": n.strip(), "value": v.strip()}))
    return cookies


def _norm_cookie(c: dict[str, Any]) -> dict[str, Any]:
    name = str(c.get("name") or c.get("Name") or "")
    value = c.get("value") if "value" in c else c.get("Value")
    if value is None:
        value = ""
    value = unquote(str(value)) if "%3D" in str(value) or "%2E" in str(value) else str(value)
    domain = str(c.get("domain") or c.get("Domain") or c.get("host") or c.get("Host") or "")
    path = str(c.get("path") or c.get("Path") or "/")
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path or "/",
        "httpOnly": bool(
            c.get("httpOnly") or c.get("HttpOnly") or c.get("is_httponly") or c.get("isHttpOnly") or False
        ),
        "secure": bool(
            c.get("secure") if "secure" in c else (
                c.get("Secure") if "Secure" in c else (
                    c.get("is_secure") if "is_secure" in c else True
                )
            )
        ),
        "sameSite": c.get("sameSite") or c.get("SameSite") or "Lax",
        "expires": c.get("expirationDate") or c.get("expires") or -1,
    }


def apply_domain(cookies: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    root = domain.lstrip(".").lower()
    out = []
    for c in cookies:
        d = (c.get("domain") or "").lstrip(".").lower()
        if not d:
            c = {**c, "domain": root}
        elif root not in d and d not in root:
            # 保留但标记；Playwright 需要匹配 URL 域
            c = {**c, "domain": root if not d.startswith(".") else d}
        out.append(c)
    return out


def to_playwright_storage(cookies: list[dict[str, Any]], origin: str) -> dict[str, Any]:
    pw = []
    for c in cookies:
        item: dict[str, Any] = {
            "name": c["name"],
            "value": c["value"],
            "domain": c["domain"] if c["domain"].startswith(".") else c["domain"],
            "path": c.get("path") or "/",
            "httpOnly": bool(c.get("httpOnly")),
            "secure": bool(c.get("secure", True)),
            "sameSite": str(c.get("sameSite") or "Lax"),
        }
        exp = c.get("expires")
        if isinstance(exp, (int, float)) and exp > 0:
            # EditThisCookie 用秒；Playwright 也用秒
            if exp > 1e12:  # ms
                exp = exp / 1000.0
            item["expires"] = float(exp)
        pw.append(item)
    return {"cookies": pw, "origins": [{"origin": origin, "localStorage": []}]}


def main() -> int:
    ap = argparse.ArgumentParser(description="Cookie/会话导入与 JWT 校验")
    ap.add_argument("--domain", required=True, help="如 授权站")
    ap.add_argument("--input", "-i", help="Cookie 文件路径")
    ap.add_argument("--stdin", action="store_true", help="从标准输入读")
    ap.add_argument("--out", "-o", required=True, help="输出目录")
    ap.add_argument(
        "--session-names",
        default=",".join(JWT_NAME_DEFAULTS),
        help="需要按 JWT 校验的 Cookie 名，逗号分隔",
    )
    ap.add_argument("--require-session", action="store_true", help="必须存在可校验的会话 Cookie")
    ap.add_argument("--require-cf", action="store_true", help="必须存在 cf_clearance")
    ap.add_argument("--scheme", default="https")
    args = ap.parse_args()

    if args.stdin:
        text = sys.stdin.read()
    elif args.input:
        text = Path(args.input).expanduser().read_text(encoding="utf-8", errors="replace")
    else:
        print("[!] 需要 --input 或 --stdin", file=sys.stderr)
        return 2

    try:
        cookies = parse_cookie_input(text)
    except Exception as e:
        print(f"[!] 解析失败: {e}", file=sys.stderr)
        return 2

    if not cookies:
        print("[!] 未解析到任何 Cookie", file=sys.stderr)
        return 2

    cookies = apply_domain(cookies, args.domain)
    by_name = {c["name"]: c for c in cookies if c.get("name")}

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "domain": args.domain,
        "cookie_count": len(cookies),
        "names": sorted(by_name.keys()),
        "jwt_checks": {},
        "ok": True,
        "errors": [],
        "hints": [],
    }

    session_names = [x.strip() for x in args.session_names.split(",") if x.strip()]
    found_ok_session = False
    for name in session_names:
        if name not in by_name:
            continue
        info = validate_jwt(by_name[name]["value"])
        report["jwt_checks"][name] = {
            "ok": info["ok"],
            "dot_count": info["dot_count"],
            "raw_len": info["raw_len"],
            "header": info.get("header"),
            "payload": info.get("payload"),
            "errors": info["errors"],
            "hints": info["hints"],
        }
        if info["ok"]:
            found_ok_session = True
        else:
            report["ok"] = False
            report["errors"].extend([f"{name}: {e}" for e in info["errors"]])
            report["hints"].extend(info["hints"])

    if args.require_session and not found_ok_session:
        report["ok"] = False
        report["errors"].append(
            f"未找到通过校验的会话 Cookie（尝试名: {session_names}）"
        )
        report["hints"].append(
            "在已登录浏览器导出 Cookie；USER_SESSION 必须含 header.payload.sig 两个点号"
        )

    if args.require_cf:
        if "cf_clearance" not in by_name:
            report["ok"] = False
            report["errors"].append("缺少 cf_clearance（--require-cf）")
        else:
            report["cf_clearance"] = True

    # 无 JWT 名时不强制失败，除非 require_session
    for name, c in by_name.items():
        if name in session_names:
            continue
        # 启发式：值像坏掉的 JWT
        v = c["value"]
        if v.startswith("eyJ") and v.count(".") != 2 and len(v) > 40:
            report["hints"].append(
                f"{name}: 以 eyJ 开头但点号数={v.count('.')}，可能是损坏的 JWT"
            )
            if name.upper() in {x.upper() for x in JWT_NAME_DEFAULTS}:
                report["ok"] = False
                report["errors"].append(f"{name}: 疑似损坏 JWT")

    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    origin = f"{args.scheme}://{args.domain.lstrip('.')}"

    (out / "cookies.json").write_text(
        json.dumps(cookies, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    storage = to_playwright_storage(cookies, origin)
    (out / "storage_state.json").write_text(
        json.dumps(storage, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out / "SESSION_REPORT.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    lines = [
        "# SESSION_REPORT",
        "",
        f"- domain: `{args.domain}`",
        f"- cookies: {len(cookies)}",
        f"- ok: **{report['ok']}**",
        "",
        "## JWT",
    ]
    for name, chk in report["jwt_checks"].items():
        lines.append(f"### {name}")
        lines.append(f"- ok: {chk['ok']} · dots={chk['dot_count']} · len={chk['raw_len']}")
        if chk.get("header"):
            lines.append(f"- header: `{json.dumps(chk['header'], ensure_ascii=False)}`")
        if chk.get("payload"):
            # 不把完整敏感 payload 无节制展开；只键名+expire
            p = chk["payload"]
            brief = {k: p[k] for k in list(p)[:8]} if isinstance(p, dict) else p
            lines.append(f"- payload(brief): `{json.dumps(brief, ensure_ascii=False)}`")
        for e in chk.get("errors") or []:
            lines.append(f"- error: {e}")
    if report["errors"]:
        lines.append("")
        lines.append("## Errors")
        lines.extend(f"- {e}" for e in report["errors"])
    if report["hints"]:
        lines.append("")
        lines.append("## Hints")
        lines.extend(f"- {h}" for h in report["hints"])
    lines.append("")
    lines.append("## 产出")
    lines.append(f"- `{out / 'cookies.json'}`")
    lines.append(f"- `{out / 'storage_state.json'}`（Playwright）")
    (out / "SESSION_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[{'OK' if report['ok'] else 'FAIL'}] cookies={len(cookies)} → {out}")
    for e in report["errors"]:
        print(f"  ! {e}")
    for h in report["hints"][:5]:
        print(f"  i {h}")
    if not report["ok"]:
        print("  → 请浏览器重新导出完整 Cookie 后再跑；勿手修 JWT。")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
