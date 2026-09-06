#!/usr/bin/env python3
"""重置 Token / 短密钥 / Session Fixation 表面（HITCON ATO 族）。

L1：忘记密码/重置页存在。
L2：JS 里重置链把 token 放查询串，或 token 长度 < 16，或重置页挂第三方追踪。
默认不提交邮箱，避免对真实用户发信。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
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

UA = "Mozilla/5.0 大爱仙尊-reset-token"
PATHS = (
    "/forgot", "/forgot-password", "/password/forgot", "/password/reset",
    "/reset-password", "/account/forgot", "/user/forgot", "/users/password",
    "/wp-login.php?action=lostpassword", "/index.php?r=site/forgot",
    "/auth/forgot", "/member/forgot",
)
TOKEN_QS = re.compile(
    r"(?:reset[_-]?token|resetToken|rp_key|pwreset|lostpassword|password_reset)=['\"]?([A-Za-z0-9_-]{4,64})",
    re.I,
)
TRACKERS = ("googletagmanager", "google-analytics", "facebook.net", "doubleclick", "tiktok")
FORM_NEEDLES = ("forgot", "reset password", "忘记密码", "忘記密碼", "重設密碼", "重置密码", "lost password")
TOKEN_STOP = frozenset({
    "true", "false", "null", "undefined", "function", "password", "email",
    "token", "reset", "forgot", "lostpassword", "action", "submit", "this",
})


def real_tokens(found: list[str]) -> list[str]:
    out: list[str] = []
    for t in found:
        if t.lower() in TOKEN_STOP or t.isdigit() or len(t) < 8:
            continue
        out.append(t)
    return out


def _get(sess: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = sess.get(url, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)[:120]}
    text = r.text or ""
    low = text.lower()
    tokens = real_tokens(TOKEN_QS.findall(text))
    short = [t for t in tokens if 8 <= len(t) < 16]
    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "form": any(n in low for n in FORM_NEEDLES) or ("<form" in low and "password" in low),
        "tokens": tokens[:8],
        "short_tokens": short[:8],
        "trackers": [t for t in TRACKERS if t in low],
        "referrer_policy": r.headers.get("Referrer-Policy", ""),
        "snip": re.sub(r"\s+", " ", text)[:140],
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    for p in PATHS:
        row = _get(sess, urljoin(base + "/", p.lstrip("/")))
        if row.get("error") or row.get("status") not in {200, 401, 403}:
            continue
        if not (row.get("form") or row.get("tokens") or "lostpassword" in p):
            continue
        lvl = "L1"
        signal = "reset-form"
        if row.get("short_tokens") or (row.get("tokens") and row.get("trackers") and not row.get("referrer_policy")):
            lvl = "L2"
            signal = "short-or-leaky-token"
        row.update({"level": lvl, "signal": signal, "path": p})
        findings.append(row)
        print(f"  {lvl} {signal} {p}")
        if lvl == "L2":
            break
    level = "L2" if any(f.get("level") == "L2" for f in findings) else (
        "L1" if findings else "none"
    )
    report = {
        "target": base,
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "findings": findings,
        "playbook": "传承/夺舍·短票.md",
        "next": "L2=短 token 或重置页挂追踪。默认不提交邮箱。Session Fixation 另看登录后换 SID。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="reset_token", filename="surface.json",
    )
    print(json.dumps({"level": level, "findings": len(findings), "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="重置 Token 表面（授权内，不发信）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
