#!/usr/bin/env python3
"""
tg_social_monitor.py — TG DM 实时监听 + AI 自动社工回复循环

工作流：
  TG DM 轮询新消息 → social_engineer_agent adapt 生成回应
  → 随机延迟(人类节奏) → 自动发送 → 写 social_monitor_state.json

用法：
  # 基本：选号、盯目标用户名、USDT兑换商身份、目标拿代理链接
  python3 炼蛊房/tg_social_monitor.py run \\
    --phone 85298765432 \\
    --target @cs_rep_xxx \\
    --identity usdt_exchanger \\
    --goal agent_url \\
    --case wldzylbot_20260810

  # 指定延迟范围（秒）
  python3 炼蛊房/tg_social_monitor.py run \\
    --phone 85298765432 \\
    --target @cs_rep_xxx \\
    --identity usdt_exchanger \\
    --case wldzylbot_20260810 \\
    --delay-min 45 --delay-max 240

  # 只看建议，不发送
  python3 炼蛊房/tg_social_monitor.py run ... --dry-run

  # 列出号库里可用账号（选号用）
  python3 炼蛊房/tg_social_monitor.py list-accounts

  # 查看当前对话状态
  python3 炼蛊房/tg_social_monitor.py status --case wldzylbot_20260810

依赖：pip install telethon
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, UTC
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
ACCOUNTS_ROOT = ENGINE / "案卷" / "_tg_accounts"
EXPORTS_ROOT = ENGINE / "案卷"

# 同时搜索 telegram账号/可登录/ 目录（万客云控等存放位置）
EXTRA_ACCOUNTS_ROOTS = [
    ENGINE / "telegram账号" / "可登录",
]
SOCIAL_AGENT = ENGINE / "炼蛊房" / "social_engineer_agent.py"

# 默认 TG API 凭据（从 _tg_accounts/api.txt 读取，或用环境变量覆盖）
DEFAULT_API_ID = int(os.environ.get("TG_API_ID", "2040"))
DEFAULT_API_HASH = os.environ.get("TG_API_HASH", "b18441a1ff607e10a989891a5462e627")

# 消息轮询间隔（秒）
POLL_INTERVAL = 15

# 发送回应后的冷却（秒）—— 防止连续刷屏
REPLY_COOLDOWN = 30


# ═══════════════════════════════════════════════════════════════
#  状态文件
# ═══════════════════════════════════════════════════════════════

def state_path(case: str) -> Path:
    d = EXPORTS_ROOT / case / "测绘"
    d.mkdir(parents=True, exist_ok=True)
    return d / "social_monitor_state.json"


def load_state(case: str) -> dict:
    p = state_path(case)
    if p.exists():
        return json.loads(p.read_text())
    return {}


def save_state(case: str, state: dict) -> None:
    p = state_path(case)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2))


def get_thread_state(state: dict, target: str) -> dict:
    """获取指定 target 的线程状态，不存在则初始化"""
    if "threads" not in state:
        state["threads"] = {}
    if target not in state["threads"]:
        state["threads"][target] = {
            "max_id": 0,
            "identity": None,
            "goal": "agent_url",
            "last_send_ts": 0,
            "log": [],
        }
    return state["threads"][target]


# ═══════════════════════════════════════════════════════════════
#  号库：选 session
# ═══════════════════════════════════════════════════════════════

def _collect_sessions() -> list[tuple[Path, dict]]:
    """
    搜集所有可用 session：
      1. 案卷/_tg_accounts/  （号库标准路径）
      2. telegram账号/可登录/                （万客云控 account.session）
    """
    candidates = []
    roots = [ACCOUNTS_ROOT] + EXTRA_ACCOUNTS_ROOTS

    for root in roots:
        if not root.exists():
            continue
        for f in sorted(root.rglob("*.session")):
            # 跳过 burn/trash 等
            if any(part in f.parts for part in ("trash", "sessions_burn", "__pycache__")):
                continue
            meta = {}
            # 优先读同名 .json
            for meta_name in (f.with_suffix(".json"), f.parent / "account.json"):
                if meta_name.exists():
                    try:
                        meta = json.loads(meta_name.read_text())
                        break
                    except Exception:
                        pass
            # 从路径提取手机号（目录名通常就是手机号）
            if not meta.get("phone"):
                # 父目录名如 84842724732
                parent_name = f.parent.name
                if parent_name.isdigit():
                    meta["phone"] = parent_name
                else:
                    # 文件名提取
                    digits = "".join(c for c in f.stem if c.isdigit())
                    if len(digits) >= 8:
                        meta["phone"] = digits
            candidates.append((f, meta))

    return candidates


def find_session(phone: str | None) -> tuple[Path, dict]:
    """
    从号库和 telegram账号/ 找到对应 .session 文件和 meta。
    如果 phone 为 None，自动选第一个可用的。
    返回 (session_path_without_ext, meta_dict)
    """
    candidates = _collect_sessions()

    if not candidates:
        print(f"[!] 号库为空：{ACCOUNTS_ROOT}", file=sys.stderr)
        print("[!] 先用 tg_account_lib.py intake 导入账号", file=sys.stderr)
        sys.exit(1)

    if phone:
        digits = "".join(c for c in phone if c.isdigit())
        for f, meta in candidates:
            name_digits = "".join(c for c in f.stem if c.isdigit())
            if digits in name_digits or name_digits in digits:
                return f.with_suffix(""), meta
        print(f"[!] 找不到手机号 {phone} 对应的 session，可用号：")
        for f, _ in candidates:
            print(f"    {f.name}")
        sys.exit(1)

    # 自动选第一个
    f, meta = candidates[0]
    print(f"[*] 自动选择账号: {f.stem}")
    return f.with_suffix(""), meta


def list_accounts() -> None:
    found = []
    for f, meta in _collect_sessions():
        phone = meta.get("phone") or f.stem
        api_id = meta.get("api_id", "?")
        try:
            rel = str(f.relative_to(ENGINE))
        except ValueError:
            rel = str(f)
        found.append((phone, rel, api_id))

    if not found:
        print("[!] 号库为空")
        return
    print(f"\n{'手机号':<20}  {'api_id':<12}  路径")
    print("-" * 72)
    for phone, path, api_id in found:
        print(f"{phone:<20}  {str(api_id):<12}  {path}")
    print(f"\n共 {len(found)} 个账号")


# ═══════════════════════════════════════════════════════════════
#  AI 生成回应（调 social_engineer_agent.py adapt）
# ═══════════════════════════════════════════════════════════════

def ai_adapt(identity: str, history: str, goal: str) -> str:
    """调用 social_engineer_agent.py adapt，返回建议回应文本"""
    cmd = [
        sys.executable, str(SOCIAL_AGENT),
        "adapt",
        "--id", identity,
        "--history", history,
        "--goal", goal,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out = result.stdout.strip()
        # 提取回复正文（去掉前缀行）
        lines = out.splitlines()
        reply_lines = []
        capture = False
        for line in lines:
            if line.startswith("建议回应") or line.startswith("我：") or line.startswith("[回应]"):
                capture = True
                content = line.split("：", 1)[-1].strip() if "：" in line else line.split("]", 1)[-1].strip()
                if content:
                    reply_lines.append(content)
                continue
            if capture:
                if line.startswith("[") or line.startswith("===") or line.startswith("---"):
                    break
                if line.strip():
                    reply_lines.append(line.strip())

        if reply_lines:
            return "\n".join(reply_lines)

        # fallback：返回全部输出
        return out if out else "[AI 未生成回应，请手动回复]"

    except subprocess.TimeoutExpired:
        return "[AI 超时，请手动回复]"
    except Exception as e:
        return f"[AI 调用失败: {e}]"


# ═══════════════════════════════════════════════════════════════
#  主监听循环
# ═══════════════════════════════════════════════════════════════

async def monitor_loop(
    session_path: Path,
    meta: dict,
    target_username: str,
    identity: str,
    goal: str,
    case: str,
    delay_min: int,
    delay_max: int,
    dry_run: bool,
) -> None:
    try:
        from telethon import TelegramClient
        from telethon.tl.types import User
    except ImportError:
        print("[!] pip install telethon", file=sys.stderr)
        sys.exit(1)

    api_id = int(meta.get("api_id") or DEFAULT_API_ID)
    api_hash = meta.get("api_hash") or DEFAULT_API_HASH

    client = TelegramClient(
        str(session_path),
        api_id,
        api_hash,
        device_model=meta.get("device_model") or "iPhone 14 Pro",
        system_version=meta.get("system_version") or "iOS 16.5",
        app_version=meta.get("app_version") or "9.6.3",
        lang_code="zh",
        system_lang_code="zh-Hans",
    )

    print("[*] 连接 TG ...", flush=True)
    await client.connect()

    if not await client.is_user_authorized():
        print("[!] Session 未授权或已失效，请先验活", file=sys.stderr)
        await client.disconnect()
        sys.exit(1)

    me = await client.get_me()
    print(f"[+] 账号: {me.first_name} (@{me.username or 'N/A'})")

    # 解析目标实体
    try:
        target_entity = await client.get_entity(target_username)
        display = getattr(target_entity, "first_name", "") or target_username
        print(f"[+] 目标: {display} ({target_username})")
    except Exception as e:
        print(f"[!] 找不到目标 {target_username}: {e}", file=sys.stderr)
        await client.disconnect()
        sys.exit(1)

    state = load_state(case)
    thread = get_thread_state(state, target_username)
    thread["identity"] = identity
    thread["goal"] = goal

    print(f"\n[*] 开始监听  目标={target_username}  身份={identity}  目标={goal}")
    print(f"    延迟范围={delay_min}s ~ {delay_max}s  干跑={dry_run}")
    print(f"    状态文件={state_path(case)}")
    print("    Ctrl+C 停止\n")
    save_state(case, state)

    consecutive_errors = 0

    while True:
        try:
            # 拉取新消息（只看对方发来的，即 from_id=target）
            messages = await client.get_messages(
                target_entity,
                min_id=thread["max_id"],
                limit=20,
            )

            new_from_target = [
                m for m in reversed(messages)
                if m.id > thread["max_id"] and m.out is False
            ]

            if new_from_target:
                consecutive_errors = 0
                for msg in new_from_target:
                    text = msg.message or ""
                    ts = msg.date.strftime("%H:%M:%S") if msg.date else "?"
                    print(f"\n[{ts}] 对方: {text}")

                    # 更新 max_id
                    thread["max_id"] = max(thread["max_id"], msg.id)

                    # 记录日志
                    thread["log"].append({
                        "ts": datetime.now(UTC).isoformat(),
                        "dir": "in",
                        "msg_id": msg.id,
                        "text": text,
                    })

                    # 冷却期检查（最近刚发过）
                    since_last = time.time() - thread["last_send_ts"]
                    if since_last < REPLY_COOLDOWN:
                        print(f"    [~] 冷却中，跳过自动回复（距上次 {since_last:.0f}s）")
                        save_state(case, state)
                        continue

                    # AI 生成回应
                    print(f"    [AI] 生成回应 (identity={identity}) ...", end="", flush=True)
                    reply = ai_adapt(identity, text, goal)
                    print(" 完成")
                    print(f"\n    建议发送: {reply}\n")

                    if dry_run:
                        print("    [干跑模式] 不发送")
                    else:
                        # 人类化延迟
                        delay = random.randint(delay_min, delay_max)
                        print(f"    [*] 等待 {delay}s 后发送...", flush=True)
                        await asyncio.sleep(delay)

                        await client.send_message(target_entity, reply)
                        thread["last_send_ts"] = time.time()
                        thread["log"].append({
                            "ts": datetime.now(UTC).isoformat(),
                            "dir": "out",
                            "text": reply,
                        })
                        print("    [+] 已发送")

                        # 目标检测：是否拿到关键信息
                        _check_goal_hit(reply, text, goal, case)

                save_state(case, state)

            else:
                # 更新最大 id（覆盖我们自己发的消息）
                all_new = [m for m in reversed(messages) if m.id > thread["max_id"]]
                if all_new:
                    thread["max_id"] = max(m.id for m in all_new)
                    save_state(case, state)

        except KeyboardInterrupt:
            print("\n[*] 停止监听")
            break
        except Exception as e:
            consecutive_errors += 1
            print(f"[!] 轮询错误: {e}")
            if consecutive_errors >= 5:
                print("[!] 连续5次错误，退出")
                break
            await asyncio.sleep(POLL_INTERVAL * 2)
            continue

        await asyncio.sleep(POLL_INTERVAL)

    await client.disconnect()
    print("[*] 断开连接，状态已保存")


def _check_goal_hit(our_reply: str, their_msg: str, goal: str, case: str) -> None:
    """检测是否命中目标（拿到代理后台链接、账号等），打印提示"""
    import re
    combined = our_reply + " " + their_msg

    if goal == "agent_url":
        urls = re.findall(r"https?://[^\s]+", combined)
        agent_kw = ["agent", "affiliate", "proxy", "代理", "aff", "partner"]
        for url in urls:
            if any(k in url.lower() for k in agent_kw):
                print(f"\n  ★ 目标命中！疑似代理后台链接: {url}")
                print("  → 立刻 scope_expand 并交 agent-probe\n")
                # 写证据文件
                ev_dir = EXPORTS_ROOT / case / "接管" / "代理后台"
                ev_dir.mkdir(parents=True, exist_ok=True)
                ev_file = ev_dir / "social_eng_hit.txt"
                with open(ev_file, "a") as f:
                    f.write(f"[{datetime.now(UTC).isoformat()}]\n")
                    f.write(f"目标消息: {their_msg}\n")
                    f.write(f"命中链接: {url}\n\n")
                print(f"  → 证据写入: {ev_file}")

    invite_match = re.search(r"invite[_=]([A-Za-z0-9]+)", combined, re.I)
    if invite_match:
        code = invite_match.group(1)
        print(f"\n  ★ 拿到邀请码: {code}")
        print("  → 用此码注册代理账号，然后跑 agent_probe.py api-enum\n")

    pid_match = re.search(r"\bpid[=:＝](\d+)", combined, re.I)
    if pid_match:
        pid = pid_match.group(1)
        print(f"\n  ★ 拿到 pid: {pid}  (代理/客服账号 ID)")
        print("  → 用 pid 探测上级 API：get_wallet / 佣金接口\n")


# ═══════════════════════════════════════════════════════════════
#  show status
# ═══════════════════════════════════════════════════════════════

def show_status(case: str) -> None:
    state = load_state(case)
    if not state:
        print(f"[!] 无状态文件: {state_path(case)}")
        return

    threads = state.get("threads", {})
    if not threads:
        print("[!] 无线程记录")
        return

    for target, t in threads.items():
        print(f"\n{'='*60}")
        print(f"  目标:    {target}")
        print(f"  身份:    {t.get('identity')}")
        print(f"  目标:    {t.get('goal')}")
        print(f"  max_id:  {t.get('max_id')}")
        last_ts = t.get("last_send_ts", 0)
        if last_ts:
            ago = int(time.time() - last_ts)
            print(f"  上次发:  {ago}s 前")
        log = t.get("log", [])
        print(f"  消息数:  {len(log)} 条")
        if log:
            last = log[-1]
            d = "→" if last["dir"] == "out" else "←"
            print(f"  最后:    {d} {last['text'][:80]}")


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        description="tg_social_monitor — TG DM 实时监听 + AI 自动社工回复（授权范围内）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # list-accounts
    sub.add_parser("list-accounts", help="列出号库可用账号").set_defaults(func=cmd_list_accounts)

    # status
    p = sub.add_parser("status", help="查看监听状态")
    p.add_argument("--case", required=True, help="案卷名（如 wldzylbot_20260810）")
    p.set_defaults(func=cmd_status)

    # run
    p = sub.add_parser("run", help="启动 TG 监听 + AI 自动回复循环")
    p.add_argument("--phone", default=None,
                   help="使用号库中哪个手机号（留空自动选第一个）")
    p.add_argument("--target", required=True,
                   help="监听的 TG 用户名或 user_id，如 @cs_rep_xxx 或 123456789")
    p.add_argument("--identity", required=True,
                   help="社工身份 ID（见 social_engineer_agent.py list）")
    p.add_argument("--goal", default="agent_url",
                   help="当前对话目标: agent_url / api_doc / tech_stack（默认 agent_url）")
    p.add_argument("--case", required=True,
                   help="案卷名，用于写状态文件（如 wldzylbot_20260810）")
    p.add_argument("--delay-min", type=int, default=45,
                   help="发送前最短随机延迟（秒，默认 45）")
    p.add_argument("--delay-max", type=int, default=240,
                   help="发送前最长随机延迟（秒，默认 240）")
    p.add_argument("--dry-run", action="store_true",
                   help="只打印 AI 建议，不实际发送")
    p.set_defaults(func=cmd_run)

    args = ap.parse_args()
    args.func(args)


def cmd_list_accounts(args: argparse.Namespace) -> None:
    list_accounts()


def cmd_status(args: argparse.Namespace) -> None:
    show_status(args.case)


def cmd_run(args: argparse.Namespace) -> None:
    session_path, meta = find_session(args.phone)

    if args.delay_min > args.delay_max:
        print("[!] delay-min 不能大于 delay-max", file=sys.stderr)
        sys.exit(1)

    asyncio.run(monitor_loop(
        session_path=session_path,
        meta=meta,
        target_username=args.target,
        identity=args.identity,
        goal=args.goal,
        case=args.case,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        dry_run=args.dry_run,
    ))


if __name__ == "__main__":
    main()
