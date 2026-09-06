#!/usr/bin/env python3
"""鲸商城PRO 商家 API 未授权批量探测脚本
用法: python3 merchant_api_probe.py <base_url>
如: python3 merchant_api_probe.py https://shop.example.com
输出: 所有返回非401的接口（潜在未授权金矿）
"""
import subprocess, sys, re, os, json

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else "https://shop.yunyfk.com"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"

# 已知 API 列表（从 chunk 收集 + 手动补充）
apis = set([
    "/merchantApi/Common/captchaStart",
    "/merchantApi/Upload/file",
    "/merchantApi/upload/file",
    "/merchantApi/User/checkUserInviteCode",
    "/merchantApi/User/checkUserInviteToken",
    "/merchantApi/email/send",
    "/merchantApi/sms/send",
    "/merchantApi/system/config",
    "/merchantApi/user/checkSafeMode",
    "/merchantApi/user/checkToken",
    "/merchantApi/user/findUsername",
    "/merchantApi/user/forget",
    "/merchantApi/user/login",
    "/merchantApi/user/loginLog",
    "/merchantApi/user/register",
    "/merchantApi/user/updateEmail",
    "/merchantApi/user/updateMobile",
    "/merchantApi/user/updatePassword",
    "/merchantApi/user/updateSafeMode",
    "/merchantApi/user/updateUsername",
    "/merchantApi/user/userinfo",
    "/merchantApi/Goods/list",
    "/merchantApi/Goods/info",
    "/merchantApi/Goods/delete",
    "/merchantApi/GoodsCategory/listAll",
    "/merchantApi/GoodsCardStorage/list",
    "/merchantApi/goodsCardStorage/exportCardsUrl",
    "/merchantApi/order/list",
    "/merchantApi/order/exportCards",
    "/merchantApi/order/orderInfo",
    "/merchantApi/Order/reissueCards",
    "/merchantApi/payment/info",
    "/merchantApi/payment/channel",
    "/merchantApi/dashboard/workplace",
    "/merchantApi/EmailPush/config",
    "/merchantApi/SalesCoupon/list",
    "/merchantApi/SalesDiscount/list",
    "/merchantApi/Plugin/list",
    "/merchantApi/Message/list",
    "/merchantApi/Risk/list",
    "/merchantApi/UserAuth/info",
    "/merchantApi/UserAuth/startAuth",
    "/merchantApi/MyAgent/agentGoodsList",
    "/merchantApi/wallet/applyCash",
    "/merchantApi/shop/setting",
    "/merchantApi/shop/start",
])

# 若本地有 chunk 文件则自动补充
for d in ["/tmp/merchant_chunks", "/tmp/merchant_main.js"]:
    if os.path.isdir(d):
        for f in os.listdir(d):
            try:
                data = open(os.path.join(d, f), encoding='utf-8', errors='ignore').read()
                apis.update(x.strip('"') for x in re.findall(r'"/merchantApi/[A-Za-z0-9_/.-]+"', data))
            except: pass
    elif os.path.isfile(d):
        try:
            data = open(d, encoding='utf-8', errors='ignore').read()
            apis.update(x.strip('"') for x in re.findall(r'"/merchantApi/[A-Za-z0-9_/.-]+"', data))
        except: pass

print(f"[*] 探测 {len(apis)} 个接口 @ {BASE}")
open_list = []
for api in sorted(apis):
    try:
        r = subprocess.run(["curl", "-s", "-m", "8", "-A", UA, "-X", "POST",
                            BASE + api, "-H", "Content-Type: application/json", "-d", '{}'],
                           capture_output=True, text=True, timeout=12)
        out = r.stdout.strip()[:120]
        if '"code":401' in out or '请先登录' in out or 'Token失效' in out:
            continue
        open_list.append((api, out))
        print(f"OPEN  {api}\n      -> {out}")
    except Exception as e:
        print(f"ERR   {api} -> {e}")

print(f"\n[*] 未授权接口 {len(open_list)} 个")
