---
name: 太白云生·市声
description: "TG营销/群发SaaS渗透: loginKey静态认证、admin单密码、SPA魔法覆盖ID挖洞。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, tg, marketing, saas, groupcast]
    category: daaixianzun
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG营销/群发SaaS平台渗透 (Telegram Group-broadcast Marketing SaaS)

## 触发条件
- 目标为 TG 营销/群发/群控 SaaS（卖点数/套餐/群发infra变现），登录页 `/signin` + 用户给"密钥"（如 `AYBOT...`）
- 常涉: 群发任务、TG账号托管、充值点数、USDT/三方支付
- 与 `tg-cloud-control-pentest`(云控, 有OSS STS) 同族但不同变现模型: 营销SaaS是**充值点数+群发/账号托管**, 通常无OSS STS

## 认证模型速判
| 现象 | 含义 |
|---|---|
| `POST /api/login {loginKey}` 用户端 | **静态永久 loginKey** = 账号即session(永不轮换、明文body) → 泄露=永久接管(报告点) |
| `POST /api/admin/login {password}` 单密码 → JWT Bearer | admin 是**单密码闩**, 无用户名; 用户loginKey对admin无效 |
| admin 拒 `{"message":"无权限"}` / `{"msg":"未授权访问，请先登录"}` (403) | 不同后端措辞, 但都是JWT门 → 无横向 |
| 登录错法报 `Cannot GET /api/x`(Express) / `404 page not found`(Go) / `{detail:[{loc,...}]}`(FastAPI) | 多后端混合 |

## ⭐ 核心技巧: SPA chunk 挖"魔法覆盖 ID" (鉴权绕过)
整包 `index-*.js` 通常只给用户端接口；**admin/账号管理/支付都是懒加载 chunk**。从 index 的懒加载 map 拿全部 chunk 名逐个下载:
```
AdminDashboard-*.js  TaskMonitor-*.js  AccountManagement-*.js  AccountStatus-*.js
BulkMessaging-*.js   BatchLogin-*.js   CloudControl-*.js  GroupManagement-*.js
VerifyFailures-*.js  deposit-*.js(白标支付模板, 常未挂, 测 /app-api/ 是否路由)
```
提取端点抓**两种形态**:
```
grep -ohE '"/api/[a-z0-9_/-]*"' chunks/*.js            # 字符串字面量
grep -ohE '\$\{[a-zA-Z]+\}/api/[a-z0-9_/-]*' chunks/*.js  # 模板拼接(必检!)
```
然后 grep chunk 找**硬编码魔法标识**(user_id/token/role/override 覆盖值):
```bash
grep -oiE '[A-Z_]{6,30}(OVERRIDE|ADMIN|MASTER|SYSTEM|ALL)' chunks/*.js
```
本类靶实测: admin 面板用硬编码 `user_id=ADMIN_OVERRIDE` 直接调 `GET /api/get_logs` 拉 admin"实时流水"视图, **无需任何认证** → 鉴权绕过+全站数据泄露。
发现魔法值后: 用它调 admin 数据端点, 再对其余 admin 端点(users/list、users/update、add-points、accounts/list)逐个测是否有 JWT 漏挂。

## ⭐ 全局 vs 按IP 限流判定(admin爆破可行性)
admin 爆破前先用**新代理IP**探一次, 一句话定卒:
- 新IP返回 `{"msg":"密码错误"}` → 限流**按IP** → 可用代理池**分布式轮换破解**
- 新IP仍返回 `{"msg":"登录尝试过于频繁，请60分钟后再试"}` → **全局限流**, 轮换IP绕不过, **爆破作废**, 立即换思路
本类靶实测为全局锁(头1-2次密码错误后才全局锁), 分布式爆破失败。别浪费轮换时间。

## 资金/充值路径
- 充值闭环: 下单 `POST /api/orders/create {loginKey,packageName,type,amount,tg_id}` → orderId + 收款地址; 确认 `POST /api/recharge-balance {...}` **校验链上到账**("未检测到转账") → 无法客户端伪造余额
- 三方支付/第三方通道偶有 `notify/callback` → 若存在且签名弱才是造余额点; 本类靶用 USDT 链上验证, 无回调伪造面
- 核心奖池 admin: `add-points` 加余额 / 全用户管理 / 批量登入 / 客户TG session。被 JWT+全局限速锁死时诚实上报, 别假装打穿

## 通用
- IP 级风控(批量GET触发连接重置/503/000) → 用 SOCKS5 代理池轮换(见 memory proxies)
- 单机单域名的营销SaaS 常无子域/无crt.sh记录, 少花时间子域枚举
- 用户接口多按 loginKey 作用域隔离 → 优先找 admin 数据端点漏挂JWT 或 魔法覆盖值

## 相关
- 本类靶完整战报/端点: `references/aytg-20260805.md`（⚠️本包未含此案例文件，跳过）
