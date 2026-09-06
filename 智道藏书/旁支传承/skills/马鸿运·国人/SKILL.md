---
name: 马鸿运·国人
description: "Use when pentesting 果仁量化 guorenlianghua.com quant platform."
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [pentest, quant, trading, node, express]
    category: daaixianzun
---

> **马鸿运**
> 鸿运加身命难收，杀机扑面运来救。
> 北原少年福如海，气运比刀更温柔。

# 果仁量化 (guorenlianghua.com) 渗透笔记

量化跟单平台(用户绑交易所API Key+Secret跟单)。前端 Vue3 SPA + Express API。

## 资产
- 主站/API: 134.122.140.135 (nginx 1.18 + Express on :3001, 服务名 guoren-quant-mock-api; 443 反代同后端)
- 后台路由: /GrenLhadmin/login; admin API: /api/admin/login (username+password; 密码强, 字典爆破失败)
- 兄弟资产 (FOFA cert 测绘): test.guorenlianghua.com (同后端); jieshouxinhao. → 137.220.225.52 (仅3389 RDP, Windows CredSSP/NLA, 同一模板); order. → 202.95.15.89 (全端口关); 134.122.140.179 (仅3389, 同证书)
- DB: PostgreSQL 5432 公网防火墙超时; 8080 曾现身(FOFA)现不可达 (可能真实后端/mock入口). SSH 22 超时. 邮件 Brevo(mock 不发真信, 密码重置不可用)

## 认证体系 (关键)
- 注册: POST /api/register {username, password(≥12位), contact}, 返回 user.id.
- 登录: POST /api/login {username, password} → Set-Cookie quant_user_token (JWT HS256, payload {userId, username, isAdmin}).
- **同表认证**: /api/admin/login 接受任何 user 表凭证, 密码对了但非admin 返回 "Forbidden: User is not an admin" (区别于 "Invalid credentials" 密码错)。admin 权限 = user 表 isAdmin 标志。
- JWT HS256 严格(alg=none/空key/弱key/公钥混淆均失败)
- **XFF 限速绕过**: /api/admin/login 有59秒限速, 每次加随机 X-Forwarded-For + X-Real-IP 头即可无限速 (admin_brute.py 模式@./data/grlh/admin_brute3.py)
- 用户枚举: 注册 username 重复→"Username already exists"; 已确认存在: admin root administrator guoren operator manager superadmin system guorenlianghua
- 未授权枚举: GET /api/register/invite-preview?inviteCode=X (无鉴权) → {valid, inviter:{userId, username, email}}; 若无邀请码则 "inviteCode 必填"

## 已确认漏洞
- **未授权交易数据全量泄露**: GET /api/v1/quant/masters/{id}/trade-dashboard 与 /strategies/{id}/trade-dashboard 无 token 可分页拉全部交易 (master1=9337条; 全站=44858条, 含价格/仓位/盈亏/traceId; 其中 3728条 source=live_webhook 真实信号). 证据存 ./data/evidence-guorenlianghua/
- **webhook 免鉴权注入面**: POST /api/webhook/trade 无鉴权. 用 trade_id=shortCode(5位, 如 1MVS3) 或 strategy_id="17 " 可定位策略; secret 字段名可配(strategy_secret/secret/token/webhook_secret 都被收, key 不识别), secret 值未知 → 校验失败 "Webhook 策略密钥校验失败". 11个策略 webhookTradeId=1MVS3/E8J8T/RPV6V/LCAQU/FLRJC/QKHPI/GB9XO/2FQ83/IDR6M/DE0QY/CC7TE
- 用户侧API: /api/v1/quant/api-keys 绑定 {exchangeName(仅okx白名单), exchangeType, label, apiKey, secretKey, passphrase, walletAddress, testnet} 返回 masked (apiKeyMasked/hasSecretKey); DELETE 越权有 "not found or no permission" 拦截

## 未突破
- 用户交易所 API Key+Secret: 仅 admin /api/v1/quant/admin/users (admin 可看 apiKeys 计数/标签) + DB 获取; admin 密码未知(爆破已停)
- CORS 白名单严格; 注册提权字段(isAdmin/role)被过滤; noSQL 注入失败
- 提现 /referral/withdrawals: 风控 (minWithdrawalUsdt=100, maxDaily=3, 余额校验, 0 余额不可提)

## 已知支付收款
- OKX USDT-TRC20: TM6xk9hjP5rN4Wi4u452cnC7JaWwh4AcNm; Binance UID 94082287
- VIP 购买: /api/v1/quant/vip/purchase 需客服核验, selfServicePaid 不会自动激活