---
name: 若府·飞头
description: "飞投/RuoYi v3.x 博彩运营商管理后台渗透: GA锁登录、Druid弱口令、farm发现."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, ruoyi, feitou, druid, admin]
    category: daaixianzun
---
# 飞投后台管理框架 (Feitou Admin) Pentest

Use when the target is a **RuoYi-based 飞投后台管理框架 v3.x** admin API — fingerprint: API root returns plain text `欢迎使用飞投后台管理框架，当前版本：v3.9.0，请通过前端地址访问。`. Deployed by gambling operators as `int.tgbet*.net` farms (also claim./mail. subdomains on the same IPs); FOFA `body="飞投后台管理框架"` finds 60+ instances. Verified 2026-08 on tgbet9008.net/嘉百 (int.tgbet271.net).

## 1. Fingerprint & discovery
- API root banner (text/plain): `欢迎使用飞投后台管理框架，当前版本：v3.9.0`
- Swagger exposed: `/v2/api-docs` + `/v3/api-docs` + `/swagger-ui/index.html` — only `test-controller` (4 endpoints under `/dev-api/test/user/*`), title `若依管理系统_接口文档`, contact `飞投`; group param `?group=` has no other groups
- Admin SPA is Vben/RuoYi Vue3: `_app.config.js` carries `VITE_GLOB_API_URL` (the int.* host) + per-brand `VITE_GLOB_APPID` (e.g. jbylhjwf=嘉百). Route modules expose /cp/* business pages. Chunk list regex must include dots: `assets/[A-Za-z0-9_./-]+\.js` (`.vue_vue_type_script...` chunks missed by `[A-Za-z0-9_-]+`)
- Farm discovery: FOFA `body="飞投后台管理框架"` → dozens of int.tgbet*.net; same-IP siblings via `ip=` (e.g. mail.zzam.pro / claim.rdcdk.com are ALSO 飞投 APIs, not mail/claim systems)
- **All instances share ONE MySQL**: druid datasource `jdbc:mysql://172.22.0.4:3888/ftgames` (Docker-internal, root, unreachable from outside; only 80/443 open on hosts)

## 2. Login — Google Authenticator (TOTP) is MANDATORY
- `POST /login {username, password, code, uuid}`; `/captchaImage` → `{"captchaEnabled":false}` (image captcha off, but `code` is repurposed as the GA code)
- `code` is a Java **Integer** — Jackson error leaks type (`Cannot deserialize value of type java.lang.Integer`); arrays/objects/whitespace/strings → parse error
- Validation order: code empty → `谷歌验证码不能为空` (GLOBAL, before user lookup) → user lookup → TOTP validate → **password check LAST**
- ⇒ Password brute-force is IMPOSSIBLE without a valid TOTP. GA cannot be bypassed via: type juggling, `rememberMe`, `captchaEnabled`, alternate field names (googleCode/googleAuth/totpCode...), `mode:null` — all tested, all fail
- **User enumeration via error text**: existing user + wrong TOTP → `谷歌验证码错误` (has 码); nonexistent user → `谷歌验证错误` (no 码). Confirmed users on farm: admin, sysadmin
- `/register` → `当前系统没有开启注册功能！`; `/common/download*` → 401

## 3. Druid console — ruoyi/123456 (universal weak cred)
- `POST /druid/submitLogin` `loginUsername=ruoyi&loginPassword=123456` → success on EVERY int.tgbet* instance (14+ tested); keep the JSESSIONID cookie for json endpoints
- Value:
  - `/druid/datasource.json` — DB topology (host/port/db/user), no password field exposed
  - `/druid/sql.json` — full business schema + MyBatis mapper usage; all parameterized (`?`) → no SQLi via druid-observed queries; check `LastSlowParameters`/`LastError` for slow-query param leaks
  - **`/druid/weburi.json` — endpoint usage + LastAccessTime = live admin activity monitor** (dashboard polls /cp/busi/count every ~2s, 74k+ hits)
- Schema leaked (from SQL log): `cp_user` (id, ucode, uname, moneys, needmons, botid, parent_botid, iscw, allcz, alltx, allwin, backsprop, packcount, fromtype, remark, cztimes...), `cp_busi`/`cp_buys`/`cp_userback` (userid,type,status,moneys,createtime), `cp_change` (wallet audits), `cp_issue` (期数+开奖 opencontent), `cp_config`, `sys_user` (**has google_key column**; login runs `select google_key from sys_user where user_name = ?`)
- session.json/connection.json/spring.json → "Do not support this request" (disabled)

## 4. Auth filter — no bypass found (do not waste time)
- Catch-all filter intercepts EVERY path except whitelist (/login, /captchaImage, /register) and `/druid/**` (separate servlet). Response: `{"msg":"请求访问：X，认证失败，无法访问系统资源","code":401}`
- Tested and failed: `;` `..;/` `%2e` `%2e%2e` `%00` double-slash case-mutation `/login/../x` — all 401 or nginx/Tomcat 400/500
- `/profile/`, `/static/`, `/assets/`, `/actuator*`, `/error*`, `/favicon.ico` — all 401 (no static-file escape)
- Fake Authorization values (admin/1/Bearer/JWT/null) — identical 401 message

## 5. 钱包管理系统变体 (资金总后台, wallet.fina.icu / 154.9.25.34 默认vhost)
- **发现方法**: 对前端服务器做 Host header fuzz (2042个 `prefix.domain` 组合) — 未绑定 Host 落到**默认 vhost**。154.9.25.34 默认 vhost = 钱包管理系统 (Vben SPA, 同构建在 admin.fina.icu)。**任何服务器先测裸IP/未绑定Host的默认vhost**
- API: `wallet.fina.icu/prod-api` (43.156.67.243) — 飞投 v3.9.0 **新版**, 防护差异:
  - `/sys/*` `/mer/*` 无token → **静默空200** (Content-Length:0, 假token也空200); 其他路径 JSON 401 — 两层过滤器
  - druid/actuator 全移除 (404); swagger 页面200但 api-docs 401
  - 锁定: 错GA 5次锁3分钟 (提示 `还剩N次机会`); `登录账号不存在` 在GA检查前 (枚举更直接)
  - 用户: admin + sysadmin (均GA); **2438用户名枚举无GA-less用户**; **TOTP弱码41个(000000/888888/123456/314159/271828...)全失败** — 密钥强随机
- `_app.config.js` 泄露**完整 RSA 私钥** (VITE_GLOB_RSA_PRIVATE_KEY, 与 ht.crypto777.vip 同密钥对; ENABLE_ENCRYPT=false 未实际使用)
- 业务端点 282个 (前端chunk提取): /sys/cp/user/* (dodraw/backDeposit/paysuc/setPwd/**setGoogleKey**/resetPwd/resetaddr/setFreeTxCount/getUsersByDevice), /sys/cp/withdraw/auditList, /sys/cp/transfer/retryCallback, /sys/cp/redpack/refund, /sys/cp/subWallet/*, /sys/cp/flashExchange/*, /sys/cp/key/*, /sys/merchant/*, /mer/cp/com/* (dodraw/depositmoney/transferMoneys), /sys/ls/* (eSIM), /sys/ebd/*, /ptpz/*, /withdrawalReview — 全需token

## 6. Business API map (auth required; /cp/* = 集合玩法/彩票管理)
- `/cp/user/*` list|export|selectAllMoney|memberReport|memberReportExcel|paiBack|paiAllBack|setState|setbacksprop|switchTest|upUname|setDailyRemarks
- `/cp/busi/*` list|count|merInfo|queryRebateDetails|selectRebateMoneysList; `/cp/change/*` list|save|doBusiAud|doWalletBusiAud|checkWalletStatus; `/cp/gameodds`, `/cp/issue`, `/cp/stat`, `/cp/settings`, `/cp/redpack` (refund/emptyFlow), `/cp/record`, `/cp/buys`, `/cp/loss`, `/cp/config`, `/packetDetail`
- All 401 without token; no unauth path found

## 6. Pitfalls & sibling attack surfaces
- **Vben admin SPA config leak**: check `_app.config.js` for `VITE_GLOB_RSA_PRIVATE_KEY` — the 人人支付系统 (crypto777.vip, same operator, Vben) shipped its full RSA private key + public key in the client config (`VITE_GLOB_ENABLE_ENCRYPT:false`). Probe payment systems' frontend configs for keypairs
- Same-operator weaker siblings: open-source `geshanzsq-blog-admin` 操作手册后台 (default creds cracked — see references), QA portals (rrqa888.com 日常QA), game-code redemption SPAs (rdcdk.com)
- Player side of same operator is 666Bet-family (`JWT iss=666BetGame`, suid→token direct login, SMS/email bomb) → see `666bet-tma-pentest` skill
- Frontend server (154.9.25.34, Windows): MySQL 3306 public (creds unknown), FTP/SMB filtered, BT panel 888/8889 needs domain+安全入口, RDP open — the site farm for all brands
- Path filter covers `/druid/*`? No — druid is the ONLY exception; everything else 401

## References
- `references/geshanzsq-blog-admin-pentest.md` — 操作手册/工单后台: API prefix, single-use captcha, **ddddocr 100% 全自动破解**, default creds 123456, unauth dictionary endpoint
- `references/666bet-player-api-extras.md` — 同族玩家API补充: realName XSS(无sink)/充值回调/reported不上分/注册IP限制/mail.tm流程/WSS协议/默认vhost发现方法论
