---
name: 商心慈·芋府微域
description: "Use for yudao TMA pentests (AES+RSA API crypto, tenants)."
version: 1.1.0
author: bot3-curator
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [telegram, tma, yudao, ruoyi, gambling, daaixianzun]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# yudao/ruoyi-vue-pro Telegram Mini App Pentest (创世游戏/世博钱包 family)

Use when the target is a Chinese gambling/wallet **Telegram Mini App** whose backend is a **yudao / ruoyi-vue-pro** Spring Boot app. Distinct from the Qzino family (`telegram-gambling-tma-pentest` skill — that one uses `/api.html` + AES-CBC + MD5 salt with a `method` wrapper). This family uses REST `/app-api/*` paths with a **per-request AES-ECB + RSA + MD5 sign** envelope.

## 1. Fingerprint (recognize the family fast)
- Vue3 SPA; `/runtime/app-config.js` exists and exposes `window.__APP_CONFIG__ = {PLATFORM_ID: <int>, API_LIST: ["https://api.xxx.com", ...], ...}` — **PLATFORM_ID is the tenant id**; API_LIST is a shared failover pool of API domains (4–6 hosts, all Cloudflare-fronted).
- HTML comments name sibling CDN/tenant domains (`img.goodvip.com`, `m.uqscbd.cn`, `a75612.shop`) — each tenant domain serves the SAME build with a different app-config.
- API endpoints all under `/app-api/` (yudao convention): `member/auth/telegramBot/autoLogin`, `system/tenant/getTenantConfiguration`, `game/info/*`, `pay/deposit-order/*`.
- Bundle chunks: `chunk/utils-*.js` (request interceptor + crypto), `chunk/vendor-crypto-*.js` (full crypto-js + jsencrypt), `chunk/common-store-*.js` (API wrappers), lazy `chunk/recharge.api-*.js` / `chunk/rechargeOrderDetails-*.js` (pay APIs).
- `/admin-api/*` (yudao admin) is on a **separate domain** — on app/API hosts it's nginx 404, on frontend hosts it's the SPA catch-all with POST → 405. Don't waste time probing it on app domains.

## 2. App config extraction (always first)
```bash
curl -s "https://<frontend>/runtime/app-config.js"   # -> PLATFORM_ID + API_LIST
curl -s "https://<frontend>/entry/index-*.js" -o entry.js
# chunk map: grep -oE '[A-Za-z0-9_-]+-[A-Za-z0-9_]{8}' entry.js | sort -u
curl -s "https://<frontend>/chunk/utils-*.js" -o utils.js
```
Grep utils.js for: `Rt="..."` (MD5 sign salt), `Lt="MII..."` (RSA public key PEM base64), `function cs`, `function _s`, `VITE_APP_API_VERSION`, `function QV` (terminal code), `X-Api-Encrypt`, `X-Ca-Token`.

## 3. Crypto protocol (verified working, complete recipe)
Per-request envelope for ALL endpoints EXCEPT `telegramBot/autoLogin`:
1. `aes_key = 16 random bytes .hex()` → 32 hex chars; **key bytes = UTF-8 of that 32-char string** (i.e. AES-256-ECB).
2. `ciphertext = base64(AES-256-ECB-PKCS7(utf8(JSON(body))))`.
3. `X-Api-Encrypt = base64(RSA_PKCS1_v1_5_encrypt(aes_key_bytes))` with pubkey `Lt` (jsencrypt default padding = PKCS1 v1.5).
4. Sign: `ts = str(now_ms)`, `nonce = 30 random [A-Za-z0-9]`, `secret = 20 chars` (frontend derives it from a keyMap table + localStorage uuid, but the server only recomputes MD5 over the RECEIVED string — **any 20-char secret works**).
   - POST with body: `g = '"<ciphertext>"|ts|nonce|secret'` (ciphertext JSON.stringify'd, i.e. wrapped in quotes)
   - GET / empty body: `g = 'ts|nonce|secret'`
   - `X-Ca-Token = MD5(g + Rt)` where `Rt` = salt (this family: `"syb"`; verify per bundle).
5. Required headers: `tenant-id: <int>`, `version: VITE_APP_API_VERSION` (e.g. `2024012901`), `terminal: 20` (QV() for web), `device-id: <fake>_<fake>` (any string ok), `Accept-language: zh-CN`, `Content-Type: application/json;charset=UTF-8`, plus X-Ca-* from step 4.
6. Body sent = raw ciphertext string (not JSON-wrapped).

Working client: `scripts/yudao_tma_client.py` (stdlib + pycryptodome; RSA via `Crypto.PublicKey.RSA` + `PKCS1_v1_5`).

## 4. Unauthenticated leaks (encrypted but no auth token)
- `POST /app-api/system/tenant/getTenantConfiguration?website=<host>` — body `{}`, **omit tenant-id header** (frontend sets `noTenantId`). Returns tenant id, currency, country/phone config, and full `loginRegisterConfig`. Confirms crypto is correct when `code:0`.
- `POST /app-api/game/info/getHotGamePage` `{pageNo,pageSize}` → full game library incl. internal `groupId`/`gameId` (19-digit snowflakes).
- `POST /app-api/system/notice/index` → announcements.

## 5. initData login (`autoLogin`)
- `POST /app-api/member/auth/telegramBot/autoLogin` — **NOT encrypted**. Body = `application/x-www-form-urlencoded`, field `tg_token=<urlencode(initData)>`. Needs `tenant-id` header.
- The frontend gets `tg_token` from the **URL query** (`?tg_token=...`) of the TMA launch URL; route guard accepts `userinfo.token || query.tg_token`.
- Success: `code:0`, data has `accessToken` + `refreshToken` (then use `Authorization: Bearer <token>` on encrypted calls).
- `code:1004003003 "Token无效或已过期"` means EITHER (a) initData past the (likely short, ~1–5 min) auth_date window, OR (b) **wrong tenant / wrong bot token** — see multi-tenant gotcha.

## 6. Multi-tenant gotcha (the big trap)
One API_LIST pool serves MANY tenants (this family had tenants 185, 187, 188, 189, 190 live; 1/2 nonexistent). Domain → tenant via getTenantConfiguration. The initData `hash` is bound to the bot's token; a bot's TMA may live on a domain whose tenant differs from the one you probed first.
- Symptom: same 1004003003 on every tenant → you're on the WRONG deployment; the bot's TMA is on another domain entirely.
- Fix: find the real TMA domain — t.me/{bot} page `og:description` lists the bot family (钱包/游戏/担保/客服/招商 siblings, e.g. @SBQB 钱包 / @SB28 游戏 / @LSDB 担保 / @SBKF 客服 / @DABO 招商); FOFA `title="<家族词>"`, `body="<bot名>"`, or ask user for the Mini App button URL. Then re-run getTenantConfiguration on that domain for the right tenant id.
- When a fresh initData arrives: **fire autoLogin IMMEDIATELY as the first action of the turn** — do NOT run other probes/recon first (this session burned ~4 min on FOFA between initData receipt and test; window may be minutes).
- Even simpler: have the user paste `JSON.stringify(localStorage)` from the TMA console — it contains `user` (with token), `device_id`, and full platform config. The token alone authenticates the API (no refreshToken needed server-side; frontend needs both only for its own isLogin getter).

## 7. Operator side-finds (FOFA bonus)
- FOFA `title="<品牌词>"` can surface the operator's NON-Cloudflare boxes: e.g. sb28.me `43.133.98.32` (IIS 8.5 + python :8080 + nginx :8888 + RDP :3389), and `47.116.162.111` (Apache Win32 PHP 5.5 + workerman :8282 + RDP :3389) hosting a PHP **公司记账** finance panel (`admin/123456` → full income/expense dump: account-farming ops, 刷粉充值, 魔云腾 cloud-phone boxes).
- PHP 5.5 panels: default creds admin:123456 common; error pages leak install paths (`D:\\account_software\\income.php`); PDO prepared statements mostly resist SQLi but param binding bugs leak stack traces.

## 8. Deposit (充值) chain — verified endpoints
Full money-in chain, all with auth token (`Authorization: Bearer <token>`), encrypted body.
- `POST /app-api/pay/bank/getRechargeChannel` `{}` → channels. Each has outer `payTypeId` (e.g. 2=USDT充值, 14=财务直充/世博钱包) and inner `payTyeRechargeTypeResVOS[].payId` (snowflake, e.g. 2854825158649372952) + `minPrice/maxPrice`, `platformType`, `jumpName`, `isFixedAddr`.
- `POST /app-api/pay/bank/checkDepositOrderIntervalTime` `{depositAmount, payTypeId}` → `{time: <cooldown_secs>, orderNo}` — **rate limit ~10.8h between orders** on USDT channel (payTypeId 14 = 0, no cooldown). Check before create.
- `POST /app-api/pay/deposit-order/create` — **the create**; payload is `{depositAmount: <amt>, depositTypeId: "<INNER payId>", activityCode: "", remark: "", bonusGrant: 1}`. Outer payTypeId → `1008000002 收款通道不存在`. Success returns `{payUrl, self, open, orderNo}`; `self:true` → offline/order-details flow; `open:true` → open payUrl.
- `POST /app-api/pay/bank/generateFixedAddr` `{payId, protocol:"TRC20"}` → per-user fixed USDT address (stable; ERC20 on a TRC20-only channel → `1008000028 虚拟币协议与充值通道不匹配`).
- `POST /app-api/pay/bank/getDepositByOrderNo?orderNo=` → order detail incl. `status` (1=pending, 5=voucher-submitted), `voucherUploadStatus`, `pageUrl`, `expireTime`. Scoped to own member (IDOR-safe).
- `POST /app-api/pay/bank/orderUploadVoucher` `{orderNo, urlList:[imgUrl]}` → **fake voucher accepted** (status 1→5). Review is MANUAL (admin), does NOT auto-credit; status 5 does NOT flip `hasFirstRecharge`. Upload image first via:
- `POST /app-api/infra/file/upload` (multipart field `file`) → `https://img.goodvip.com/qifei/<sha>.png` (any valid PNG; 1×1 works).
- Amount validation quirk: server checks `int(amount) > 0` → `0.5` rejected as "充值金额必须大于零" (truncates), but `100.99` stored as-is; range check `10.00~1000000.00` on real value.

## 9. Withdraw (提现) chain — verified endpoints
- `POST /app-api/pay/bank/getWithdrawalTypes` → types: 极速虚拟币提款 (USDT, code 2), **TG钱包直提** (code 18, currencyType 1), 人工客服直提 (code 17).
- `POST /app-api/pay/bank/getWithdrawals?withdrawTypeId=<id>` → rules (`minPrice 10 / maxPrice 100000`), `memberUserUsdtRespDTOS` (bound addresses), `canWithdrawAmount`.
- `POST /app-api/member/wallet/addUserUsdt` `{address: "<TRC20>", usdtType: 1}` → bind USDT withdraw address. usdtType: 1=TRC20, 2=ERC20 (address validated against protocol), 3/4 → "该钱包地址已被绑定" if taken.
- **`POST /app-api/member/user/set-pay-password` `{payPassword: "<6 digits>"}` — NO old-password check when `payPasswordSet=0`** (code:0). Second call → `1004001024 会员已设置过支付密码`. This bypasses the withdraw password precondition. Non-6-digit → `400 密码为 6 位数字`.
- `POST /app-api/pay/withdrawOrder/create` `{withdrawTypeId, amount, payPassword}` → all types blocked by `1009000012` first-deposit gate (`hasFirstRecharge` must be true; deposit must be PAID, voucher-submitted status 5 doesn't count). Unlock paths: real tiny deposit (min 10 USDT), voucher approval by admin, or forge the payment-gateway callback (below).

## 10. Payment gateway (aurpay / aio.cash)
The USDT channel is powered by **aurpay.net** (rebranded checkout `pay.aio.cash`; widget `cdn.aio.cash/payment-widget/crypto-pay-widget.umd.js` — grep `VITE_CHECKOUT_*` for API bases).
- Order create returns `payUrl: https://pay.aio.cash/<txid>`.
- **`GET https://pay.aio.cash/api/<txid>`** → `{status, vs_amount, chain:"Tron", addr:<per-order deposit address>, amount, bind_id:"<casinoOrderNo>#<tenantId>", overdue_at, contract_addr, decimals}` — the `bind_id` is how the gateway tells the casino which order to credit. `GET /api/<txid>/status` and `/api/<txid>/info` also work; `/api/v2/pub/*` are POST/GET "Method Not Allowed" (widget-only).
- Casino-side callback/notify endpoint NOT under `/app-api` (that prefix 401s) and NOT on `/pay/*`, `/gbw-*` prefixes (nginx 404) — fuzz the origin/dedicated notify host if pursuing callback forgery.
- Underpayment/replay angles untested (needs real USDT on-chain tx).

## 11. Driving the SPA in a headless browser (token injection)
- The pinia `user` store persists to `localStorage["user"]` with paths `userinfo/token/refreshToken/tenantId/fbPixelId`. **isLogin getter requires token AND refreshToken both truthy** → inject `{userinfo:{token: T}, token: T, refreshToken: T}` then `location.reload()` (SPA hash navigation does NOT reload, so the store never re-hydrates).
- After reload the app fires authenticated calls (get-userInfo etc.) and you can drive the recharge/withdraw UI. Handy for harvesting exact payloads of endpoints (lazy chunks appear in `performance.getEntriesByType('resource')` — e.g. `recharge.api-*.js`, `rechargeOrderDetails-*.js`).
- The wallet channel (财务直充/世博钱包, platformType 7) create fails with `1008000005 获取存款地址失败` when the wallet backend is unreachable/down — a service-side dependency, not a param bug.

## 12. Wallet backend & Bot池中控台 (family infra)
The "钱包" bot (e.g. @SBQB 世博钱包) is the casino's deposit/withdraw wallet. Its backend is separate from the casino API pool:
- `sb-bridge-cr7.com` = `128.1.44.118` — **"世博钱包 · Bot池中控台"** (nginx/1.18 Ubuntu): `:9999` HTTP Basic 401, **`:3306` MySQL exposed**, `:7777/:8080/:8880/:9001/:10001/:11333/:12300/:12333/:18082/:10181/:10196/:10352/:10396/:19530` http, `:22/:32580` ssh.
- `165.154.180.182` — "世博钱包" (nginx/1.27.5): `:80/:9001/:10001/:19100`, ssh :22.
- These hosts **firewall datacenter IPs** (every port → 8s timeout, even r.jina.ai can't reach) — need the user's SOCKS5 proxy pool (test each proxy with a GET first). FOFA still sees the ports.
- Family brand domains: `sb28.me` (世博游戏中心), `sb7364.com` (直播站), `sb98.net` (成人站), `sb123.one` (影视站).

## 13. Pitfalls
- **IP ban**: >~10 rapid login attempts (or any burst) against the PHP boxes firewalls your whole IP at the host level (all ports → 8s timeout, 000). Use the user's SOCKS5 proxy pool (test each with GET first), keep `sleep(0.3–3)` between calls.
- Wrong tenant id → same generic error; always enumerate tenants before concluding "token expired".
- Don't re-login between phases if single-session tokens: get token once, chain all authenticated probes in one script with `time.sleep(0.2)` spacing.
- RSA pubkey + salt are per-bundle constants — re-extract from `utils-*.js` if the build rotates.
- **Response triage**: `404 "The requested address does not exist:app-api/..."` = no controller; `401 账号未登录` = controller EXISTS but needs auth; `400 param` error = exists + reachable. Use this to triage endpoint fuzzing.
- `checkDepositOrderIntervalTime` cooldown blocks rapid deposit-order creation — check before each create.
- Frontend auth ≠ API auth: a token works for `/app-api` calls even when `refreshToken` is null; only the SPA's isLogin getter needs both.

## References
- `references/cs666-shibo-family.md`（⚠️本包未含此案例文件，跳过） — case notes: domains/tenants, credentials, deposit & withdraw chain observations, aurpay order API, wallet-backend port map (2026-08).
- `scripts/yudao_tma_client.py` — reusable client: `call(host, url, data, tenant_id, token, encrypted)` + autoLogin helper.
