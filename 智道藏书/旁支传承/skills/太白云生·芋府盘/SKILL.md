---
name: 太白云生·芋府盘
description: "Use for yudao gambling TMAs: crypto, initData, deposits."
version: 1.0.0
author: bot3-curator
license: MIT
platforms: [linux]
metadata:
    tags: [telegram, tma, gambling, yudao, pentest, daaixianzun]
    category: daaixianzun
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# Telegram Gambling TMA Pentest — yudao/ruoyi-vue-pro family (创世游戏/世博钱包)

Use when the target is a **Telegram gambling/betting Mini App on a yudao/ruoyi-vue-pro backend** —
multi-tenant casino/wallet ("创世游戏" brand, 世博钱包@SBQB / 世博游戏@SB28 families). Structurally
the SAME class as the Qzino family (see `telegram-gambling-tma-pentest` in the default profile for the
Qzino-specific crypto) but a different codebase: AES-ECB+RSA+MD5-salt request encryption, form-encoded
initData login, aurpay/aio.cash USDT gateway, first-deposit withdraw gate.

## 1. Fingerprint
- Vue3 SPA; `/runtime/app-config.js` sets `window.__APP_CONFIG__ = {PLATFORM_ID, API_LIST:[...]}`.
  `API_LIST` = pool of CF-fronted `api.*` domains (e.g. api.gjrkc.com / api.fiuwk.com / api.hiebs.com).
- Backend headers: `vary: Origin`, `trace-id:` (empty), `x-content-type-options: nosniff`.
- Multi-tenant: same API pool serves many tenants; `PLATFORM_ID` (189, 185, …) = tenant-id header.
  Each bot in the family = one tenant/domain. Related domains found in config/HTML comments:
  cs666.com(189), a75612.shop(185), m.uqscbd.cn, sb28.me, sb7364.com, sb98.net, sb123.one.
- FOFA: `body="__APP_CONFIG__"` does NOT index (config in separate JS file) — use
  `domain="<family>"`, `cert="<domain>"`, `title="世博"` etc. Family bots via t.me page og:title.
- Load `telegram-mini-app-bot-security` too (initData mechanics, bot token, webhook).

## 2. Request crypto — fully reversed (utils-Bh5zcnIA.js, verified 2026-08)
1. AES-256-ECB-PKCS7(json_body, key=hex(16 random bytes)) → base64 ciphertext string
2. header `X-Api-Encrypt` = base64(RSA-PKCS1v1.5(key_hex)) — RSA public key const `Lt` in bundle
3. sign headers:
   - ts = epoch ms; nonce = 30 random alnum; secret = keymap-derived BUT rides inside the signed
     string → **any 20-char value works** (server only recomputes MD5 over the received string)
   - `g = JSON.stringify(ciphertext) + "|" + ts + "|" + nonce + "|" + secret`
     (GET/empty body: `ts|nonce|secret`)
   - `X-Ca-Token = MD5(g + "syb")` — salt const `Rt = "syb"`
4. mandatory headers: `version=2024012901`, `terminal=20`, `device-id=<any>`,
   `tenant-id=<PLATFORM_ID>`, `Accept-Language: zh-CN`; `Authorization: Bearer <token>` after login
5. Response envelope: `{"code":0,"data":…}` success; `404 …address does not exist` = no endpoint;
   `401 账号未登录` = endpoint exists, needs auth; `400/500` business errors = endpoint valid.
6. Working client: `scripts/chuangshi_client.py` (pycryptodome; venv: `python3`).

## 3. initData auth — SHORT WINDOW workflow
- **autoLogin is the ONLY unencrypted endpoint**: `POST /app-api/member/auth/telegramBot/autoLogin`,
  `Content-Type: application/x-www-form-urlencoded`, body `tg_token=<urlencode(initData)>`,
  `tenant-id` header REQUIRED. Param name is `tg_token` (not initData).
- **auth_date window ~1-2 min**: 4+ min old → `{"code":1004003003,"msg":"登录失败，Token无效或已过期"}`.
  Same error on EVERY tenant → the initData hash binds to that bot's tenant; don't waste time
  looping tenants. One-shot pattern: user pastes fresh initData → login + all authenticated tests
  in one script within ~60s.
- If user-side console script keeps throwing SyntaxError from Telegram smart-quotes: ship single-line
  ASCII-only, no arrow functions, no template literals; verify with `node --check` before sending.
- **Fastest unlock — localStorage dump**: ask user to run `JSON.stringify(localStorage)` in the TMA
  devtools. The `user` key holds `{userinfo:{…},token,refreshToken,tenantId}` → a WORKING session
  token without racing the initData window. Re-inject into browser:
  - pinia `isLogin` getter = `token && refreshToken` (BOTH non-null; dumps often have
    `refreshToken:null` → set `refreshToken = token`)
  - write localStorage, then `location.reload()` — hash-only SPA navigation does NOT re-hydrate pinia.

## 4. High-value member endpoints (all AES+RSA signed, POST unless noted)
- `/app-api/system/tenant/getTenantConfiguration?website=<host>` — pre-auth tenant config (no
  tenant-id header needed, still encrypted)
- `/app-api/member/user/get-userInfo`, `/app-api/member/wallet/get-allWallets`
- `/app-api/pay/bank/getRechargeChannel` → `payTyeRechargeTypeResVOS[].payId` = inner channel ID
  (this inner payId is what `depositTypeId` expects, NOT the outer payTypeId)
- `/app-api/pay/deposit-order/create`
  `{"depositAmount":N,"depositTypeId":"<inner payId>","activityCode":"","remark":"","bonusGrant":1}`
  → `{orderNo, payUrl(3rd-party gateway), self, open}`. Amount must be ≥1 (validation truncates to
  int: 0.5 → "必须大于零"); range min~max enforced (e.g. 10~1000000 USDT).
- `/app-api/pay/bank/checkDepositOrderIntervalTime {depositAmount,payTypeId}` — order cooldown
  (~11 h) between creates; `time:0` = no cooldown on that channel.
- `/app-api/pay/bank/getDepositByOrderNo?orderNo=…` — own orders only (no IDOR observed).
- `/app-api/pay/bank/generateFixedAddr {payId,protocol}` → per-user fixed USDT address
  (on-chain auto-credit, "两次网络确认后自动到账，无需提交订单").
- `/app-api/pay/bank/orderUploadVoucher {orderNo,urlList:[imgURL]}` → fake payment screenshot;
  order status 1→5 (manual review; social-engineering unlock).
- `/app-api/pay/bank/orderCancel?orderNo=…`
- `/app-api/member/user/set-pay-password {"payPassword":"123456"}` — **NO old-password check when
  payPasswordSet=0** (6-digit numeric only).
- `/app-api/member/wallet/addUserUsdt {"address","usdtType":1=TRC20,2=ERC20}` — bind withdraw address
- `/app-api/pay/withdrawOrder/create` → `1009000012 首次提款需要存入任意金额` unless
  `hasFirstRecharge=true` (the FIRST-DEPOSIT GATE).
- `/app-api/pay/bank/getWithdrawalTypes` → 极速虚拟币(2)/TG钱包直提(18)/人工客服(17);
  `/app-api/pay/bank/getWithdrawals?withdrawTypeId=…` → min/max + bound addresses
- `/app-api/game/plat/withdraw` — NO pay-password/first-deposit checks (but needs game balance)
- `/app-api/infra/file/upload` (multipart `file`) → `img.<cdn>.com/...` URL (voucher images)

## 5. USDT gateway = aurpay (white-label pay.aio.cash)
- Order → `payUrl: https://pay.aio.cash/<txid>`; `GET https://pay.aio.cash/api/<txid>` →
  `{status, addr, amount, bind_id:"<casinoOrderNo>#<tenantId>"}` — the deposit-credit mapping.
- Callback forgery (free credit) is THE prize: find the casino's notify endpoint (not under
  /app-api — those 401; not /gbw-* prefixes). Fuzz other hosts/prefixes; bind_id + amount +
  status=paid is the likely payload.
- Gateway Go services expose `/metrics` → 403 (Prometheus, IP-allowlisted); `/debug/pprof/` open on
  monitoring agents (see §7 infra).

## 6. Withdraw first-deposit gate — bypass paths
1. fake voucher → admin approval flips `hasFirstRecharge` (social engineering via 客服)
2. tiny real deposit (min 10 USDT) — flips gate, then full withdraw chain testable
3. aurpay callback forgery — needs casino notify endpoint (see §5)

## 7. Infra / operator side
- Wallet bot family t.me og:title: 钱包@SBQB / 游戏@SB28 / 担保@LSDB / 客服@SBKF / 招商@DABO.
- Wallet backend ("世博钱包·Bot池中控台" sb-bridge-cr7.com = 128.1.44.118): :9999 nginx basic-auth,
  :3306 MySQL, many http ports — usually firewall-blocks foreign IPs (all ports timeout even via
  US SOCKS5). Only leaked service: :19100 = Hawkeye monitoring agent (Go, `./bin/hawkeye_agent`)
  with **`/debug/pprof/` exposed** (goroutine/heap/cmdline — heap dump 2.4MB, mostly runtime symbols;
  low direct value but proves pprof hygiene failure and can leak strings).
- HBBOT server pool (Vultr IPs, "HBBOT - 服务器式完整版") = bot farm panels; often dead.
- **Brute-forcing a PHP login bans the WHOLE host IP** (47.116.162.111 :88/:91 → 000 on all ports
  after ~10 creds; Apache Win32 PHP 5.5). Do login brute force through SOCKS5 from the start.
- SOCKS5 proxy pool workflow: test each proxy with TCP connect (`pysocks`), `socks5h` first; the
  target often bans datacenter IPs broadly — only ~1/10 proxies survives; 19100-style services may
  still leak even when the console is firewalled (scan the full port range, don't trust FOFA).

## 8. Pitfalls
- `depositTypeId` = inner `payId` from getRechargeChannel, NOT the outer payTypeId (outer → "收款通道不存在").
- Never re-login mid-test: each login invalidates the previous token (single-session).
- Frontend crypto consts rotate per deployment — always re-extract `Lt`/`Rt`/API_LIST from the live bundle.
- The order cooldown (~11h) blocks rapid deposit-order churn — budget tests before creating orders.
- TMA console scripts: keep them single-line ASCII; Telegram mangles smart quotes/backticks.
- Cross-check "host down" vs "IP banned": r.jina.ai fetch 200 on the same URL = your IP is banned.

## References
- `references/chuangshi-endpoint-map.md`（⚠️本包未含此案例文件，跳过） — full endpoint list + observed responses + attack results (2026-08)
- `scripts/chuangshi_client.py` — reusable client: AES-ECB+RSA+MD5("syb") sign, any-secret trick, token auth
