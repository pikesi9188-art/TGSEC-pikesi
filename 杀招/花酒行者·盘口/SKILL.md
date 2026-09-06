---
name: 花酒行者·盘口
description: "Laravel 系 TG Mini App 博彩渗透：API Token 鉴权绕过、TG initData 伪造、充值/提现业务逻辑。触发：Laravel/Sanctum/api-token/TMA/TG 博彩小程序。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [telegram, tma, gambling, laravel, soketi, cloudfront]
    category: daaixianzun
---

> **花酒行者**
> 花酒一壶藏遗藏，青茅山底醉人亡。
> 行者已去蛊还在，后来人续这一缸。

# Laravel RESTful Gambling TMA Pentest (币發/bf11 family)

Use when the target is a **Telegram gambling Mini App whose API is a plain-JSON Laravel backend** — no `/api.html` wrapper (that's Qzino), no `/app-api/` + AES/RSA envelope (that's Yudao). Third family of the Telegram gambling TMA taxonomy; see `telegram-tma-gambling` (Qzino) and `yudao-appapi-pentest` for the other two.

## 1. Fingerprint (recognize fast)
- Frontend: Vue3 SPA, build assets under `/v<ver>/assets/*.js`, `telegram-web-app.js` reference, dark mobile UI, `<title>` = brand (e.g. 币發娱乐)
- **API is a SEPARATE subdomain** (`api.<domain>`) fronted by CloudFront; frontend static on S3+CloudFront (`server: AmazonS3`, `x-cache: CloudFront`)
- Console query `VITE_*` env constants leak architecture: `VITE_API_BASE_URL`, `VITE_REVERB_APP_KEY`, `VITE_REVERB_HOST`, **`VITE_DEBUG_PIN`**, `VITE_TG_AUTO_LOGIN`, `VITE_TG_DEBUG_BYPASS`, `VITE_TG_BOT_DEEPLINK` (t.me bot handle)
- **`X-Device-Id` header is REQUIRED on every request** — missing → `{"code":400,"message":"请求缺少设备ID：X-Device-Id"}`. This JSON error is the definitive family marker.
- Realtime via **Soketi** (self-hosted Laravel Reverb, `uwewebsockets: 20` header, responds `OK` on GET /, `access-control-allow-origin: *`)
- Bot handles often a family farm: `@lite`, `@lite105/106/109`, `@reddyisok` — VIP/support bots linked from `VITE_VIP_BOT_LINK_*`

## 2. Frontend config extraction (always first)
```bash
curl -s https://<domain>/ -o index.html
# grab the main bundle name from <script type="module" crossorigin src="...">
curl -s https://<domain>/<bundle>.js -o app.js
# dump env constants:
grep -oE 'VITE_[A-Z_]+:"[^"]*"' app.js | sort -u
# full API endpoint list (RESTful, no method wrapper):
grep -oE '"/api/[a-zA-Z0-9/_-]+"' app.js | sort -u
```
Typical endpoint family (48+ endpoints seen): `/api/auth/login/password`, `/api/auth/login/telegram`, `/api/auth/register`, `/api/auth/password-reset/*`, `/api/config`, `/api/games`, `/api/bets`, `/api/mine*`, `/api/wallet/*` (balance/recharges/withdraws/transactions), `/api/addresses*` (CRUD), `/api/rebate*`, `/api/turnover*`, `/api/auto-bet/strategies*`, `/api/about/disclaimer`. Auth = `Authorization: Bearer <token>` added by axios interceptor.

## 3. X-Device-Id (spoofable — pure format check)
- Format: **16 lowercase hex chars** (`/^[0-9a-fA-F]{16}$/`), generated randomly client-side (`ui(8)` = 8 random bytes hex) and persisted in `localStorage["device.id"]`
- Server accepts ANY well-formed 16-hex value — no server-side registration/state. Fabricate freely: `python3 -c "import random; print(''.join(random.choices('0123456789abcdef', k=16)))"`
- A second device-id is stored as localStorage `device-id` (randomUUID or Math.random slice) — used for some analytics, X-Device-Id is the auth-relevant one

## 4. Frontend debug backdoor (HIGH VALUE — hardcoded in production build)
`VITE_DEBUG_PIN` ships in the bundle with the verification logic — attack surface without any auth:
- URL params: `?debug=1&pin=<VITE_DEBUG_PIN>&grant=<token>` → **injects arbitrary auth token** into `localStorage auth.token` (function stores token then reloads) → grants frontend session to anyone who knows the PIN
- `grant`/`g` param requires length ≥16 else ignored; any string accepted
- `VITE_TG_DEBUG_BYPASS:"true"` + `VITE_TG_AUTO_LOGIN:"true"` ⇒ TG initData checks may be bypassable client-side — verify against real API whether server validates initData hash
- Full debug console via `?debug=1&pin=` (eruda) — enables net latency spoofing etc. (client-only, limited value)
- **Exploitation chain**: this backdoor alone fails without a valid token. Combine with: leaked token via other vuln, or use the PIN to pivot a session once you have any user's token.

## 5. CloudFront WAF / IP-block — the usual wall
- Our datacenter IP → CloudFront 403 (`x-cache: Error from cloudfront`, "We can't connect to the server") — looks like origin-down but often is just IP/ASN filtering
- **Reachability probe that works**: `curl -s "https://r.jina.ai/https://api.<domain>/api/config"` → if it returns the JSON `400 请求缺少设备ID` response (not an error page), the API is ALIVE and only our IP is blocked
- **r.jina.ai limit**: does NOT forward custom headers (X-Device-Id) and GET-only ⇒ cannot drive authenticated/business API calls through it. Use only as liveness/error-differential oracle; also confirms WAF-vs-origin: 200-with-business-error = origin alive, 403/502 = our IP banned
- Origin-behind-CloudFront: source IP history via FOFA (`ip="<old-ip>"` shows sibling domains — e.g. bf11 shared origin `54.169.218.145` with `api.pcpd.pro`, and exposed 禅道 ZenTao on :18080, SSH :222, tinyproxy :8888) — but old origin IPs often go dark when the CF config is rebuilt
- Fix: user SOCKS5 proxy pool (see Qzino skill §6 for the proxy-pinning workflow — same pattern: test each proxy with a GET, target bans datacenter IPs broadly)

## 6. Soketi probe
- `GET https://ws.soketi.vip/api/v1/channels?app_key=<VITE_REVERB_APP_KEY>` → `{"error":"The app ... could not be found","code":404}` = app key valid but channel-API disabled or app id differs; WS handshake returns HTTP 200 + `OK` body (not 101) — check both
- `VITE_REVERB_*`: app key `FY32AENXSUFX8QF4`-style (16-char), cluster mt1, host `ws.soketi.vip`. If channel API 404s, the WS app may still accept Pusher-protocol connections on :443
- Low priority: these are message brokers, not usually the data prize

## 7. Pitfalls
- Do NOT assume Qzino/Yudao crypto on a Laravel RESTful target — plain JSON; trying to AES-wrap will just confuse error triage
- CloudFront 403 ≠ origin dead: always differential-test via r.jina.ai before declaring the API down
- r.jina.ai response caching: append a unique query `?debug=<ts>` to force a fresh fetch and prove liveness
- FOFA rate limits: 429 "Too Many Requests" under parallel queries — add sleep(1–2) between FOFA calls
- The `X-Device-Id` requirement applies to unauthenticated endpoints too (/api/config, /api/about/disclaimer) — always send it in every probe
- 405 on GET to POST-only endpoints (auth/register, auth/login/*) is normal — those need POST with JSON body + X-Device-Id

## References
- `references/bf11-case.md` — bf11.vip (币發娱乐) case notes: asset map, frontend config dump, endpoint list, WAF bypass findings (2026-08)

## 真源

- 手法：`传承/商燕飞·盘口.md`
- 工具：`python3 炼蛊房/gambling_family_probe.py --family laravel-tma --base https://授权站 --case <案卷>`
