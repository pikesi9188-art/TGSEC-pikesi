---
name: 星宿·微域密文
description: "Reverse AES-encrypted TMA/gambling API envelopes end-to-end."
version: 1.0.0
author: bot2
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [telegram, tma, gambling, aes, reverse, pentest]
    category: daaixianzun
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# SKILL: TMA Encrypted-API Reversal (gambling / white-label)

Use when a Telegram Mini App (TMA) / white-label gambling platform's HTTP API encrypts
every request and response with a hardcoded symmetric key and has NO request signature.
Proven against UMI.CC / umi7.vip (@umi88, m-jbgroup white-label, Go `/gc` gateway).

> NOTE: broader TMA attack playbook lives in `telegram-mini-app-bot-security` (default
> profile shared dir, user-owned — read it for initData theory, WebView XSS, webhook,
> TON, Stars). This skill is the concrete encrypted-API reversal workflow for the
> gambling-family targets bot2 hits. Curator: consolidate into that umbrella if adopted.

## 1. Fingerprint the protocol
- Static shell: `<script src="/telegram-web-app.js?59">` + `<div id="root">` + `/<hash>.js` bundle.
- Backend: `GET /gc/<route>?c=<base64>` (or Go gateway `/api/v1/...`).
- Response: `{"s":<status>,"m":"<msg>","c":"<base64 AES(JSON)>"}` — decrypt `c` with the found key.
- Go error corpses (stack tell):
  - `"json unmarshal error"` → your decrypted body failed field types/padding.
  - `"404 page not found"` → Go mux default (route absent OR wrong method).
  - `{"code":404,"message":"Route Not Found","data":[]}` → gin/echo gateway.
  - HTTP 429 on guessed path that later 404s → nginx rate-limit runs BEFORE routing; **429 ≠ route exists**. Bypass with X-Forwarded-For; if it then 404s, route is absent.
- Status codes: `s=0` success, `s=2 InvalidSign` (initData HMAC only), `s=10` not logged in, `s=12000` bad param, `s=20003` bad phone, `s=20004` account missing, `s=20602` channel missing.

## 2. Extract key + envelope from the bundle
- Download main bundle (multi-MB, ships crypto-js). The key is a 16-char literal beside the AES wrapper:
  `AES.encrypt(x, Utf8.parse("<16ch>"), {iv: Utf8.parse("<16ch>"), mode: ECB, padding: Pkcs7})`.
  Mode is **ECB** → the IV is dead weight; only the key matters.
- Find the interceptor wiring the envelope:
  `requestInterceptors: [params = {c: AES(JSON.stringify(params))}]`
  `responseInterceptors: [data = JSON.parse(AES.decrypt(resp.c))]`.
- No request-wide signature — only the initData/login call is HMAC-signed (`s=2`).

## 3. Replica client — single-pad rule (the live bug)
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
KEY = b"<16ch>"
def enc(o): return base64.b64encode(AES.new(KEY,AES.MODE_ECB).encrypt(pad(json.dumps(o).encode(),16))).decode()
def dec(b): return unpad(AES.new(KEY,AES.MODE_ECB).decrypt(base64.b64decode(b)),16).decode("utf-8","ignore")
```
- **pycryptodome does NOT auto-pad → manual `pad(raw,16)` is correct (single pad).**
- **Node `crypto.createCipheriv` DOES auto-pad by default.** If you also hand-pad there you get
  DOUBLE padding → backend returns `"json unmarshal error"` on every request. In Node use
  `Buffer.concat([c.update(JSON.stringify(obj)), c.final()])` with NO manual pad.
- Other unmarshal triggers: `uid` must be **int not string** (`54692260` vs `"54692260"`); keep
  `common` field order identical to the captured live request (`pkg,platform,token,uid,language,cha,ttclid,trace_id,domain`).

## 4. Get a REAL initData (Telethon RequestWebView)
```python
r = await client(functions.messages.RequestWebViewRequest(
    peer=bot, bot=bot, platform='android', from_bot_menu=False, url='<TMA URL>'))
frag = r.url.split('#')[-1]
init_data = urllib.parse.parse_qs(frag).get('tgWebAppData',[''])[0]
```
- Login: `{"login_type":"telegram","params":{"telegram_webapp_init_data": init_data}, "only_login": False, "pid": <business_id>}`.
- **initData replays fine (not one-shot) and survives concurrent logins** — weaponizable for batch sessions.
  Tampering `user` fields breaks HMAC (`s=2 InvalidSign`), so you can't forge identity — only replay your own.

## 5. Drive real frontend for a live token (puppeteer local chromium)
- `telegram-web-app.js` reads init params from **location hash `#tgWebAppData=...`**, NOT from a
  `window.Telegram.WebApp` mock object. Mock-only injection keeps the app logged out.
- Correct load: `page.goto(TMA + '#tgWebAppData=' + encodeURIComponent(init_data))` →
  auto-login; token lands in `localStorage['token']`, `sessionStorage['tg_logged_in']=1`.
- Token rotates every login and is session-scoped → do authenticated fetches inside the SAME page context.

## 6. Money/logic surface to test first (gambling TMA)
- `/transaction/*`: recharge_channel_list (fixed TRON address, on-chain scan — no callback to forge),
  withdraw_info/wallet_list/channel_list (manual finance + bet-flow + tax tiers + first-withdraw human approval).
- `/game/*`: enter/transfer_back/rebate*/claim; `/vip/info` tiers; `/activity/get` tasks.
- IDOR: uid↔token bound (other uid → s=10). Phone-bind `POST /user/update_info {type:2, phone, verify_code}`
  often accepts ANY code and actually writes `phone` (verify via `/user/info`) — real bypass, repeatable re-bind.
- When money layer is hard, pivot: SaaS vendor leaked via resource host (`source.m-<group>.com`),
  gateway `swagger/` 403, extra ports behind CF return 000 (edge-blocked).

## 7. Field kit (from the umi88 engagement)
- Telethon venv `$HOME/tgenv`, mule `12698203583` (json `./data/tg_12698203583.json`).
- `/usr/bin/chromium` + `puppeteer-core` for TMA driving.
- Evidence dir pattern: `./data/<target>/evidence/` with bundle, live initData/token, API logs, REPORT*.md.
