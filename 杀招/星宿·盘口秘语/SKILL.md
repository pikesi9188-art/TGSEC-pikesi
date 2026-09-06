---
name: 星宿·盘口秘语
description: "博彩 API 签名/加密逆向：JS bundle 抽密钥、WebSocket 加密帧重放、HMAC/AES/RSA 协议复刻。触发：签名字段 sign/token/encrypt、加密 WS 帧、前端 bundle 含密钥常量。"
version: 1.0.0
license: MIT
metadata:
    tags: [gambling, api, crypto, signature, websocket, pentest]
    category: daaixianzun
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# Gambling Platform API Crypto & Signature Reversal

国密 / js-websocket / webpackChunk → `spa-protocol-reverse`。sk_encrypt 网关 → `encrypted-api-spa`。本卡只管盘口 MD5/HMAC + bundle 里的 VITE/VUE 密钥。

## Trigger
Gambling/entertainment platforms (Vue/Nuxt/React SPA + Node/PHP/Laravel backend) where:
- API requests carry a `signature` field (MD5 param+secret), or
- responses have `"encrypted": 1`, or
- WebSocket frames are base64/AES blobs.
Also use for white-label families where one JS bundle serves 30+ domains (GoFun/66U/Lucky/xihu, 99娱乐, etc.).

## Core insight
These platforms ship the **signing secret and AES key in the frontend bundle** via Vite env vars. One bundle + key leak = full API forgery + full traffic decryption. White-label families reuse the same bundle across all member sites — one key dump compromises the whole family.

## 1. Recon & bundle harvesting
1. `curl` the homepage, grep `src="..."` for all JS. Download EVERYTHING: main bundle plus every `/assets/*.js` or `/_nuxt/*.js` chunk. For Nuxt also fetch `/_nuxt/builds/meta/<buildId>.json`; for Vue CLI check `webpackChunk` global at runtime.
2. Grep bundles for keys and crypto:
 - `VITE_HTTP_SINGKETY`, `VITE_SOCKET_SINGKEY`, `VUE_APP_KA`, `VUE_APP_KS` — these are REAL secrets.
 - `handleParam`, `Utf8.parse`, `AES.encrypt/decrypt`, `mode.ECB`, `pad.Pkcs7`, `md5` — locate sign/encrypt code.
 - `dealKey` = hex-pair→ASCII decoder: `s.split(/(\w\w)/g).filter(Boolean).map(x=>String.fromCharCode(parseInt(x,16))).join('')`. Hex-encoded keys are decoded with this.
3. API discovery: grep `url:"/m_api/..."`, `"/api/..."`, `"/web_api/..."`. JWT `iss` field leaks the real API host (e.g. `http://api.xinaoman.com/m_api/userLogin`).
4. Unauth config endpoints worth probing: `/api/getPackagingConfig` (needs master_id+shop_id — leaks agent_url, web_domain, app downloads), `/web_api/systemInfo`, `/m_api/systemInfo` (leaks ws_host, live-stream URLs, configItem).

## 2. Signature forgery
Pattern (verified on xihu02.vip and rich.xinaomengame.com):
```
signature = MD5(sorted "k=v&k2=v2" + SECRET)
body also carries is_tg=1 and time=<ms timestamp>
nested objects serialized compact JSON (no spaces)
```
```python
def sign(data):
 d = {k: v for k, v in data.items() if v is not None}
 s = "&".join(f"{k}={d[k] if isinstance(d[k], str) else json.dumps(d[k], separators=(',', ':'))}" for k in sorted(d))
 return hashlib.md5((s + SECRET).encode()).hexdigest()
```
Call: `body = {**params, 'is_tg': 1, 'time': int(time.time()*1000)}; body['signature'] = sign(body)`.

Pitfalls:
- **Bearer prefix**: tokens are stored as `"Bearer" + JWT`, sometimes WITHOUT the space. `replace('Bearer ','')` silently fails → token keeps prefix → 401/50014. Use `replace('Bearer','').strip()` and verify per site. One site here required Authorization WITHOUT Bearer at all.
- Required headers: `Mid: <master_id>` (e.g. 31 main, 124202 VIP), `Language: zh-rCN`. Missing Mid → 50014.
- Error-code triage: `50014 请重新登录` = token invalid/unauthorized; `签名错误` = signature wrong. Debug by which error you get.

## 3. WebSocket decryption
- Frame = `base64(AES-128-ECB(Pkcs7, key=KA))` of JSON `{"mode":..., "data":..., "client_id":...}`.
- Handshake: `init` → ok+client_id; `login` `{uid, shop_id, ws_token}` → later modes work; then `heart`, `balance`, `deskList` (→ login/uid or shop_player online count), `table`/`joinDesk` `{desk_id}` → `game_result` (road-history leak, enumerate any desk).
- Unknown mode → server replies 404/`Undefined` or `logout` (socket closed) — after logout, re-init + re-login before next probe.
- Some mode names map server-side to other handlers (mode "desk" returned balance here) — enumerate candidates, don't assume.
- Python stack: `python3 -m pip install websocket-client pycryptodome` (system python3 lacks these).

## 4. Trial / guest accounts
- `trialLogin` / `genOnlyAccount` / `游客登录` often have NO captcha → infinite trial accounts (token + ws_token + 2000 chips). Great for API/WS access testing.
- Trial accounts are blocked from withdraw/deposit (`试玩账号不可提现与充值`) — money-flow tests need a real account.
- Behavior captcha (`getBehaviorVerifyCode` PNG + `behaviorVerify` {tn_r, key}) validates strictly — fuzzing it wastes time. Use a real session or solve properly.

## 5. IP-bound tokens (critical)
- **Real-account HTTP tokens are bound to the login IP**: calling from another IP → 50014. Trial tokens are NOT bound. WS `ws_token` is NOT bound even for real accounts.
- X-Forwarded-For / X-Real-IP / Client-IP spoofing does NOT bypass (server uses real socket IP).
- US SOCKS proxy pools get blocked by Cloudflare (HTML challenge page) on these CF-fronted APIs — don't rely on them.
- **Workaround for IP-bound ops**: hand the user a self-contained browser script (inline MD5 + sign + fetch reading token from `sessionStorage['store'].userInfo.token`) to run in their logged-in browser.
 - **Deliver as FILES via MEDIA:, not inline code** — long inline code gets truncated by chat (`...` → `Uncaught SyntaxError: Unexpected token '...'`). Split into part1 (MD5 function) + part2 (executor) so each paste is small.
 - Console output truncates long strings to `abc...xyz` — retrieve via 100-char slices, or have the user paste the JSON (files/notepad OK).

## 6. Account enumeration (error-message oracle)
Login endpoints distinguish:
- `Robot verification failed` / captcha demanded for a specific account = **account exists** (may be captcha-gated, not brute-forceable via API)
- `Wrong account or password` = not exists
- `Please confirm that all required fields are entered` = missing field
Enumerate real accounts; gate brute force on whether GeeTest is required.

## 7. Reusable observations
- Stored XSS: `update/info` nickname accepts `<svg onload=...>` verbatim; chat message snapshots embed `user.nickname` → XSS reaches chat renderers (and likely admin panels).
- 2FA secret leak: `/user/2fa/take` + `/user/detail` return `google2fa_secret` + otpauth URI → TOTP forgeable, 2FA bypassable.
- `paymentChannels` returns mch_id/mch_key (payment merchant secret leak).
- Python urllib: set `os.environ["NO_PROXY"]="*"` before imports or proxy env vars break DNS resolution.
- JWT is HS256 with `prv` field (Laravel Passport/Sanctum); its key is usually a separate APP_KEY, NOT the leaked KS/KA — don't claim JWT forgery until you test the leaked keys against it.

## 8. Files
- 本库无此外门 `scripts/signed_api_client.py`。按本卡填 SECRET/KA 后用 curl / 短 Python 重放。
- `templates/browser_signed_exec.js` — self-contained browser executor (MD5 + sign + fetch) for IP-bound sessions; split at the marker line before sending to the user.
- 个案附件未入库（原 references/xihu-gofun8-session.md） — session detail: keys, endpoints, desk IDs, findings for xihu02.vip (66U/Lucky) and GoFun8.

## Pitfalls recap
- Confirm the target's REAL entry point (bot miniapp URL, actual web domain) before brand-name FOFA recon — brand search can hit a different platform under the same name.
- Cloudflare APIs need a full browser UA + Origin/Referer; raw curl/urllib gets "Attention Required" or empty responses.
- System python3 lacks Crypto/numpy — always use `python3`.

## 真源

- 手法：`传承/星宿·秘语.md`
- 工具：`python3 炼蛊房/hall_crypto.py --help`
