---
name: 太白云生·微域盘
description: "Qzino TMA pentest: api.html crypto, initData, upload WAF."
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# Telegram Gambling TMA Pentest (Qzino family)

Use when the target is a **Telegram gambling/betting bot Mini App** — PC28 lottery, slots, fish, USDT deposit/withdraw, task rewards ("综合站"/"棋牌"/"彩票" bots). Covers the Qzino commercial framework (deployed as `qqzonghe/gbzonghe/mymy/timi/kkzh/yongfa/qidian.<domain>` subdomain farms, all behind Cloudflare) and structurally similar gambling TMAs.

## 1. Fingerprint
- HTML `<title>Qzino</title>`, `server_name_session` cookie, `POST /api.html` (disguised API base), Vue3 SPA with `/vue/config.js` + `/vue/index-*.js?v=timestamp`
- Same crypto constants across ALL subdomains of the farm; each subdomain = one bot, shared backend (same bot token family, same initData rejection patterns)
- Static files served from sibling `oss.<domain>` (uploaded content lands here, does NOT execute PHP)
- FOFA: `domain="<farm-domain>"`, `cert="<farm-domain>"` (free quota works for this)
- Related: prior art in `telegram-mini-app-bot-security` skill (initData forgery, webhook) — load both.

## 2. Crypto replication (works for every Qzino deployment)
Extract from main bundle (`/vue/index-*.js`): `Hb` = AES key, `Wb` = sign salt, `Qf` = MD5, `ew=td()` = `/api.html`.
Request recipe (must match exactly, else server rejects sign):
1. `params` (incl. `method`) → sort keys → `s1 = json.dumps(sorted)` (compact, no spaces)
2. `sign = md5(s1 + Wb).hexdigest()` → add `sign` to params → sort keys again → `s2 = json.dumps`
3. `enc = AES-128-CBC(key=Hb[:16], iv=random16).encrypt(pkcs7(s2))` → `payload = base64(iv + enc)`
4. `POST /api.html` body `data=<urlencode(payload)>`, headers `Content-Type: application/x-www-form-urlencoded`, `language: zh|en|tw` (REQUIRED; missing/None breaks some flows, changes error language)
5. Known Qzino constants (verify against current bundle, they rotate per deployment): `Hb=4523E51C8F78D3ED`, `Wb=FA72ACE15FEB1FB2111E9AE1938550DABCCA4E52`

Signatures validate easily — "token 参数缺失"/"未开放" style business errors mean your crypto is CORRECT; "sign" errors mean wrong salt.

## 3. initData auth — SHORT WINDOW workflow (critical)
- Login: `{initData: base64(initData), method: "login"}` → returns `token` + wallet list. Response `code:1` = success.
- **initData from `chat_type=supergroup` is rejected** ("登录验证失败"); `chat_type=sender` (private DM) works.
- **auth_date window is ~1–2 minutes.** Old initData dies fast; each login mints a new token and invalidates prior tokens (single-session). ⇒ **One-shot attack script pattern**: request fresh initData from user, run a script that logs in and fires ALL authenticated tests within ~60s with `time.sleep(0.2)` between calls. Never spread tests across multiple turns with one initData.
- Fresh initData grab (user side): open bot → Mini App → F12 console → `Telegram.WebApp.initData`.

## 4. High-value endpoints (Qzino; full map in references/qzino-api-map.md)
- **Unauthenticated leaks**: `randbet` (count=N) → any player's masked username + bet_amount + win_amount; `lotterylist`/`gamelist`/`gametype`/`playlist` (game lib, payment channels: `dlpay_usdt/okpay_usdt/kkpay_usdt/anony`)
- `myinf` → internal sequential `id` (IDOR surface); `mytask` → task list INCLUDING `receivecode` (claim codes)
- `upwithpass` = set withdraw password: **no old-password check when unset** (setseart=2); requires old password once set (setseart=1)
- `postwithdrawal` needs `withpassword` param + `withtype`; `AnonyPayBot` type takes `address`
- `deposit_anony` → TRC20 USDT address + QR; `deposit_dlpay/okpay/kkpay` → t.me payment links (rate-limited "点击过快" 3s)
- `game_pc28` (gameid,page) → current issue + deadline + history; `betpc28` needs structured `betdata` (format lives in lazy chunk `Pc28Game-*.js` / `play-*.js` — fetch via proxy, direct often 502)
- `web_login`/`web_reg` → "未开放" (disabled) on this family
- `walletoperat` (supplier,btype) → wallet⇄game transfers, rate-limited
- `usersign` daily sign → diamond; `receivetask` (taskid, receivecode) → claim rewards; `ceakertaskqd` checks "个性签名"

## 5. Arbitrary file upload (`upflie`) — no token needed
- `upflie` takes ONLY `method` + `sign` (no token!) — multipart/form-data fields `data` (encrypted payload) + `image` (file), fetch to `/api.html`, header `language`
- App-layer extension whitelist: jpg/jpeg/png/gif/webp only ("图片格式不支持，仅限…")
- **WAF**: body containing `<?php`, `<?=`, `<html>` → CF 502. `<script language="php">…</script>` **bypasses the WAF** and uploads fine.
- **But**: files land on static `oss.<domain>/uploads/<date>/<md5>.ext` served as `image/png` → no PHP execution → no RCE via this alone. Value: phishing asset hosting, storage abuse, stored-XSS if a target ever serves HTML.
- **Upload storm → IP fail2ban**: >~10 uploads in a burst bans your IP at the ORIGIN (all CF requests return 502, even GET /; `r.jina.ai` still returns 200 ⇒ your IP banned, site alive). Ban lasts 10–60+ min; no port 2052/8443 escape; cooling alone is unreliable.

## 6. IP-ban evasion (user has proxy pool)
- Detect ban: CF 502 on everything direct + r.jina.ai 200 on same URL.
- Fix: user-provisioned **SOCKS5** proxies (`IP:port:user:pass`; test `socks5h://` FIRST — HTTP proxy assumption fails on these), e.g. port 50101 with auth.
- **Target bans datacenter IPs broadly**: of 10 proxies, ~1 survives (others get 502 too). Test each proxy with a GET; pin the survivor in the client.
- PySocks install in this env: `uv pip install --python python3 pysocks` (venv has no pip module).
- Rate discipline: even through a good proxy, keep `time.sleep(0.2–3)` between API calls and NEVER burst the upload endpoint.

## 7. Zero-dependency user-side scripts
When the user's home machine must run tests (their IP is clean / they hold the fresh initData), ship a pure-stdlib script: `scripts/pure_aes.py` (NIST-validated AES-128-CBC, no deps) + urllib. Verify pure-Python AES against pycryptodome BEFORE shipping. User Windows Python 3.13: long initData strings must be passed as one arg / file, not shell-quoted.

## 8. Pitfalls
- `data=` must be URL-encoded, not raw base64.
- `upflie` response `code:1` returns `filePath` — always fetch the file afterward to confirm storage & content-type.
- Don't re-login between phases — each login kills the previous token; do everything in one script.
- `chat_type` in initData decides acceptance — ask user to grab initData from the private-chat Mini App, not a group.
- Some methods (walletoperat) are rate-limited with "操作频繁" — space probes.

## References
- `references/qzino-api-map.md`（⚠️本包未含此案例文件，跳过） — full 50-method endpoint map with params + observed responses
- `scripts/pure_aes.py` — verified pure-Python AES-128-CBC (NIST vector + roundtrip tests, zero deps)
- `scripts/qzino_client.py` — reusable Qzino API client: sign + AES + proxy pool + one-shot login
