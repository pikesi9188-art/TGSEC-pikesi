---
name: 星宿·密文
description: "Web SPA encrypted-API reversal (keys, decrypt, client)."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [gambling, web, app-api, encrypt, aes, ctr, sk_encrypt, pentest, js-reverse, crypto]
    category: daaixianzun
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# Encrypted-API Gateway Reversal (web SPA, /app-api/encrypt family)

Use when a **web** (non-miniapp) React/Vue SPA talks to a backend whose responses come back as
opaque base64 blobs under a rewritten gateway path — fingerprints: `/app-api/encrypt/*` returns
base64 strings (not JSON), `*_encrypt.json` variants, a `companycode` header, form-urlencoded
register/login under `/app-api/v/user/*`. Family names in the wild: yudao/ruoyi-vue-pro web
variants, "kaiyuancp" white-labels (`kaiyuancp_v2` passphrase constant, `ic_kaiyuan` logos).
Distinct from TMA/miniapp variants (per-request RSA/AES-ECB + sign envelope) and from
signature-only families (MD5 param signing) — fingerprint first, then pick the protocol.

## Golden rule: the keys are usually PUBLIC config, not crypto to crack

The JS contains a key-fetch function (pattern: `zr()`/`pm()` hitting `sk_encrypt.json` /
`/im-api/common/sk_encrypt`). **Grep the bundle for that fetch, then curl the endpoints directly —
before touching any decrypt code.** On this family the AES keys are served unauthenticated:

```bash
curl -s "https://TARGET/sys-upload/data/json/sk_encrypt.json"        # base64-wrapped JSON
curl -s "https://TARGET/dflt/sys-upload/data/json/sk_encrypt.json"   # /dflt variant (different key!)
curl -s "https://TARGET/im-api/common/sk_encrypt?_t=<ms>"            # {"encodeKey":...,"open":true}
# decode: base64 -> JSON -> .encrypt_key.configValue (16-char ASCII, e.g. "1234567890123457")
```

One key per prefix: `/app-api` uses the root file's key, `/dflt/*` and `/im-api/*` use their own.
Read ALL files — values differ (observed ...57 vs ...55 on one site).

## Verified envelope: AES-128-CTR, key = IV, then gzip

Response = `base64( AES-CTR( gzip( JSON ) ) )`.

- crypto-js call in bundle: `AES.decrypt(cipherParams, key, {mode: ModeCtr, iv: key, padding: NoPadding})`
- key and IV are the **same 16-byte string** (Utf8), counter = full 128-bit big-endian increment
- after CTR decrypt the stream starts with gzip magic `\x1f\x8b`; gunzip → JSON
- Request bodies are plaintext (form-urlencoded) — only responses are encrypted

**Verify with openssl (no pip/pycryptodome needed)** — crypto-js CTR counter == OpenSSL 128-bit
big-endian counter:

```bash
echo '<base64-response>' | base64 -d > raw.bin
openssl enc -aes-128-ctr -d -K 31323334353637383930313233343537 -iv 31323334353637383930313233343537 -in raw.bin -out dec.bin
# dec.bin must start \x1f\x8b; then zcat
```

Python equivalent (pycryptodome): `Counter.new(128, initial_value=int.from_bytes(KEY,"big"))` +
`AES.new(KEY, AES.MODE_CTR, counter=ctr).decrypt(base64.b64decode(resp))` + `gzip.decompress`.

## URL-rewrite interceptor (why /app-api/encrypt 403s are normal)

axios request interceptor rewrites every request when a key exists for the URL:
`/app-api` → `/app-api/encrypt`, `/im-api` → `/im-api/encrypt`, any `.json` → `_encrypt.json`.
- Direct `GET /app-api/encrypt` (bare) returns 403 from nginx — expected; always call the rewritten path.
- The plain (unrewritten) prefix often ALSO works and returns plaintext JSON errors
  (`UC/TOKEN_INVALID` etc.) — use it for fast probe/debug, then switch to the encrypted path.

## Headers & auth

- `Authorization: <token>` AND `token: <token>` (same value, doubled by the interceptor)
- `Language: en|zh...`, `companycode: <hardcoded, e.g. "xgame">` (required; missing → UC/INVALID_COMPANY_CODE)
- optional: `first_open_ip`, `root_proxy_code` (from localStorage), `device: pwa`
- chat endpoints use `accessToken` header + a chat JWT (different from the main token)
- token storage: `localStorage.access_token` (`dafacp_token` for /dflt URLs)
- register/login password is **MD5-hashed client-side** (`he()` = standard MD5 impl); submit
  `password=MD5(p)` + `confirmPassword=MD5(p)`; fields also carry `mode` (QUICK/ACCOUNT/EMAIL/PHONE),
  `version` ("1.0.8.15"-style), `lang`, optional `vCode`/`otp`/`fundPwd`/`intrCode`/`fullName`

## Minified Vite bundle: resolve crypto aliases via chunk exports

Main bundle imports crypto from a `utils-crypto-*.js` chunk:
`import{r as fo, a as tp, A as gs, M as _o, N as go}from"./utils-crypto-D0Surbua.js"` with chunk
exports `export{AES as A, ModeCtr as M, NoPadding as N, ...}`. So `gs`=AES, `_o`=ModeCtr,
`go`=NoPadding. **Read the chunk's export list to name the minified aliases** — fastest path to
algorithm+mode+padding without deobfuscation. Grep `Co=`, `encryptionKey`, `dfltEncryptionKey`,
`getEncryptKeyBaseonRequestUrl` to locate the key manager class.

## High-value unauth endpoints (this family)

- `/sys-upload/data/json/*.json` — sk_encrypt.json (keys), config.json, token.json (payment
  tokens), currency.json, country.json, limit/userLoginLimit.json — all public config
- `/app-api/encrypt/api/install/get` — leaks domain, proxyCode, yourIp, yourUa, device_hash (no auth)
- decrypted `config_encrypt.json` — `system_config` (incl. encrypt_key), `pay_account_config`
  (may include a MasterSecret field), `api_external`, `online_pay_banks`
- `/app-api/encrypt/api/webdomian/getByDomainRequestV3` — returns empty data without token

## Workflow

1. Curl homepage → harvest EVERY `/assets-*/` chunk (Vite) — main bundle + all referenced chunks
2. Grep for key-fetch funcs (`sk_encrypt`, `/im-api/common/sk_encrypt`) → curl key endpoints → keys
3. Grep import/export of the crypto chunk → name algorithm/mode/padding
4. Capture one real response (e.g. `/app-api/encrypt/api/user/info` without token still returns an
   encrypted error body — perfect decrypt test vector) → verify with openssl → gunzip
5. Map endpoints + params from call sites (grep `"/app-api/..."` and the wrapper functions
   `ge(...)`/`oe(...)`); build the Python client (requests + openssl/pycryptodome)
6. Test unauth config leaks; then register/login → token → balance/recharge/withdraw calls

## Files

- `references/ldy1-xgame-session.md`（⚠️本包未含此案例文件，跳过） — verified session (ldy1.xgxxx1.cc, xgame): exact keys,
  full endpoint/param table, leak fields, decrypt recipe output, registration caveats
