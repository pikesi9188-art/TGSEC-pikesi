---
name: 星宿·密文
description: >-
 授权目标上 Web SPA 加密网关：/app-api/encrypt 返回 base64、sk_encrypt.json
 未授权密钥、companycode 头、kaiyuancp 白标。
  
  window.goEncrypt 浏览器 oracle 走 tg-cloud-panel 第四族，禁止先拆 WASM。
 TMA 每请求 RSA 信封走 yudao-appapi-pentest；仅 MD5 签名走 gambling-api-crypto-reversal。
 旧名 `encrypted-api-gateway-reversal` / `encrypted-api-gateway-reversing` 已并入本卡。
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# 加密 API 网关逆向

```bash
python3 炼蛊房/yudao_appapi_probe.py --base https://授权站 --case <案>
```

## 四刀

1. **分流** — 页有 `window.goEncrypt` / `/main.wasm` → **立刻** `tg-cloud-panel` 第四族（浏览器 oracle），禁止先拆 WASM  
2. **先钥后算法** — 先 curl：  
   `/sys-upload/data/json/sk_encrypt.json`  
   `/dflt/sys-upload/data/json/sk_encrypt.json`  
3. **解密** — 按 bundle 选 AES-CBC 或 CTR（常见 key=iv）；解开应见 gzip `\x1f\x8b` 或 JSON  
4. **登录** — 客户端 MD5 密码 + `companycode` 头；明文 `/app-api/*` 常回错误码可探活

TMA 每请求 RSA 信封 → `yudao-appapi-pentest`。只 MD5 签名、无 blob → `gambling-api-crypto-reversal`。

不要先猜算法再找密钥。真源：`传承/芋府·微域.md` §3
