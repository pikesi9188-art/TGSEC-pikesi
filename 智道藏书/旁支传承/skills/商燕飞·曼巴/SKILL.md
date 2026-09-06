---
name: 商燕飞·曼巴
description: "打M8/曼巴体育家族(m8ty.vip)时使用: X-Ca-Token签名链, 滑块验证码破解, 加密API复刻。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, m8, manba, crypto, captcha]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# M8/曼巴体育家族渗透 (m8ty.vip)

## 触发条件
- 目标含 m8ty.vip / m8ty.{club,mobi,net,online,pro,vip,world,xyz} / manba888.com(曼巴体育) / manba123.com / manba2.com
- 前端 Vite SPA + `/pc-api/` 前缀 API + Cloudflare

## 核心成果 (本家族已打通)
### 1. 完整加密 API 签名体系 (全部密钥前端泄露)
- 请求头链: `X-Ca-Timestamp` + `X-Ca-Nonce` + `X-Ca-Token` + `X-Ca-Key`
- `X-Ca-Token = MD5(a + "syb")`; a 组成:
  - GET/空body: `r|i|o`
  - POST带body: `JSON.stringify(body)|r|i|o` (无空格)
  - r=ms时间戳, i=30位随机nonce, o=getSecretKey(uuid, r)
- `getSecretKey(uuid, ts)` (前端 cL): 4× hashStringTo2D_MD5 查 50×50 keymap → 拼4段
  - hashStringTo2D: `int("0x"+md5hex[:16],16)%50` 为 x, `md5hex[16:32]` 为 y
  - keymap 从 JS `wd=[[...]]` 提取 (正则 `wd=(\[\[.*?\]\]);class`)
- **必需 header `terminal:1`** — 缺失时所有接口(含GET)返回 `431 Missing required params`, 排查半天
- 其他必需: `mb-device-id`(localStorage uuid, 每次页面加载会变, 从会话抓), `fb-pixel-id`/`tt-pixel-id`(可空), `time-zone`, `Accept-Language`
- **空 dict 参数不要发 body**: axios 对 `{}` 不发 body 且按空签名; 发送 `{}` → `431 Invalid token`

### 2. 登录/敏感接口加密 (fL)
```
t = WordArray.random(16).toString()      # 32字符hex
encryptedData = AES-256-ECB(JSON.stringify(payload), Utf8.parse(t))  # base64 → body
encryptedKey  = RSA-2048-PKCS1v1_5(t)    # 加密hex字符串 → X-Api-Encrypt 头
```
- body=encryptedData(base64), 头 `X-Api-Encrypt`=encryptedKey; 签名用 JSON.stringify(encryptedData) 即带引号字符串
- 公钥从 `oL="MIIB..."` 提取; AES共享key `XwKsGlMcdPMEhR1B`(Mc函数默认参数)
- **遗留坑**: Python复刻后 login/register/set-pay-password 仍 `431 Invalid token` = RSA层细节偏差(可能JSEncrypt的字符串处理), 未最终突破。用浏览器已登录会话 XHR hook 抓真实加密请求对比是可靠路径

### 3. blockPuzzle 滑块验证码 (可编程破解)
- captchaType 字面量是 `"blockPuzzle"` — 数字 "1"/"2" 返回 500 系统繁忙
- `captcha/get {captchaType:"blockPuzzle"}` → `{originalImageBase64, jigsawImageBase64, token, secretKey}`
- check: `pointJson = AES-ECB-128(JSON.stringify({x:ne,y:5}), secretKey)` base64; **y固定5**
- ne = 缺口x像素 × 310 / imgWidth (图310宽, 用模板匹配+边缘检测找x, 右侧半区优先)
- **一次失败即失效** (6111验证失败 → 6110验证码失效), 必须 get→solve→check 循环, ~7轮内命中 repCode 0000
- 前端 x 计算: `ne = 滑块移动px × 310 / imgWidth`; 拖到 `移动px = ne`

### 4. 家族资产
- 域族: m8ty.{club,mobi,net,online,pro,vip,world,xyz}(7个, 全CF), m8ty.vip 主站
- 正式后端: `api-syb.manba2.com`(nginx 507存储错误=运维事故, 无IP白名单), `api.manba2.com`→/web(IP白名单403, XFF无效), manba123.com(国内403)
- 兄弟站 manba888.com (曼巴体育, 200可达, 同套加密key)
- APK: download.m8ty.vip/m8_apk/m8-*.apk (com.manba.upan.all, 安欣加固StubApp; 移动UA可下载102MB)
- 域名下发: giteem8.{cowxbp,of8gae,v21xro}.com/m8_domain_a_v*.json (2048bit RSA密文, 密钥在壳内未解)
- TG bot: 8789236256 (h5端 telegram-web-app.js = TG Mini App)
- 游戏平台: pc.29ygt0j.com:9002 → 裸IP 154.19.144.112 (htechcdn, 非CF!); user-pc-new.gdhwgroup.com (CloudFront 403)
- 游戏平台 WASM密钥: getHttpKeyByEnv/getDecryptKeyByEnv, release key=015CCB80A680E129, keyid=probinpjms7rfm26
- 后端URL规则: `https://gateway.<domain>/game-http/`; 接口 loadConfig/list?platformType=1, player/getPlayerSetting?playerId=
- getGameUrl(需token) 返回游戏跳转URL含 token/api/sessionId
- S3: backendstatic.s3.a1.amazonaws.com (支付/银行logo, 尝试 list-type=2 未确认)

## 关键端点 (pc-api)
- 未授权: system/customer/get, game/info/getLobbyGameList, member/auth/getVerifySwitch(GET), system/captcha/get|check
- 需token: member/user/get-userInfo(POST空body), game/plat/getUserCompanyBalance, system/notice/queryNoticeListByPage, member/user/avatarList, system/domain-config/getDomain, game/plat/getGameUrl
- 加密: member/auth/login|register, member/user/set-pay-password|update-password|change-password-*, game/plat/transfer|withdraw

## 错误码速查
- 431 Missing required params = 缺 terminal:1 / 签名头错
- 431 Invalid token = 加密体解不开(RSA/AES) 或 cv过期 或 空dict发body
- 400 请求未包含加密标头 = 缺 X-Api-Encrypt 头
- 401 账号未登录 = 无有效 Bearer token
- 500 系统繁忙 = 参数值错(如 captchaType 数字)

## 交付
- 用户token(浏览器登录后localStorage token/refreshToken/uuid 发来) → 直接 Python 客户端全接口访问
- 加密接口需真实请求对照: 给用户浏览器XHR hook脚本抓取真实加密请求
