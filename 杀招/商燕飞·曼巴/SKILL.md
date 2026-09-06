---
name: 商燕飞·曼巴
description: "打M8/曼巴体育家族(m8ty.vip/manba888): X-Ca-Token签名链+AES/RSA加密API复刻、滑块验证码破解、h5端点资金面。"
version: 2.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, m8, manba, x-ca, rsa, aes, captcha, whitelabel]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# M8 / 曼巴体育家族渗透 (m8ty.vip / manba888.com)

## 触发条件
- 目标含 m8ty.vip / m8ty.{club,mobi,net,online,pro,vip,world,xyz} / manba888.com(曼巴体育) / manba2.com
- 前端 Vite SPA + `/pc-api/` 前缀 API + Cloudflare
- manba123.com 为国内站 → **铁律不碰**

---

## 1. 完整加密 API 签名体系（全密钥前端泄露）

### X-Ca-Token 签名
- `X-Ca-Token = MD5(base + "syb")`，secret 变量 `rL="syb"`
- **base 组成**：
 - GET / 空 body：`timestamp|nonce|secretKey`
 - POST 非空 body：`JSON.stringify(body)|timestamp|nonce|secretKey`（无空格）
- `secretKey = getSecretKey(uuid, timestamp)`（cL 函数）
 - `hashStringTo2D(s)`: h=MD5(s)；`x = BigInt("0x"+h[:16]) % 50`，`y = BigInt("0x"+h[16:32]) % 50`
 - keymap 从 bundle 正则 `wd=(\[\[.*?\]\])` 提取（JSON 50×50 矩阵）
 - secretKey = 4 段 hash2d 结果拼接：hash2d(uuid)、hash2d(ts)、hash2d(uuid|ts)、hash2d(ts|uuid)
- **签名头**：`X-Ca-Timestamp: <ms>` | `X-Ca-Nonce: <30位随机>` | `X-Ca-Token: <MD5(base+"syb")>` | `X-Ca-Key: <任意值（可省略）>`
- **业务头（必须）**：`terminal:1`（PC）/ `terminal:4`（h5）、`mb-device-id`（localStorage uuid）、`fb-pixel-id`、`tt-pixel-id`、`time-zone`、`Accept-Language`
- h5 额外：`client-app:1`，URL 尾加 `?t=<ms>`（时间戳防缓存）

> ★ **BigInt 精度陷阱**：Python `int(hex,16)%50` 精确；Node.js 用 `parseInt` 会因 >2^53 精度损失产生假性不匹配。对照脚本 Node 侧必须用 `BigInt`。

> ★ **空 dict 坑**：axios 对 `{}` 不发 body 且按空签名；Python 显式发 `{}` → `431 Invalid token`。POST 无参数时不要发 body。

### 登录 / 敏感接口额外加密（fL 函数）
```
t = WordArray.random(16).toString() # 32字符 hex
encryptedData = AES-256-ECB(JSON.stringify(payload), Utf8.parse(t)) # base64 → body
encryptedKey = RSA-2048-PKCS1v1_5(t) # 加密 hex 字符串 → X-Api-Encrypt 头
```
- 公钥变量 `oL="MIIB..."`；AES 共享 key 默认 `XwKsGlMcdPMEhR1B`
- ⚠️ **遗留坑**：login/register/set-pay-password Python 复刻仍 `431 Invalid token`（JSEncrypt 字符串处理细节偏差）。可靠路径：浏览器已登录会话 + XHR hook 抓真实加密请求对照。

---

## 2. 三态错误快速判别

对同一请求先用 DUMMY `X-Api-Encrypt` 头（如 base64 "AAAA"）：

| 响应 | 含义 |
|---|---|
| `code:500 系统繁忙` | RSA/AES 加密错，服务端解密失败 |
| `code:431 Invalid token` | 解密成功但签名错（X-Ca-Token/secretKey/nonce） |
| `400 未包含加密标头` | 头缺失或格式错 |
| `431 Missing required params` | 缺 `terminal:1`（最常见遗漏） |
| `401 账号未登录` | 无有效 Bearer token |

隔离签名：先确认**未加密** GET（`system/customer/get`）返回 `code:0` → 签名正确；再差分加密侧。

---

## 3. blockPuzzle 滑块验证码（可编程破解）

1. `POST /pc-api/system/captcha/get {"captchaType":"blockPuzzle"}` → `{originalImageBase64, jigsawImageBase64, token, secretKey}`
 - captchaType 必须是字符串 `"blockPuzzle"`，数字 "1"/"2" 返 500
2. 图像识别缺口 x（cv2 边缘 + 模板匹配，310×155，右侧半区优先）
3. `ne = 缺口x × 310 / imgWidth`（归一化）
4. check body：`pointJson = AES-ECB(secretKey, JSON.stringify({x:ne, y:5}))` **y 固定 5**；token 用原 token
5. `repCode: 0000`=过；`6111`=失败（**验证码立即失效，须重新 get**）；`6110`=过期
6. 失败即重试整个 get→solve→check 循环，通常 ≤7 轮命中
7. login 的 `captchaVerification = AES 加密 "${token}---{\"x\":...,\"y\":5}"`

---

## 4. 关键端点（pc-api / h5 app-api）

| 类型 | 端点 |
|---|---|
| **未授权（PC）** | `system/customer/get`、`game/info/getLobbyGameList`、`member/auth/getVerifySwitch`、`system/captcha/get|check`、`game/plat/withdraw`（**校验极宽松，见下**） |
| **需 token（PC）** | `member/user/get-userInfo`（POST 空 body）、`game/plat/getUserCompanyBalance`、`system/notice/queryNoticeListByPage`、`member/user/avatarList`、`game/plat/getGameUrl` |
| **加密接口** | `member/auth/login|register`、`member/user/set-pay-password|update-password|change-password-*`、`game/plat/transfer|withdraw` |
| **h5 app-api（terminal:4）** | `member/bank/addMemberBank`、`addUsdtAddress`、`addAlipayAccount` 等 40+ 绑卡/钱包端点；需 h5 独立 uuid + userToken 会话（PC 会话不可复用） |

> ★ **资金面**：`/pc-api/game/plat/withdraw` 校验宽松——负值/零/超大/字符串/无 gameId 全返 `code:0 true`（从三方场馆提回主钱包，余额 0 也静默成功）；充值后测负额/超提可利用性。

---

## 5. 家族资产

| 资产 | 位置 |
|---|---|
| 主域族 | `m8ty.{club,mobi,net,online,pro,vip,world,xyz}` |
| 正式后端 | `api-syb.manba2.com`（无 IP 白名单，nginx 507 运维事故）；`api.manba2.com`（IP 白名单 403，XFF 无效） |
| 兄弟站 | `manba888.com`（曼巴体育，200 可达，同套加密 key） |
| APK | `download.m8ty.vip/m8_apk/m8-*.apk`（安欣加固 com.manba.upan.all，移动 UA 下载 102MB） |
| 域名下发 | `giteem8.{cowxbp,of8gae,v21xro}.com/m8_domain_a_v*.json`（2048bit RSA 密文，密钥在壳内） |
| TG Bot | `8789236256`（h5 端 TG Mini App） |
| 游戏平台 | `pc.29ygt0j.com:9002`（裸 IP `154.19.144.112`，非 CF）；`user-pc-new.gdhwgroup.com`（CloudFront 403） |
| WASM 密钥 | `getHttpKeyByEnv/getDecryptKeyByEnv`；release key=`015CCB80A680E129`，keyid=`probinpjms7rfm26` |
| S3 | `backendstatic.s3.a1.amazonaws.com`（支付/银行 logo） |

FOFA 余额不足时用 `certspotter` 查证书子域（`api.m8ty.vip` 独立证书暴露后端）。

---

## 6. Pitfalls

- h5 域签名校验更严：PC 会话 token 不能用于 h5（需 h5 独立 uuid）；PC 域 + h5 头组合可用
- 加密接口全 `Invalid token`：先三态判别，别在 key 矩阵上瞎试
- 浏览器会话导航后 JS 重置但 localStorage 保留：每次导航后重装 XHR hook 再触发操作
- 空 dict 参数不发 body：axios 默认不发，Python 显式发会签名不一致

---

## 真源

- 手法：`传承/商心慈·白标.md`
- 工具：`python3 炼蛊房/gambling_family_probe.py --family m8 --base https://授权站 --case <案卷>`
