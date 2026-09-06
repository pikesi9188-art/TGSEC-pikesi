---
name: 商燕飞·曼五
description: "打M8/曼巴体育家族(m8ty.vip/manba888): X-Ca签名+AES+RSA加密API, 滑块验证码破解。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, manba, m8, x-ca, rsa, aes, captcha, whitelabel]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# M8 / 曼巴体育家族 渗透 (m8ty.vip / manba888.com)

## 触发条件
- 目标: m8ty.vip (M8), www.manba888.com (曼巴体育), manba123.com (国内, 铁律不碰), manba2.com 家族
- 特征: SPA 首页 title=M8/曼巴体育, `/assets/index-*.js` bundle, `/pc-api/*` API 前缀, CF 兜底
- 关联: 游戏平台 pc.29ygt0j.com:9002 (裸IP 154.19.144.112), user-pc-new.gdhwgroup.com (CloudFront)

## 加密签名体系 (全复刻, 已验证)
- **X-Ca-Token** = MD5(base + secret), secret = `"syb"` (JS 变量 rL)
  - base = `<timestamp>|<nonce>|<secretKey>` (GET/空 body)
  - base = `<JSON(body)>|<timestamp>|<nonce>|<secretKey>` (非空 body, JSON.stringify 无空格)
- **secretKey** = getSecretKey(uuid, timestamp), uuid = mb-device-id header 值
  - hash2d(s): h=MD5(s); `x = BigInt("0x"+h[:16]) % width`, `y = BigInt("0x"+h[16:32]) % height`
  - width=50x50 keymap (JS 变量 wd/id, 从 bundle 提取 JSON), getKeyByIndex(t,n)=keymap[t%50][n%50]
  - getSecretKey(a,b) = 4 hash 拼 keymap: a, b, a|b, b|a
- **Payload 加密** (fL→dU): body = AES-256-ECB(base64), key = `WordArray.random(16).toString()` 的 hex(32字符) UTF-8 后 32 字节; `X-Api-Encrypt` header = RSA-2048 (jsencrypt PKCS1v1.5) 加密同一个 32-hex 字符串
- **必带 header**: terminal:1(pc)/4(h5), mb-device-id=uuid, time-zone, Accept-Language, fb-pixel-id, tt-pixel-id; h5 另加 client-app:1 且 URL 尾部加 ?t=<ms>
- nonce: 30 字符, 字符集 `useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict`, `n4[byte&63]`

## ★ 最坑的复刻陷阱 (浪费数小时)
> 前端 hash2d 用 BigInt 精确取模。Python `int(hex,16)%n` 是**正确**的。
> 但用 Node 写对照脚本时, 若照抄 JS 源码的 parseInt 会因 >2^53 精度损失产生**假性不匹配**。
> 正确做法: Node 对照也必须用 BigInt; Python 直接用 int。两者精确取模输出一致。
> 用 Node+jsencrypt+CryptoJS 做加密对照可精确验证 AES/RSA 输出是否一致。

## 快速定位重放错误 (三态判别)
对同一请求用 DUMMY `X-Api-Encrypt` 头 (如 base64 "AAAA"):
- **code:500 系统繁忙** → 服务端尝试解密失败 → 你的 RSA/AES 加密错
- **code:431 Invalid token** → 解密成功但签名/内容校验失败 → X-Ca-Token (secretKey/secret/nonce) 错
- **400 未包含加密标头** → 头缺失/格式错

隔离签名: 先确认**未加密** GET (system/customer/get) 返回 code:0 → 签名正确; 再差分加密侧。

## 滑块验证码 (blockPuzzle, 全自动破解)
1. POST /pc-api/system/captcha/get {captchaType:"blockPuzzle"} → repData{originalImageBase64, jigsawImageBase64, token, secretKey}
2. 图像识别缺口 x (cv2 边缘+模板匹配, 310x155 图), ne = x*310/width 归一化
3. check body: pointJson = AES-ECB(secretKey) 加密 {x:ne, y:5}; token 用原 token
4. repCode 0000=过; 6111=失败(验证码作废须重新 get); 6110=过期
5. 失败即重试循环, 通常 ≤7 轮命中; 识别不稳时在浏览器内多次拖不同候选 x
6. login 的 captchaVerification = AES 加密 `${token}---{"x":..,"y":5}` (前端 $emit success 构造)

## 资金面 (高价值)
- **/pc-api/game/plat/withdraw 校验宽松**: 负值/零/超大/字符串/无gameId 全返回 code:0 true (从三方场馆提回主钱包, 余额0也静默成功) — 充值后验证负额/超提可利用性
- /pc-api/game/plat/transfer 严格: 金额>0, 负值/参数缺失拒绝 (无篡改面)
- 绑卡/钱包接口全在 **h5 app-api** (terminal:4 + client-app): addMemberBank/addUsdtAddress/addAlipayAccount 等 40+ 端点; h5 需独立 uuid+userToken 会话
- 支付下单仅 getFirstRechargeOrder (查询型), 主充值流程在 APK 内

## 资产发现
- APK: download.m8ty.vip/m8_apk/*.apk (加壳 com.manba.upan.all, 需移动 UA 下载)
- 域名下发: giteem8.{cowxbp,of8gae,v21xro}.com/m8_domain_a_v*.json (RSA 密文, 密钥在壳内)
- 正式后端: api-syb.manba2.com (nginx 507), api.manba2.com (IP白名单403, XFF 无效)
- TG bot: 8789236256; 游戏平台 WASM 密钥 getHttpKeyByEnv/getDecryptKeyByEnv
- 家族域: m8ty.{vip,xyz,clu8,mobi,net,online,pro,world}; 兄弟站 manba888.com (200 可达)
- S3: backendstatic.s3.a1.amazonaws.com (支付/银行 logo)

## Pitfalls
- h5 域签名校验更严: pc 会话 token 不能用于 h5 (需 h5 独立 uuid); 但 pc 域 + h5 头组合可用
- 加密接口全 Invalid token 排查: 先做三态判别, 别在 key 矩阵上瞎试
- manba123.com 为国内站 → 铁律不碰
- 浏览器会话导航后 JS 重置但 localStorage 保留: 每次导航后重装 XHR hook 再触发操作
- FOFA 余额不足时用 certspotter 查证书子域 (api.m8ty.vip 独立证书暴露后端)