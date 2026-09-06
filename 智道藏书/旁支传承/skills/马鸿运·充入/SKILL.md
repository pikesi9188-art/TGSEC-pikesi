---
name: 马鸿运·充入
description: "Gambling deposit chain: bind-card/KYC bypass + cert forgery."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, deposit, kyc, payment-chain, whitelabel]
    category: daaixianzun
---

> **马鸿运**
> 鸿运加身命难收，杀机扑面运来救。
> 北原少年福如海，气运比刀更温柔。

# 白标博彩 充值/提现链渗透

## 触发条件
- 博彩站充值需先**绑定金融账户**(银行卡/USDT 钱包) + **提现密码** + KYC 等级,充值走人工审核(上传转账凭证)
- 典型流程: 注册 → 绑卡 → KYC → 充值申请(公司卡/第三方) → 人工审核到账 → 提现
- UI 常见表现: 充值按钮弹"Bind financial account"、金额表单 Next step、凭证上传 Required

## 核心认知
1. **UI 客户端校验可绕过 → 全走 API 层**: 前端表单被卡(客户端正则/隐藏组件/动态导入失败), 不代表服务端校验存在。直接从 JS chunk 逆向出提交对象, 用 curl/Python 逐字段拼 multipart, 往往一次过。
2. **提现密码常在"绑定金融账户"时一并设置** — 找绑卡/绑钱包接口的 `withdrawalCode` 字段, 别单独找提现密码设置接口(参数名反直觉且常被卡)。
3. **充值凭证伪造是白标博彩高频高危洞** — 人工审核渠道的 deposit/apply 常只校验"文件是图片格式", 不校验内容/转账流水/凭证唯一性 → 任意金额 + 任意图片 = 刷单。
4. **同 site 常有第二 API 域名**(`{siteId}{随机}.<平台域>/api`): 无滑块、限流更宽松 → 爆破/枚举走这个入口。
5. **注册 token 多短效**(分钟~小时级): 全接口 `20001 Login failed` = 过期 → 直接重注册拿新 token, 别排查。

## 攻击链(API 层)

### 1. 注册拿 token
- 多数平台: `POST /api/core/member/frontend/register {account,password(明文),registerDomain}` 即注册即登录
- dingyi 系需 verifyKey 链: `login/verify-key/get` → `register/verify {verifyKey}` → `register`(直接 register 报 50006; `verifyKey = floor(random*10^digit)+array[1]+array[3]-array[0]-array[2]` 同登录)
- token 直接 `Authorization: Bearer` 用; 用户 id 连续可估规模

### 2. 绑卡/绑钱包(绕过 UI)
```
POST /api/core/finance/frontend/digital-wallet/v2/add   (multipart/form-data)
  USDT钱包: {walletType:"WALLET", chainTypeId:1(TRC20), walletAddress, withdrawalCode:<6位>}
  银行卡:   {walletType:"CARD",   bankId:<银行id>, branch:"", cardNumber, holder, withdrawalCode}
```
- 银行 id 从 `bank/get {currency}`; 已绑列表从 `digital-wallet/list {walletType:"WALLET"|"CARD"}`
- **提现密码在绑定时一并设置**

### 3. KYC 解锁提现
- 银行卡验证: `kyc-verify-log/apply` multipart `{event:9, walletId:<卡id>}` → status=3, kycLevel 提升(解锁 withdrawal)
- event 枚举取 `kyc-event-enum/get`; event 0(实名)常需本地身份证号校验(如泰 13 位), 失败别死磕, 先打 event 9

### 4. 充值订单生成 + 凭证伪造
```
POST /api/core/finance/frontend/deposit/apply   (multipart)
  文本字段: amount, payChannelId   (公司卡渠道 CARD, 人工审核)
  文件字段: certificate=<图片文件> (段名 certificate, filename 任意)
```
判定清单(全过 = 高危, 可报"充值凭证伪造 → 免费充值/洗钱"):
1. 凭证内容任意: 1x1 透明 PNG 通过?(仅校验图片格式)
2. 凭证可复用: 同一 PNG 连刷多单成功?(无唯一性校验)
3. 金额任意: 只校验 >0?(不核对实际转账流水)
4. 订单自动流转 NOT_REVIEWED→UNDER_REVIEW(进人工审核)
- 订单查询: `deposit-log/page {currency,pageNum,pageSize}`
- 第三方扫码渠道常 60002/卡 KYC 实名 → 别死磕, CARD 人工审核渠道才是伪造目标

### 5. 提现
- `withdrawal/apply {amount,currency,digitalWalletId,withdrawalCode}`; 人工审核通道不可控, 漏洞价值 = 报告素材 + 审核疏漏利用

## 爆破/限流绕过补充
- 第二 API 域名: 无滑块; 20 次/IP 错误计数; `X-Forwarded-For` 伪造可隔离计数(真实 IP 高频仍随机 `50001` 全局节流)
- 登录错误码审计(dingyi 系): 40000=不存在 / 20000=代理·员工禁前端登录 / 40004=密码错(需过滑块) / 50001=限流
- 直连源站(带 Host)绕 CDN/WAF; 端口常仅 80/443/8443(CDN 节点)

## 坑
- 前端上传组件常为**客户端 base64**(compressImg+FileReader), 但服务端要 multipart 文件段: 带 `filename` + `Content-Type: image/png` 二进制, 别传 base64 文本
- 页面可能双渲染(PC+Mobile), 部分按钮 `getBoundingClientRect()` 宽高为 0 — 操作前先查可见性
- SPA fallback: 任意路径 200 且 body==index.html, 用 `cmp a.txt index.html` 区分
- 网关白名单: /api/core /api/platform /api/extra 可达, /api/im /api/promotion 直接 405 — 别浪费
- 浏览器 fetch/XHR hook 刷新即失效(axios 可能走 Service Worker); 注册流程若 UI 提交无响应 = 动态导入 chunk 失败

## 参考实例
- dingyi.io 白标 msg389.com 全链实证: `./data/msg389/FINDINGS.md` + `FINDINGS2.md` + `login_enc.py`(含 register/verifyKey 实现)
- 家族专属技能 `dingyi-whitelabel-gambling-pentest` 存共享目录(default profile)