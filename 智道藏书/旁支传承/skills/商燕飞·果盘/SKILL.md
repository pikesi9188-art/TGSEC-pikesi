---
name: 商燕飞·果盘
description: "打AKS包网家族(gofun8/n1s168)时使用: 免验证码注册→2FA TOTP→游戏token→rank泄露。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, whitelabel, aks, laravel, usdt, trc20]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# AKS 包网家族渗透（GoFun / n1s168 / 99Ubit / allin8168）

## 触发条件
- 目标为 AKS 包网白标博彩家族，指纹:
  - 主站标题含 "AKS包網/AKS包网"（如 www.n1s168.com）
  - API 路径 `/api/v1/user/register`、`/api/v1/web/rank/withdrawal`、`/api/v1/game/login`
  - 域名 n1s168/n1s189/no1system/n1smw/aksvn/aksmy/aksgaming
  - 东京机群 `14.128.0.0/24`（AKS 网关，各 IP x 端口 nginx 400）
- 后端 Laravel，前端 Nuxt/Vue3（chunk 哈希共享 = 一个租户漏洞全平台通用）

## 核心架构认知
1. **多租户白标包网**: gofun8.com(web_id=30002) / n1s168.com(web_id=2) / 99Ubit(60199) / allin8168(30656) 全是 AKS 一个后端的不同租户。JWT 带 aud=租户ID，跨租户 token 报 "Site read error"（不是 "Please log in"，说明结构同源）。
2. **托管钱包模式**: 充值地址由平台分配（`/api/v1/deposit/activation` 返回每用户 TRC-20 地址=公钥），钱包私钥存后端 DB，API **无私钥导出**。拿私钥必须后台/DB。
3. 前端 JS chunk 是金矿: `grep -o 'https://[a-z0-9.-]*'` 找 API 域；`dev.n1s168.com` 前端指向 **api.aks18.com**（AKS 核心后端域名）。

## 攻击链（已验证）

### 1. 免验证码注册入口（关键突破口）
- `dev-api.gofun8.com` 和 `api.n1s168.com` 的 `register_google_verify=false` → 直接注册拿 JWT
- 生产 `api.gofun8.com` 的 `register_google_verify=true`（hCaptcha, sitekey `25221736-187a-4fe8-92d2-2c9024c6a608`）挡住
- 注册 payload: `{superid, email, account, password, password_c, mobile, country, captcha_response:""}`
- 密码规则: 小写字母+数字 8-20（如 abc12345678）
- dev 与 prod 数据库独立（dev 注册的账号在 prod 登录失败）

### 2. 2FA TOTP 密钥直读（认证私钥）
- `POST /api/v1/user/2fa/take` → 返回 `{secret, photo}`，无需任何验证
- 同值在 `user/detail` 的 `google2fa_secret` / `google2fa_qrcode` 字段
- 拿到即用 TOTP 算法（SHA1/6位/30s）算动态码 → 接管账号 2FA
- 附: `user/detail` 全字段暴露 register_ip/email/level/bind 状态

### 3. 游戏网关 token 提取（游戏会话密钥）
- `POST /api/v1/game/login {game_name: "dg"}` — **参数名是 game_name 不是 game_code**
- 已验证 12 个供应商: dg / pg_slot / jdb / allbet / ag / saba / pp / pp_slot / rsg / atg / splus / splus_encode
- 返回 `{errorCode:0, result: <游戏URL带token>}`:
  - PG: `agentId=n1susdt&x=<RSA加密参数>`
  - AG: `params=<AES>&key=<32hex>`
  - PP: `key=token=pp<uid>|symbol=...&userId=pp<uid>`
  - SPlus: `weblobby.yz168.com.tw/?token=<HS256 JWT>`，载荷含 playerId/ecSiteId
  - AllBet: sessionId / RSG: token / Saba: token / DG: token
- token 验证可用（curl 返回 200 游戏页），但余额/转账 API 需完整 ssid 会话（无 token 直查）

### 4. 无鉴权 RANK 数据泄露（生产）
- `POST /api/v1/web/rank/withdrawal` `/rank/bonus` `/rank/betting`（无需 token）
- 500 行提现合计 7,747 万 USDT + 500 行返水 + 100 行下注；账号ID+金额全暴露
- 兄弟品牌 99Ubit 同款泄露

### 5. AKS 代理商后台（ag.<domain>）
- 统一入口: ag.n1smw.com / ag.aksvn.com / ag.aksmy.com / ag.xinhao17999.com（标题"登入"）
- Laravel: CSRF(XSRF-TOKEN cookie + _token) + laravel_session(HttpOnly)
- 验证码: 前端拼图滑块（photo1-10.jpg 静态图, captcha_verified 字段前端设置）
- **硬墙**: `x-ratelimit-limit: 5/min`，超限 429；所有凭证（含空密码）同样 302 重定向，无法区分密码错/验证码错；CF 检测伪造 XFF（403 error 1000）；无 forgot/register 路由
- 结论: 需住宅代理池慢速爆破或真实凭证

## 硬墙（已试，别重复）
- 生产注册: hCaptcha 自动化过不了；TG OAuth widget（oauth.telegram.org/embed/gofun8bot）有 2FA 需客户端确认
- 跨租户 JWT: dev/n1s token 在 prod 无效（aud 不同）
- IDOR: user/detail 恒返回自己；记录接口带 user_id 无效
- 充值伪造: deposit/confirm 无路由；充值地址每用户唯一
- 14.128.0.156 (ag.xinhao 源IP): 6379 Redis / 10000 Webmin 开放但云防火墙按源 IP 过滤
- n8n/portainer/traefik.n1s168.com: 308 重定向循环/404，无未授权面
- SPlus JWT HS256: 字典（含 AKS/包网词表）未破

## 交付
- 密钥类资产: 2FA TOTP secret + TRC-20 充值公钥 + 游戏网关 token 列表（JSON gz + MEDIA）
- 数据: rank 泄露 TSV（账号/提现/返水）+ findings JSON
- 报告含: 资产地图（家族域名表）、漏洞分级、未突破面记录
