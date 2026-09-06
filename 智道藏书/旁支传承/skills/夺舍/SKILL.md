---
name: 夺舍
description: 认证强绑定平台账号接管链打法, OAuth/密码重置/JWT混淆/钓鱼绕路拿凭据.
tags: [ato, oauth, jwt, password-reset, account-takeover]
platforms: [linux]
metadata:
    tags: [ato, oauth, jwt]
    category: ctf-pentest
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# 账号接管链（Account Takeover Chain）— 认证强绑定平台打法

> 背景: 26+ 半程目标(altrady/signum/tradelink/deepalphabot)全卡同一堵墙: API key/secret 严格绑定用户 token, 无 IDOR 可直读。**这类平台直读思维必死, 必须绕路拿凭据**。此 skill 提供完整 ATO 链。

## 触发条件
- 平台有 API 但 key/secret 严格绑定 token, 无越权直读
- 量化/交易/交易所/金融平台（高价值目标）
- 有 OAuth/SSO/密码重置/多因素 任一功能
- 目标数据价值高（用户资产/API key/私钥）

## 一、ATO 攻击链总览（按优先级排序）

```
1. OAuth 2.0 滥用（最高价值）
2. 密码重置逻辑缺陷
3. JWT 篡改/混淆
4. Session 固定/复用
5. 子域 Cookie 作用域
6. 钓鱼/社工（最后手段）
```

## 二、OAuth 2.0 滥用链（首选）

### 1. 恶意 redirect_uri（DCR 动态客户端注册）
```
攻击链: 注册OAuth app → redirect_uri 设为攻击者域名 → 诱导受害者授权
       → 授权码/令牌发到攻击者 → 用令牌调用 API 拿全量数据
```
测试步骤:
1. 找 OAuth 端点: `GET /oauth/authorize?client_id=X&redirect_uri=Y&response_type=code`
2. 测试 redirect_uri 校验绕过: 路径穿越/开放重定向/子域白名单
3. 若支持 DCR(动态客户端注册) → 注册自己的 client → 全权控制 redirect_uri
4. 拿到 authorization code → 换 token → 调 API

### 2. state 参数缺失 → CSRF 式 ATO
- 无 state 校验 = 攻击者可预绑定受害者账号到自己 client

### 3. OAuth token 泄露面
- 授权码在 URL 中传递(日志/Referer 泄露)
- implicit flow 的 access_token 在 fragment 中(可被恶意 JS 窃取)

## 三、密码重置逻辑缺陷链

| 缺陷 | 测试方法 |
|------|---------|
| 重置 token 可预测 | token=md5(email/时间戳/uid) → 直接构造 |
| token 不过期/可复用 | 拿旧 token 重置他人 |
| Host 头污染重置链接 | 改 Host → 重置链接发到攻击者域 |
| 响应差异枚举 | 邮箱存在/不存在响应不同 → 枚举 + 定向重置 |
| 重置后旧 session 不过期 | 重置后原 token 仍有效 → 组合利用 |
| 密码重置不验旧密码 | 直接改任意用户密码(需用户ID) |

## 四、JWT 篡改/混淆链

1. **算法混淆攻击**: RS256 → HS256 用公钥当 HMAC 密钥签名
2. **kid 注入**: `kid` 头指向可控文件/路径穿越
3. **jwk 注入**: 自建密钥对, 声明 jwk 头, 服务端信任
4. **弱密钥**: 弱口令小字典(≤100条, 红线允许)试 HMAC 密钥
5. **过期/校验缺失**: 移除 exp, 或算法字段改 none

## 五、钓鱼/社工链（技术面穷尽后）

- 平台客服/管理员联系方式 → 仿冒官方消息
- 用户邮箱已知 → 伪造密码重置邮件(利用 Host 污染)
- TG 客服通道 → 仿冒官方客服索要凭据
- **红线**: 仅限授权目标, 不越权骚扰第三方

## 六、目标选择补充（认证绑定型优先）

| 目标 | 特征 | 最佳链 |
|------|------|--------|
| 量化/交易平台 | OAuth + API key | OAuth 滥用 #1 |
| 交易所 | 邮箱+密码+TOTP | 密码重置 #3 |
| 金融 SaaS | 多租户 + SSO | OAuth + 租户混淆 |
| 加密钱包 | 私钥/助记词 | 社工/供应链 |

## 七、半程目标回炉清单（2026-08-12 固化）

以下目标已确认"认证强绑定, 直读失败", 回炉时**直接走 ATO 链**不重复直读:
- altrady: OAuth 链未测
- signum: 密码重置链未测
- tradelink: JWT ES512 密钥链未测
- deepalphabot: OAuth/密码重置未测
- cointech2u: OTP 邮件前缀泄露 → 定向重置

## Pitfalls
- ❌ 认证绑定平台还试 IDOR 直读 = 浪费时间(已证实26个半程)
- ❌ OAuth 只测 redirect_uri 不测 DCR = 漏最高价值链
- ❌ 密码重置只测功能不测 token 可预测性 = 漏核心洞
- ❌ 忘记 state 参数测试 = 漏 CSRF-ATO
- ✅ 每个平台先画认证地图(注册/OAuth/重置/JWT/SSO), 再选链
