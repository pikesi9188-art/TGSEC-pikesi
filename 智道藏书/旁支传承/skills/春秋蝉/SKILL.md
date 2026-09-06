---
name: 春秋蝉
description: 目标可打性评分与打法分流, 侦察30分钟判死, 高防1小时止损.
tags: [triage, recon, methodology, target-selection]
platforms: [linux]
metadata:
    tags: [triage, recon, methodology]
    category: ctf-pentest
---

> **红莲**
> 当时年少掷春光，花马踏蹄酒溅香。
> 爱恨情仇随浪来，夏蝉歌醒夜未央。
> 光阴长河种红莲，韶光重回泪已干。
> 今刻沧桑登舞榭，万灵且待命无缰！
> 无限轮回无限伤，可怜青丝满沧桑！

# 目标可打性评分 + 打法分流（2026-08-12 复盘固化）

> 背景: 106 目标打穿率仅 14%, 34% 目标无报告(开打即弃), 27% 半程。根因 = 死目标上浪费时间 + 打法不分流。此 skill 解决两个问题。

## 触发条件
- 拿到任何新目标（URL/域名/APK/IP）开始侦察时
- 侦察进行 20-30 分钟还没有实质性发现时
- 感觉"这目标不对劲"时

## 一、30 分钟判死清单（侦察阶段必跑）

侦察动作：curl 首页 + 看 JS + 找 API + 找登录/注册 + FOFA 查资产 + 源站探测，**30 分钟内完成**。

### 💀 死目标特征（命中任意 2 项 = 判死换目标）
| 特征 | 判定方法 |
|------|---------|
| 纯前端 SPA 无后端 API | JS 里 grep 不到真实 API 基址, 数据全 Mock |
| CF/区锁/5秒盾且源站找不到 | 响应头 cf-ray + DNS 全 CDN, 无历史 IP |
| 静态站/展示页无交互 | 无登录/注册/搜索/API, 纯静态 |
| 只有登录框无注册无重置无第三方 | 无账号获取途径 = 无洞面 |
| 全站 WAF 拦截所有探测 | 目录/参数/接口全 403/419, 无绕过面 |

**判死后**: 记一行到目标目录 INTEL.md 标注"DEAD: 原因", 换下一个目标。**不恋战, 不反复确认**。

### 🔥 高价值目标特征（重点投入）
- 有真实 API + 未授权端点（不需要登录就能调）
- 有注册流程（可自建账号拿内部视角）
- 有支付/充值/提现/卡密逻辑（变现面）
- 框架已知且版本有 CVE（RuoYi/Laravel/ThinkPHP 等）

### ⏱ 高防目标（1 小时止损）
- GA-TOTP 强制 + 参数化 SQL + 全局过滤器 = 正面不可破
- 判定后**立即转侧信道**（钓鱼/供应链/第三方组件/社工）或放弃
- 禁止反复爆破/绕过尝试超过 1 小时

## 二、打法分流（按目标类型选打法）

| 目标类型 | 特征 | 打法 | 参考 skill |
|---------|------|------|-----------|
| **直读型** | API 有 IDOR/BOLA 面 | 注册→越权直读 | register-bypass-idor / idor-testing |
| **认证绑定型** | API key 严格绑 token, 无 IDOR | **转账号接管链**, 不直读 | account-takeover-chain |
| **高防型** | GA-TOTP/强 WAF/参数化 | 1h 止损转侧信道/社工 | social-engineering-framework |
| **支付/发卡型** | 订单/回调/卡密 | 回调伪造/IDOR/弱签名 | faka-shop-pentest / epay-admin-pentest |
| **TG bot/TMA** | TG 生态 | session/initData/协议逆向 | telegram-bot-discovery / tma-encrypted-api-reversal |
| **博彩/游戏** | 白标/TMA/赔率 | 租户枚举/S3/协议逆向 | whitelabel-gambling-pentest / gambling-saas-pentest-workflow |
| **金融/量化** | 强认证+资产 | **账号接管链**, 不做直读 | account-takeover-chain / quant-copy-trading-pentest |

## 三、打穿率自检（每轮结束问自己）
- [ ] 这个目标是死目标吗? 判死没有?
- [ ] 打法按类型分流了吗? 还是用直读思维打认证绑定平台?
- [ ] 高防目标止损了吗? 还是恋战了?
- [ ] 半程目标(有发现差最后一步)回炉清单更新了吗?

## Pitfalls
- ❌ 死目标上反复确认 = 浪费时间, 判死即走
- ❌ 用直读思维打认证绑定平台 = 必然卡半程
- ❌ 高防目标爆破/绕过超过 1 小时 = 投入产出倒挂
- ❌ 侦察完不写 INTEL.md = 下次重复侦察
- ✅ 每个目标侦察完必须产出: INTEL.md(资产+API面+判定) + 打法选择
