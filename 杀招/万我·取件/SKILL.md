---
name: 万我·取件
description: >-
  大爱仙尊·云控跨租IDOR→session直链。py-api任务跨租→account_path→GET.session。
---

> **东方长凡**
> 万我出手千身同，一念分身遍北原。
> 智海无边身作舟，长凡不凡我即天。

# idor-session-download（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/idor-session-download/SKILL.md`
- 手法：`传承/万我·信门.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name idor-session-download`

---

# 云控跨租 IDOR · Session 直链下载手册

> 应对 TG 云控平台（wanke 类，py-api 后端）。核心链：**低权会话读他人私信任务 → JSON 含 account_path → 路径前缀为 market/upload/ 的直链可匿名下载 .session → 平台 inspect 代持读对话**。

## 目标判定
- 前台是静态页面/404，后台是独立端口的 py-api（OpenAPI 标题 `tg-python-core`，上百条 path）。
- 请求需要两个头：`X-Site-Host`（主站 host）+ `X-Frontend-Timestamp`（毫秒时间戳）。
- 有免费注册就先拿低权 Cookie。

## 步骤 1 — 真 API 怎么找到

主站打不开/404，跟前端或历史反代，业务在独立端口：
```http
GET /py-api/private-message/tasks
X-Site-Host: <主站>
X-Frontend-Timestamp: <ms>
Cookie: <低权会话，可空测一次>
```

两个请求头**缺一不可**（缺了空列表或 403）。

## 步骤 2 — 跨租读任务（IDOR）

返回的是**全平台**任务，不是"我的任务"。每条里有：
- 手机号/username
- **`account_path`**：磁盘上 `.session` 或 tdata 的绝对路径
- 路径前缀能分出"市场买号"vs"某代理目录"

## 步骤 3 — 哪些 path 能当文件下

对每条 path 看前缀，不要假设都能 GET：

| path 形态 | HTTP 直下 | 本案 |
|-----------|-----------|------|
| Web 根下 `.../market/upload/<日期>/...` | **能**。Nginx 映射，无鉴权 | 全部 200 |
| 应用目录 `.../py/py/account/<租户>/...session` | 直链 404 | inspect 仍能代持 |

实现：
1. 从 `account_path` 截掉 Web 根之前的部分。
2. 拼到站点 origin。
3. `GET` `.session`。
4. **同目录**再 GET companion `.json`（`api_id`/`api_hash`）。没有 json 则本地 Telethon 少环境参数。

## 步骤 4 — 还没下载也能"看见号"（inspect 代持）

```http
POST /py-api/account-profile/inspect
{"account": {"path": "<步骤2的绝对路径>"}}
```
平台在**自己的机器**上打开这个 session，返回对话列表。market 的、部分代理目录、甚至 tdata 路径都能回 dialogs。用来验活、看频道，不必先把文件拷走。

客户端传的是任意绝对路径，没有"必须是我的号"校验。

## 步骤 5 — 扩量卡在哪（诚实）

| 试过 | 结果 |
|------|------|
| lock/内部 id 枚举 | 存活 id 到 N 量级，响应**不带** account_path |
| 公网 php-api | 已 404，path 在 PHP/MySQL 侧拿不到 |
| `file://` 读盘 oracle | 只能看到文件头约 200 字，补不齐剩余 path |

所以不能把"存活 id 量级"写成"已接管"。没有 path 就没有文件。

## 实现顺序
```
静态官网 → 独立端口 py-api + 两个站点头
  → 低权 GET /private-message/tasks（N条）
  → 展开 account_path（M唯一）
  → 前缀 /market/upload/ → HTTPS匿名GET（K套session+json）
  → 其余path → inspect代持验活
  → lock id≈N无path → 停，不报全库
```

## 诚实纪律
- 可下载的 session 数 = 前缀=market/upload + HTTP 200 的集合，不是另一次扫描。
- 本地 Telethon 登录验证只对已落盘的 session 做。inspect 活 ≠ 本地 session 永久有效（卖家作废/DC 变更会挂）。
- 768 只证明库存下界更大，没有 path 就不能下载。
