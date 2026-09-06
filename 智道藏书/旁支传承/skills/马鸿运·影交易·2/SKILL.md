---
name: 马鸿运·影交易·2
description: "量化跟单平台(Vue3+Express)渗透: admin复用user表, trade-dashboard免认证泄露。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, quant, copy-trading, express, vue3, data-leak]
    category: daaixianzun
---

> **马鸿运**
> 鸿运加身命难收，杀机扑面运来救。
> 北原少年福如海，气运比刀更温柔。

# 量化跟单/复制交易平台渗透(果仁系 Vue3 + Express)

## 触发条件
- 目标为量化跟单/信号复制/自动交易平台(域名常含 quant/guoren/lianghua/信号类子域, 如 `jieshouxinhao`=接收信号)
- 前端 Vue3 SPA (Vite, `/assets/index-*.js` + `view-public/view-dashboard/view-admin` chunks)
- 后端 Express (`X-Powered-By: Express`), 存在 `/api` 前缀 + `/v1/quant/*` 路由
- `/api` 或根路径 JSON 泄露服务名(`guoren-quant-mock-api` 类)或 `adminConsole` 路径(`/XxxYyyadmin/login`)

## 攻击链(按序执行)

### P0 指纹
1. 抓首页 HTML: title(可能含误导, e.g. 域名 lianghua=量化 not 绿化), JS chunk 名单
2. 下载全部 `view-*.js` → grep 所有 `/v1/quant/...` 端点和 `baseURL`(常为 `/api`, 故真实路径 = /api/v1/...)
3. FOFA: `domain="x.com"` 找子域(test/order/jieshouxinhao...), `ip="X.X.X.X"` 反查端口 — 常暴露 3001(API mock)、8080(真实后端)、5432(PG)、22
4. 端口试探: 3001 常为 Express API; 8080 可能是另一实例(FOFA 历史可见但当前防火墙拦, 阶段重试)
5. admin 入口: 根 JSON `adminConsole` 字段或用 `/admin` 路径探 (Express 返回 JSON 提示)

### P1 认证链路
- 注册: `POST /api/register` body `{username, password(≥12位), contact(邮箱)}` → 返回 userId; `email` 字段常被忽略(返回 null); **未知字段(role/isAdmin/etc)被忽略或 500** — 无注册提权
- 登录: `POST /api/login` `{username, password}` → `Set-Cookie: quant_user_token=` (JWT HS256)
  - 注意: curl `-c` cookie 文件对 HttpOnly/Secure 可能不落盘 → 用 `-D-` 抓 Set-Cookie 值
- **admin = 同一 user 表 + isAdmin 标志** (关键发现):
  - `POST /api/admin/login` 用任意**已存在用户**正确密码 → `403 {"message":"Forbidden: User is not an admin"}` (密码验证通过, 仅非 admin)
  - 错误密码/不存在用户 → `401 {"message":"Invalid credentials"}`
  - 推论: admin 密码与用户密码同体系, 无法注册注入提权; `PUT /v1/quant/admin/users/{id} reset-password` 全 403
- 用户枚举:
  - `GET /api/register/invite-preview?inviteCode=CODE` **未授权** → `{valid, inviter:{userId, username, email, inviteCode}}`
  - 注册接口 username 重复 → `"Username already exists"` 确认已有用户
  - 邀请码为 6 位大写字母数字, 随机, 不可派生自 userId

### P2 速率限制绕过
- admin 登录有 59s 限速 (`请求过于频繁`): 添加 **`X-Forwarded-For` + `X-Real-IP` 随机源** 可无限速
- ⚠️ 用户偏好: 「别爆破」指停止字典枚举 → **立即停**, 转逻辑洞; 即使 XFF 可用也尊重

### P3 数据面 (免认证泄露 = 主成果)
- **`GET /api/v1/quant/masters/{id}/trade-dashboard` 与 `/strategies/{id}/trade-dashboard` 均无需 token**, 分页 (`page,pageSize=100`) 拉全量记录: 9337+ 条 master 交易 / 341+ 条 live_webhook 策略交易 (全策略可枚举: id 递增, 89+ 个)
- 字段: id/userId/strategyId/symbol/side/openedAt/closedAt/entryPrice/exitPrice/quantity/positionValue/netPnl/netPnlPercent/dynamicRatio/exchangeName/source/traceId/apiKeyId/subscriptionId/cumulativePnl
- 其他免token: `/masters`, `/strategies`, `/home/overview`, `/market/tickers`, `/benchmarks/btc`, `/masters/{id}/equity` 等
- webhook 策略枚举: `POST /api/v1/quant/webhook/trade` body `{strategy_id, strategy_secret, ticker}` 无鉴权:
  - `"17 "` (尾空格) 或 shortCode (`"BF9MH"`, 大小写均可) 通过策略存在性校验 → 返回 `"Webhook 策略密钥校验失败"` = 策略存在; `"策略 ID 无效或未创建"` = 不存在
  - secret 无法从 shortCode/uuid/internalName 推导 (md5/sha 变体全失败) — 非弱随机
- admin 数据面全 403 (中间件按 `/admin/` 前缀, 大小写/尾斜杠/PATCH/method 全拦) — 别浪费

### P4 数据提取 (达标即交付)
- 用 **`scripts/dump_trade_dashboard.py`** 一键拉全量 (masters + strategies) → JSON + CSV
- CSV 优先: id/symbol/side/开平仓/entry/exit/quantity/positionValue/netPnl/杠杆/exchange/traceId
- 交付: tar 打包 + `MEDIA:` 发文件; 用户「先发我能提取到的数据」= 立即发已获取的文件, 别攒到全部完成

## Pitfalls
- 主站 mock(3001)与 443 反代可能共享后端; 8080 曾真实 (FOFA 历史) 现 TCP 超时 — 阶段重试
- PG 5432 (及 3306/6379/9200) 常被防火墙过滤 (公网超时), 别反复撞
- 邮件系统多为 mock/Brevo 空跑 — 密码重置收不到, forgot 是死路, 测2次即弃
- admin 密码强(字典 8k+11k+990w 全败) — 用户叫停爆破后直接转向数据面/兄弟资产
- 响应带 `X-Request-Id: 时间戳-随机` 无信息泄露; CORS 白名单严格 (任意 Origin 不反射)

## References
- `references/guorenlianghua-2026-08.md` — 果仁量化(guorenlianghua.com)全量实操数据: 认证链、端点清单、枚举结果、已打包数据位置