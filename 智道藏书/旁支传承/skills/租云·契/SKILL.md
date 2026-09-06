---
name: 租云·契
description: "Use when pentesting multi-tenant SaaS tenant-scoped APIs."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, api, bola, multitenant, saas]
    category: ctf-pentest
---
# 多租户 SaaS ACL 差分测试 (Multi-Tenant ACL Differential Testing)

触发: 目标 API 是**多租户**平台 — 有 `X-*-PROJECT-ID` / `X-Tenant-Id` / `X-Account-Id` 之类
的租户头, 数据按 project/org/tenant 隔离 (crypto 交易平台、白标、博彩、量化跟单等)。
目标常是: 拿到**别的租户/全部用户的敏感数据**(API 密钥、余额、订单)。

## 0. 先建基线 (P0)

1. 拿到合法会话: 能注册就注册 (临时邮箱注册绕过见下), 拿到 `access_token`
2. 建自己的租户 (项目): `POST /projects/` 之类 → 得到 `my_tenant_id`
3. 拉 `openapi.json` (FastAPI: `/api/openapi.json` + `/api/docs` + `/api/redoc` 常公开)
4. 建证据目录, 全量端点地图落盘

## 1. ★ 端点差分扫描 (核心技: 找到唯一没设防的端点)

**每个带租户头的端点请求两次**: 一次自己的租户头, 一次**别人的租户值** (任意非我 id)。
多数端点对别人返回 `404 Not Found` / `403` / `Permission denied` —
**任何返回 200 / 500 / 400(参数错) 的端点 = 租户校验缺口**:

```bash
for p in <all endpoints>; do
  c1=$(curl -s -o /dev/null -w '%{http_code}' "$B$p" -H "Authorization: Bearer $T" -H 'X-TENANT-ID: <mine>')
  c2=$(curl -s -o /dev/null -w '%{http_code}' "$B$p" -H "Authorization: Bearer $T" -H 'X-TENANT-ID: <foreign>')
  [ "$c2" != "404" ] && echo "$p mine=$c1 foreign=$c2 <<<"
done
```

要点:
- **400 而非 404 是经典漏检**: 参数校验在租户校验之前 (代码顺序) → foreign 值已过成员检查。
  修好参数格式继续打, 就是跨租户读。真实例: `GET /mining/{id}/spread_graph` 带别人项目头返回
  `400 Bad time filters`, 修正时间窗后 `200` 返回别人项目的流动性数据。
- 对比 `mine=422/400` vs `foreign=404` 同义 (422=参数没过, 404=租户没过; foreign 若是 400/422 而非 404, 租户检查被跳过)。
- **逐端点对比, 别只测热门端点** — 漏洞常在最冷门的只读聚合/统计/图表端点上。
- WAF (Cloudflare crl) 会限流: 触发 `429 {"status":"banned","cause":"crl"}` 就冷却 45-60s 再继续。

## 2. Body-vs-Header 租户 id 混淆 (BOLA 写)

OpenAPI requestBody schema 里有 `project_id`/`tenant_id` 字段, 但**前端 bundle 从不发送该字段**
(服务端 DTO 遗留, 前端只从 header 取租户) → 请求体注入租户 id, header 留自己的:

```http
POST /api/projects/projectpreset/
X-Origami-Project-Id: my_id
{ "project_id": 100, "symbol_id": 1, "options": {"pwn": 1} }
# → 200: 写进别人的项目! (同资源的 PUT 变体却正确 404 — PUT 重查成员)
```

发现法: 从 bundle 的 OpenAPI client (`url:"..."` 字面量 + mutation 调用点) 反推前端实际发送的
字段集合, 与 openapi.json schema diff — **schema 有而前端从不发的字段 = body 注入靶点**。

**存在性 oracle**: 冲突响应 (`Duplicate item`) 而非 404/400 → 目标租户该子对象已存在。
可无读权限地测绘: 哪些租户存在、各拥有哪些 symbol/子对象。

## 3. WS 私有频道隔离测试

- vite bundle 里找 `socket-worker-*.js` chunk → 帧协议对全量提取:
  认证帧 `{"request_id":"<ts>","data":{"op":"auth","token":"<access_token>"}}`,
  订阅帧 `{"request_id":key,"data":{"op":"subscribe","data":{"topic":"orders","project_id":N}}}`,
  响应 `data.op` ∈ authorized/subscribed/unsubscribed/update/error, 越权报 `Permission denied`
- 先订阅自己租户确认协议通, 再用**别的租户 id** 订阅 orders/positions/balances/user_logs 等
  → 预期 `Permission denied`; 其他响应 = 跨租户数据流
- topics 常分公开 (candles/orderbook/market_trades) 与私有 (orders/positions/balances/
  manual_orders/bot_status/user_logs), 私有全部要过租户校验

## 4. 密钥库模式 (交易/加密平台)

交易所/券商类平台把用户 API 凭据**明文**存 accounts 表 (`api_key`/`secret_key`/`passphrase`),
`GET /accounts/account/{item_id}` 对租户成员原样返回 (链上交易所如 Aster/Hyperliquid 的
`secret_key` = 前端生成的 signer 私钥, 同样提交后端存储)。跨租户枚举 `item_id` 1..N 全 404
= 租户边界正确 → 只能靠 §1/§2 找缺口。**这就是目标对象, 差分扫描是唯一入口。**

## 5. 配套辅助技术

- **临时邮箱注册绕过** (注册/找回要邮箱验证码时): mail.tm 等临时邮箱 API 收码。
  mail.tm 坑: `/messages` 返回 hydra Collection 结构, 取 `hydra:member`; token 完整落盘再解析
  (终端输出会截断长 JWT — 用 `curl -o file` 再读)。
- **限流特征**: Cloudflare `crl` 封禁返回 `429 {"status":"banned","cause":"crl"}`; 通常 3 次错误/
  窗口, **X-Forwarded-For/Forwarded 无法绕过** (CF 按真实客户端 IP), 冷却约 45-60s。爆破需代理池。
- **JWT 测试顺序**: 解码 header/payload → alg=none → 常见弱密钥 + FastAPI 文档默认
  `09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7` → rockyou。
  `sub` 常是 email; 弱密钥命中 → 伪造任意用户 token 直接绕全部租户 ACL (最高价值)。
- **已下线/隐藏端点**: 旧版 bundle (另一个子域可能跑旧前端) 的 client URL 集合 diff 现役
  openapi → 发现已下线端点 (通常 404, 偶有漏网)。
- **526 子域**: CF 前置下 `526` (源站证书失效) 的 hostname 是真实 DNS 记录, 可枚举
  `admin/staging/dev/db/redis/...` 等资产名; 但源站在 CF 后, 直连要另找源站 IP。

## 6. 收尾

- 半程利用 ≠ 打穿: 跨租户**写** preset 但没有读回通道 = 报告 BOLA write, 不吹打穿
- 诚实汇报: 每条攻击路径的实测结果 (200/404/429/denied) 列表; 用户库/枚举数据落 JSON
- 证据: openapi.json + 会话凭证 + 差分扫描结果 + BOLA 复现请求落地 evidence/ 目录

详见 `references/multitenant-acl-playbook.md` (origami.tech 实战完整配方: 差分脚本、WS 帧、
mail.tm 流程、JWT 顺序、限流实测)。