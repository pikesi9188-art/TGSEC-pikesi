---
name: 秦百胜·钱庄
description: >-
  大爱仙尊·加密交易所/做市(MM)后端无认证 API 审计。应对无认证 FastAPI/Node 做市后端、HMAC-SHA256签名的交易所API、IP白名单绕过。来自GGE
  X做市实战。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# crypto-exchange-mm-backend（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/crypto-exchange-mm-backend/SKILL.md`
- 手法：`传承/使证闸.md`
- 工具：`python3 炼蛊房/crypto_decode.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name crypto-exchange-mm-backend`

---

# 加密交易所 / 做市后端 无认证 API

## 触发条件
- 目标为加密货币交易所（WE/GGEX/LBank 类）、做市系统（Smart Trade Guard、MM Backend）、量化机器人后端
- 特征：`/docs`、`/openapi.json`（FastAPI）、`/api/account/balances`、`:8001` 类端口、`exchange=ggex/weex` 参数

## 为什么做市后端高危
做市系统持有交易所真实 API Key，且在**服务器本地代签**。后端无认证暴露 = 攻击者免 Key 操纵账户资产。

## 步骤

### 1) 找无认证后端
- Shodan 搜 `"openapi.json"` / `port:8001` / `/docs`
- FastAPI 无认证 → 直接吃 OpenAPI 全量端点列表（104 个端点）
- Swagger: `http://target:8001/docs`；JSON: `/openapi.json`

### 2) 验证关键端点（读余额/挂单/下单/撤单）
```
GET  /api/account/balances?exchange=ggex     # 全资产余额（USD估值）
GET  /api/account/balance/{asset}?exchange=  # 单资产
GET  /api/orders/ggex/open                   # 当前挂单
POST /api/orders/ggex/orders                 # 下单 {symbol,side,orderType,force,price,quantity}
DELETE /api/orders/ggex/orders/{id}          # 撤单
DELETE /api/orders/ggex/orders/all           # 撤全部
GET  /api/orders/ggex/history                # 历史
GET  /api/ggex/listen-key                    # WS 监听 key
```
- 下单 side 必须**小写** buy/sell；`BUY/SELL` 不通用
- 响应含 `"status":"success"` + 临时 orderId → 确认无认证可交易

### 3) 评估资金操纵
- 确认 TGK/USDT 可用余额 → 可砸盘/拉盘（概念验证只读，生产勿重复）
- 提币/站内转账**通常无对应端点**（Withdraw/Transfer 不存在）→ 不能直接转走资产，如实标注

### 4) IP 白名单与直连绕过
- 从 .env 读到的企业 API Key 直连交易所官方 API 常因 IP 白名单失败：
  `{"code":-600102,"msg":"User API authentication failed."}`
- 绕过：经**本地点(:8001)后端代签**，或目标机本地发起
- 若拿到 shell 可本地直连官方 API

## HMAC-SHA256 签名公式（直连交易所私有 API 参考）
- Header: `X-MBX-APIKEY: {api_key}`
- 签名消息: `{timestamp}{apiKey}{recvWindow}{queryString}`
- `signature = HMAC-SHA256(secret, msg)`
- 参数: timestamp, recvWindow(5000), queryString(sort)
- 补充 `.env` 里的 `IP_ADRESS` 常是白名单绑定 IP → 判断能否外网直连

## 诚实纪律
- **提币不可行**要明说（无 withdraw/transfer 端点），不夸大为"可提走全部资产"
- 对外探测不存在的路径返回 200 空 body ≠ 有效 API（服务端 catch-all）
- 下单/撤单能力 = 交易操纵风险（High/Critical）；提币 = 依赖独立端点
- 未闭环的（如超管提权）如实标 [potential]，不标已确认
