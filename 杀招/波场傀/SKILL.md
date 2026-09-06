---
name: 波场傀
description: >-
  大爱仙尊·TRON能量租赁机器人与Telegram Bot逆向。应对 trx.vin 系能量机器人、TG bot 攻击面、签名算法逆向、initData伪造。来自TRX.VIN
  实战。
---

# trx-energy-bot-reversing（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/trx-energy-bot-reversing/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name trx-energy-bot-reversing`

---

# TRON 能量机器人逆向 / TG Bot 攻击面

## 触发条件
- 目标为 TRON 能量租赁类 TG 机器人（Gas63Bot/Hao123Trx/TrxVinBot 等）
- 关键词：`free_energy`、`energy rental`、`trx.vin`、TG bot token、X-Sign、initData
- 特征：多 bot 共享一套源码/后端（同 admin、同模板）

## 核心攻击面

### 1) Bot 资产清单（先收集全）
收集每个 bot：username、bot id、token、域名、免费能量开关、日限额、新用户礼包、封号阈值(mismatch_block_threshold)。

**重点标注**：
- `free_energy_daily_limit=0` → 理论无限领取（如 U789Bot/HXNL_bot）
- `mismatch_block_threshold=0` → 发错对手方永不封号（如 TrxVinBot）

### 2) 攻击面分类
- **TG bot token 泄露**：可冒充 bot 发消息、读 update（若未关 webhook）、伪造 admin 操作
- **后台 API**：`{domain}/api/...` 能量租赁接口，X-Sign 签名
- **前端 JS**：签名算法、免费能量领取条件、配额逻辑全在前端可读

### 3) 请求签名算法（逆向重点）
```
X-Sign = MD5(jwt_token + X-Timestamp)
```
- jwt_token 从何来？登录/初始化接口下发
- 时间戳参与签名 → 防重放，但也便于离线爆破 order（若算法弱）

### 4) initData 伪造（Telegram WebApp 校验）
发起方校验逻辑（可复现）：
```
data_check_string = sorted(params).join("\n")
secret_key       = HMAC-SHA256("WebAppData", bot_token)
hash             = HMAC-SHA256(secret_key, data_check_string)
```
- 拿到 bot_token 即可**伪造任意 initData**（伪造 tg_id、auth_date 等）
- 每个唯一 tg_id = 独立新账号 = 独立每日 quota → **可无限伪造 tg_id 批量领取**

### 5) 免费能量领取条件（服务端校验链，缺一不可）
1. 地址已在 TRON 链激活（有交易记录）
2. 有地址 B 曾向该地址转 USDT（链上真实记录）
3. 地址 B 当前 USDT 余额 ≥ free_energy_eligibility_usdt_threshold（多数 100U）
→ 需自备链上地址池/资金满足条件

## 附带情报
- 收集到的 API key（`accec...` 格式，api_id → key → 使用 bot）可跨 bot 复用
- 收款地址（TNVWd... 等）→ 资金追踪/交易关联
- 作战服务器（SRV1/SRV2 root 密码）→ 若能触达即拿 shell → 读 bot 主程序 + 地址池

## 诚实纪律
- bot token 有效 ≠ bot 可完全控制（很多机器人无 broad 副作用）
- 无限免费额度是否真能"无限领"要实测（服务端仍有链上校验）
- 封号阈值 0 意味着"本次操作"不触发，不代表永久安全
- 伪造 session 后立即转移使用，防被作废
