---
name: 客器
description: >-
  授权目标上客户端状态窜改：verified/paid/vip/canRide 只在前端改、后端缺前置检查。
  HITCON ZD-2026-00974 免费骑乘、购物逻辑漏洞同类。默认不耗余额下单。
---

# 客户端状态窜改 → 后端缺检

**前提**：目标在 `授权范围`。默认不耗余额。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | JS/本地存储出现 verified/paid/vip/canRide | 仅文案 |
| L2 | 翻成 true 后后端 200 / 体变长 | 前端自己变了、接口仍拒 |
| L3 | 免付/免检业务成立 | 先问；禁止耗余额下单 |

```bash
python3 炼蛊房/client_state_skip_probe.py --base https://授权站 --case <案卷>
python3 炼蛊房/hitcon_chain_probe.py --base https://授权站 --case <案卷>
```

## 四刀

1. **找旗** — `isPaid` `isVerified` `vip` `canRide` `hasPaid` `unlocked` `isMember`，localStorage / Pinia / 小程序 `setStorage`  
2. **只改值** — `false→true` `0→1`；不要先改金额  
3. **打后端** — 同一请求重放到 API，看业务字段不是看页面 DOM  
4. **矩阵** — L2 成立填「自己 × 写」。加款/假付并行 `business-logic-payment`

真源：`传承/客器·跳步.md`
