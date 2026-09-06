---
name: 马鸿运·稳币
description: >-
 授权目标上 USDT/链上充值「付款地址归属」逻辑漏洞：共享收款地址按 from 绑表入账、
 同址可多账号绑定、无所有权证明 → 充值入账劫持；以及隐藏 paytype/deposit 建单攻击面。
 仅授权范围。
---

> **马鸿运**
> 鸿运加身命难收，杀机扑面运来救。
> 北原少年福如海，气运比刀更温柔。

# USDT 充值归属劫持（+ 隐藏 paytype）

**前提**：目标已在 `授权范围`。真充只用**自控测试地址/授权小额**；禁止批量绑无关第三方热地址「收割」。

**成功口径**：自控小额从绑定付款址打入平台收款地址后，**余额进入非预期账号**（L2）。仅能绑定或仅隐藏 paytype 可建单 ≠ 主洞完成。

## 何时启用

- 共享平台 USDT 收款地址 + 用户自助绑定付款钱包
- API：`bind` / `usdtCreate` / `setDefault` / `rechargeAddress` / `wallet/usdt*`
- 低门槛注册（guest / 无 KYC）
- 假支付已硬化（如全局 `1002`）但仍有链上自动入账
- 用户点名：归属劫持、同址多绑、隐藏 paytype、deposit

不适用：每用户专属收款地址且无 from 绑表；纯 HTTP 回调假付（走 `payment-callback-forgery`）。  
展示层把收款址换掉（受害人屏幕上的址 ≠ 平台分配址）走 `fund-edge-ops`，与本卡并行。

## 与假支付分流

| 面 | Skill / 工具 |
|----|----------------|
| HTTP notify / submit 回放 | `payment-callback-forgery` · `pay_matrix.py` |
| **链上 from → 绑表归属** | **本 Skill** · `usdt_attr_hijack.py` |
| 两者都有 | **并行**；假付阴不必结案 |

## 标准六步（按序留证）

| 步 | 动作 | 关键产出 |
|----|------|----------|
| ① | 授权 + 指纹（共享收款 / 绑定 API） | STATUS 指纹段 |
| ② | 双账号 A/B + 自控地址 `W_test` | Token、地址 |
| ③ | `bind-dup`：同址双绑 / 抢默认 | L1 证据 |
| ④ | （并行）`paytype-enum` 隐藏通道 | P1 面 |
| ⑤ | 自控最小额链上打入 → 查 A/B 余额 | **L2 硬条件** |
| ⑥ | 固化；提现/大规模面先问 | `案卷/usdt_attr/` |

## 作业红线

1. 只用自控钱包证明错归属；不扫链批量绑受害人地址。 
2. 耗余额提现、大规模注册刷绑 → **先问**。 
3. 用户「暂停」→ 停进攻面，可整理文档。

## 最短命令

```bash
python3 炼蛊房/usdt_attr_hijack.py bind-dup \
 --base https://目标 --case <案卷> \
 --token-a "$TOKEN_A" --token-b "$TOKEN_B" \
 --address <自控TRC20> \
 --bind-path /api/wallet/usdt/bind

python3 炼蛊房/usdt_attr_hijack.py paytype-enum \
 --base https://目标 --case <案卷> --token "$TOKEN" \
 --create-path /api/deposit/create --visible 1,2,4 --probe 0-16

# 链上只读拓线（大爱仙尊收编，写 案卷/usdt_attr/）
python3 炼蛊房/usdt_attr_hijack.py chain-scan --case <案卷> --pages 15
python3 炼蛊房/usdt_attr_hijack.py chain-verify --case <案卷> --address T...
```

## 真源

- 手法卡：`传承/马鸿运·归属.md`
- 原图：（开源包不收个案摘记）
- 索引：`传承/春秋蝉·分案.md`
- 假支付对照：`杀招/秦百胜·回响`
- 展示层地址 / wallet_id / 双路径：`杀招/血神子·锋`
