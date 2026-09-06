---
name: 秦百胜·货仓
description: >-
 异次元 ACG-FAKA 发卡站专项：后台随机路径、USER_SESSION JWT、
 callback handle 枚举、假支付矩阵衔接、共享货上游库存链（gmail168 真经）。
 
 打发卡网：假签硬化后先支付栈取钥，再打上游库存；勿只死磕前台 RCE/`sign:true`。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# ACG-FAKA 专项

## 真源

| 内容 | 路径 |
|------|------|
| **发卡网分流总卡** | `传承/秦百胜·拍卖.md` |
| **gmail168 真经 / 库存上游 Playbook** | `传承/货仓·上游.md` |
| 工具包 | `tools/acg-faka/` |
| 探针 | `tools/acg-faka/bin/acg_probe.py` |
| **共享货上游** | `tools/acg-faka/bin/acg_shared_upstream.py` |
| 商户字典样例 | `tools/acg-faka/dicts/shared_merchants.example.json` |
| 会话结构 | `tools/acg-faka/USER_SESSION.md` |
| CF 人机 | `炼蛊房/cf_session.py` |
| 假支付 | `pay_matrix.py` + `payment-callback-forgery` |
| **严签后取钥** | `传承/宝黄天·回灌.md` |

## 心智（先背）

前台是橱窗。钱：假签 → 支付栈取钥 → 合法签出卡。货：钥也打不通再打**上游库存**。 
ACG 共享货 ≈ gmail168 的 `cookie.store`。 
口诀：`资源宿主 + 共享码 + 历史凭据 = 上游候选`；`钱打不通先取钥，钥打不通再打货`。 
成功口径：**出卡或稳定读上游库存（或 SQL）**，不是前台 RCE。

发现上游五步：①跟资源 ②跟 `shared_id/code` ③历史案卷 ④inventory 对码 ⑤静默扩权。 
档位：L1 API 读库 → L2 Entrance/SQL → L3 主机；复工先选定档，勿三档空扫。

## 强制顺序

1. scope 内 
2. `cf_session capture`（有头过 CF/登录）→ storage 
3. `acg_probe.py --storage …`（后台 + callback） 
4. `pay_matrix.py`（中转异 host 静默扩权）— **严签则停假签空转，下一步取钥，勿死磕 `sign:true`** 
5. **ACG 3.4.x `非法签名`** → **先支付栈取钥**（`宝黄天·回灌.md`，走 `payment-callback-forgery`），再考虑上游 
6. **出现 `shared_id` / cover 异站 / 支付栈也进不去** → **立刻切共享货上游**（Playbook §0–§1） 
7. 会员面用 `session_pipeline` / `cf_session consume` 

损坏的 `USER_SESSION` 禁止手修，见 `USER_SESSION.md`。

## 共享货上游命令

```bash
python3 tools/acg-faka/bin/acg_shared_upstream.py discover \
 --base https://橱窗 --case <案卷> --expand

python3 tools/acg-faka/bin/acg_shared_upstream.py connect \
 --upstream https://上游 --app-id <id> --app-key <key> \
 --base https://橱窗 --case <案卷> --items

python3 tools/acg-faka/bin/acg_shared_upstream.py match \
 --base https://橱窗 --upstream https://上游 \
 --app-id <id> --app-key <key> --case <案卷>
```

产物：`案卷/<案卷>/案卷/acg_shared/` 
签名 / L1–L3 / 踩坑见 Playbook。

## Entrance 探测要点

| 形态 | 命中信号 |
|------|----------|
| 核心 AdminEntrance | 响应头 `Refresh` 含 `/admin` +「认证成功」 |
| Entrance 插件 | 「没有使用正确入口」+ Config 路径泄露 |
| 失败 | 勿对**无关**易支付后台广谱喷登录（`@login.lock`）；主站 `submit` 指向的那台支付栈 **要** 短字典 |

## 与假支付分工

- 松散回调 / 中转弱签 → `payment-callback-forgery` 
- 严签 + 支付页跳聚合支付后台 → **先** `payment-callback-forgery` 支付栈取钥（弱口读商户 key → 合法签） 
- 严签 + 支付栈也打不开 + `shared_id` / 发卡默认 → **本 Skill 上游链** 
- 3.4.8 实锤：`POST /user/api/index/query` 对已付单可直接带 `secret`（未付仍不出） 
- zephique/LemPay/TokenPay = 钱；guopi/code92 = 货；勿混打
