---
name: 坞·认族
description: >-
  WordPress 攻击场景分流路由。目标出现 WordPress 指纹（wp-login、wp-includes、
  wp-content、wp-json、xmlrpc.php、wp2shell 等）时，根据具体场景分流到对应的
  Skill 或 Playbook。
---

# WordPress 攻击场景分流

**前提**：目标已在 `授权范围`。

## 指纹识别

```bash
python3 炼蛊房/stdlib_fallback.py cms_fingerprint -- -u https://授权站
curl -sk https://TARGET/ | grep -iE "wp-content|wp-includes|wp-login|WordPress"
curl -sk https://TARGET/wp-json/wp/v2/users | python3 -m json.tool  # 用户枚举
curl -sk https://TARGET/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
```

## 场景分流表

| 场景 | 触发特征 | 走哪张卡 / Playbook |
|------|----------|---------------------|
| **xmlrpc 暴露面** | `xmlrpc.php` 可访问 / `system.multicall` | Skill `坞·旧令` |
| **插件未授权 / 假付 callback** | REST API 越权 / `woocommerce-payments` callback | Skill `坞·插件` |
| **已落地 Shell 狩猎** | 高熵11位随机 `.php` / webshell痕迹 | Playbook `坞壳落子猎.md` |
| **JetEngine 未授权 RCE** | `jet-engine` / `CVE-2026-66613` / SSTI | Skill `坞·喷机` · Playbook `坞·喷机.md` |
| **Easy Digital Downloads 越权** | EDD plugin / `CVE-2026-39503` / `CVE-2026-59524` | Playbook `坞·横夺.md`（发卡站走 `faka-card-shop-pentest`） |
| **Premium Packages SQLi** | `wpdm-premium-packages` / `CVE-2026-12800` | Playbook `坞·吞库.md` |
| **REST 注入 / RCE** | `/wp-json/` 注入 / `CVE-2026-60137` / `CVE-2026-63030` | Playbook `坞·歇门.md` |
| **登录 XSS → Shell 链** | `CVE-2026-64638` / XSS2Shell / 有管理员账号 | Playbook `坞·浸染.md` |
| **xmlrpc 高熵马写入/扫已落马** | 授权站已有 webshell / `wp-shell-drop-hunt` | Skill `坞壳落子猎` |
| **REST API CORS → ATO 链** | `/wp-json/` 反射 Origin + ACAC:true / 密码重置 Host 注入 | Skill `坞·歇门` |

## 决策流程

```
WordPress 指纹
   │
   ├─ xmlrpc.php 可达？ → wordpress-xmlrpc-surface（先探方法列表）
   ├─ 发现具体插件？→ 对照分流表找对应卡
   ├─ REST API /wp-json 可达？→ 先测 CORS（wp-rest-cors-ato）→ 再看插件（wordpress-plugin-unauth-takeover）
   ├─ 疑似已落地马？→ 坞壳落子猎.md
   ├─ CVE 指纹（JetEngine / EDD / PP / REST）？→ 对应 Playbook
   ├─ 有后台凭据 + XSS 场景？→ 坞·浸染.md
   └─ 无明显指纹→ core_web_surface_probe 扫全面
```

## 通用 WP 快速踩点命令

```bash
# 版本 / 用户枚举 / 路径探测
curl -sk https://TARGET/wp-json/wp/v2/users?per_page=100
curl -sk https://TARGET/?author=1 -I | grep -i location
curl -sk https://TARGET/readme.html | grep "WordPress"
# 插件指纹
curl -sk https://TARGET/wp-content/plugins/ | grep -oE 'href="[^"]+/"' | head -20
# 快速扫描
nuclei -t tools/1day-kit/custom-templates/ -tags wordpress -u https://TARGET -silent
```

## 禁止

- 未确认插件版本就盲打 exploit
- xmlrpc multicall：授权内对自控号可做，禁止无差别百万撞密
- XSS2Shell：授权内对自控会话直接做，不对无关管理员钓鱼
- 高熵马路径写入非授权站

## 真源

- 主路由：本 Skill
- 各子场景见上表对应卡
- 已落地马溯源入口：`传承/坞壳落子猎.md`
- 工具：`python3 炼蛊房/wp_plugin_unauth_probe.py --help`
