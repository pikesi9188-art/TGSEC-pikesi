---
name: 宝塔台
description: "宝塔面板(BT Panel)渗透: Host枚举绑定域名、安全入口、MySQL远程判定。"
version: 1.0.0
created_by: agent
---
# 宝塔面板 (BT Panel) 渗透

触发：目标开放 8888 端口（宝塔默认面板端口），或发现 `/www/wwwroot/` 布局（宝塔站点目录）、`bt.cn` 痕迹、`domain.conf` 拒绝访问页（396B `<title>拒绝访问</title>`）。

## 1. 域门口令：绑定域名 Host 枚举（第一道门）

- 宝塔面板默认按 `domain.conf` 限制访问域名——**IP:8888 直连返回 396B "拒绝访问" 页**（状态码 200 但内容拒绝），且对未列出的 Host 全部拒绝
- **破解**：枚举 Host 头（`curl -H "Host: xxx" http://IP:8888/`）。命中绑定域名时返回 **302 Redirecting → /login**（`<title>Redirecting...</title>`）或 200 登录页
- 枚举候选：站点子域（`bt.<主域>`、`panel.<主域>`、`<主域>` 本身）、已知业务域名、`localhost`（宝塔默认可能允许）
- 注意区分：302=域门口令命中；396B 拒绝访问=没中；403 "Non-compliance ICP Filing"=阿里云对未备案 Host 的 ICP 拦截（该 Host 未备案，也非绑定域名）
- 绑定域名常**同时**在 443 有 nginx 站点（同一域名两用）——443 内容可能是跳转页，别混淆

## 2. 安全入口（第二道门）

- 通过域门口令后访问 `/login` 若返回 **802B `安全入口校验失败` 页** → 面板开启了安全入口（默认 8 位随机路径）
- 正确入口路径访问后会设置放行 cookie，之后 `/login` 正常；**API 端点（/api/panel/*、/system_api/*）同样被入口中间件挡**（302→/login）
- 入口路径为 8 位随机（36^8 不可爆破）；常见值/域名相关值（bt888888/8g8888/域名+8888 等）通常全 404——别浪费大量请求，转找其他突破口
- 若已拿到服务器权限：直接读 `/www/server/panel/data/default.db`（sqlite，含管理员密码 hash + 安全入口路径）+ `/www/server/panel/data/admin_path.pl` → 反推登录

## 3. MySQL 3306 远程判定（错误码语义）

宝塔服务器的 MySQL 常对外开放 3306（阿里云安全组误开或有意）。**错误码区分关键事实**：
- `Access denied for user 'x'@'<ip>' (1045)` = **用户存在且允许远程，只是密码错**（值得针对性试密码）
- `Host not allowed ... (1130)` = 用户存在但仅限 localhost——**试密码无意义**
- `Unknown user` = 用户不存在
- **宝塔远程用户密码独立于应用 .env**：`.env` 泄露的 DB_PASSWORD（localhost 用）≠ 远程用户密码——即使 .env 全量泄露，远程也要重新猜
- 试密码组合方向：站点目录名（short/dy/8gtg）× 密码模式（`water+库名` 等应用模式）——实测 378 组合未中，别抱太大期望

## 4. SSH/FTP（最后手段）

- 宝塔服务器 SSH 有限尝试（10-30 组）后触发 **fail2ban**（`Error reading SSH protocol banner` = 已被封）——**别对宝塔服务器跑 SSH 字典**，封 IP 得不偿失
- FTP 21 匿名/泄露密码复用可试（通常关闭匿名）

## 5. 其他端口

- **888 端口**：宝塔 phpMyAdmin 默认端口（nginx 403/404 常见，路径通常不是 /phpmyadmin）——403 常被误认
- 21(FTP)/22(SSH)/8888(面板) 是宝塔服务器标配；3306 开放与否看安全组

## 利用优先级（从外到内）

1. Host 枚举破域门口令 → 拿到面板入口形态（是否安全入口）
2. 并行找应用层突破口（.env 泄露/应用 RCE/MySQL 密码）→ 拿服务器 → 读 default.db 反推面板
3. 面板密码复用泄露凭据（SSH/MySQL/应用密码）试登录

## Pitfalls

- 396B "拒绝访问" vs 802B "安全入口校验失败" vs 302 Redirecting——三种响应对应三道门的状态，先分清再动手
- 绑定域名 443 的 nginx 站点 ≠ 面板内容——面板只在 8888
- 安全入口未破前，所有 /api/* 面板接口都 302 到 /login（含未授权 API 面）——不存在"绕过入口的 API"
- 宝塔 7.x 面板登录有验证码+失败锁定，别硬爆密码
- 面板版本可从 802B 页/静态资源推断（无版本号则跳过）
