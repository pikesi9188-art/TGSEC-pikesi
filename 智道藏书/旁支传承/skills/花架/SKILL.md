---
name: 花架
description: "Laravel pentest: debug leak, .env, version fingerprint."
version: 1.0.0
created_by: agent
---
# Laravel 应用渗透（debug 泄露 / 版本指纹 / RCE 决策）

## 触发条件
- 目标返回 Laravel 特征: `laravel_session`/`XSRF-TOKEN` cookie、Whoops 异常页（`<!--\n\n\n<Exception>: ...Stack trace...` 注释式 HTML）、`/api/user` 500、`Route [login] not defined`
- debug 模式开启 = 异常页含完整堆栈 + **Environment Variables 面板**（.env 全量泄露）

## 1. .env 泄露（Whoops env 面板）
- 触发任意异常（如未认证路由 `GET /api/user` → 500 `InvalidArgumentException: Route [login] not defined`）→ Whoops 页底部 Environment Variables 表格含 APP_KEY/DB_*/MAIL_* 等 **实际值**
- 提取: 键名列和值列分两列, 按行配对解析（sf-dump span）
- 已实测泄露: APP_KEY(base64:...)、DB_HOST/DB_DATABASE/DB_USERNAME/DB_PASSWORD、APP_URL、SERVER_ADDR(内网 IP)
- 辅助: `/composer.json`、`/vendor/composer/installed.json`、`/.env`、`/storage/logs/laravel.log` 常被 nginx deny(404) — 别浪费时间, Whoops 页更快

## 2. 版本指纹（异常页行号对比 GitHub 源码）
- 关键行号: `UrlGenerator.php` 中 `throw new InvalidArgumentException("Route [login] not defined.")` 的行号 **随版本单调变化**
- 实测行号表(比对 raw.githubusercontent.com/laravel/framework/<tag>/src/Illuminate/Routing/UrlGenerator.php):

| Laravel | 行号 |
|---|---|
| 5.5.50 | 305 |
| 5.6.40 | 372 |
| **5.8.38** | **388** |
| 6.20.44 | 437 |
| 7.30.6 | 420 |
| 8.83.27 | 444 |
| 9.52.0 | 467 |

- 目标行号 389 → **5.8.x**（小版本差异 ±1 行）
- 辅助指纹: `RouteCollection.php` methodNotAllowed throw 行号(255 附近, 各版本差异小, 参考性弱); `fideloper/proxy` TrustProxies 在堆栈中 = 5.x-6.x 特征(7+ 内置)
- 方法: 下载目标 tag 的 UrlGenerator.php → grep `Route [` 所在行 → 与异常页行号匹配

## 3. RCE 决策矩阵（按版本, 已实测排除项）
| CVE | 适用 | 快速验证 |
|---|---|---|
| CVE-2018-15133 (APP_KEY unserialize RCE) | **≤5.6.30** | PHPGGC Laravel/RCE{1,3,5,7,9} + 自写 Encrypter(AES-256-CBC+HMAC, iv/value/mac JSON base64) 发 `X-XSRF-TOKEN`; 响应无变化=已修复 |
| CVE-2019-11043 (PHP-FPM RCE) | PHP 7.1-7.3 + nginx fastcgi_split_path_info | 先验 `index.php/xxx` 返回非 404(PATH_INFO 可达); 再扫 `?a=%0a*n` 找 `Primary script unknown` 500 — 全 200=不适用 |
| CVE-2021-3129 (Ignition RCE) | Laravel 7+ 且 _ignition 可达 | `/_ignition/health-check` — nginx 404=被挡; 5.8 用 Whoops 无 Ignition |
| 修复后 APP_KEY | 解密已拿到的加密 cookie/session | EncryptCookies 5.6.30+ 不再 unserialize — 仅解密用 |

- **结论规则**: Laravel 5.8/6.x + debug 但 RCE 全堵 = 大概率无公开 RCE, 转横向（DB 密码复用/宝塔/同源资产）

## 4. APP_KEY 利用（无 RCE 时）
- 解密任何 Laravel 加密值（cookie、加密字段）— 需先拿到密文
- DB 密码等凭据 → 密码复用横向（注意 MySQL 用户常绑定 localhost）
- APP_URL/SERVER_ADDR 泄露 → 源站/内网拓扑

## 5. 路由枚举 oracle（debug 模式）
- **catch-all 路由**（如短链服务 `/{code}`）: 任意 POST → `MethodNotAllowedHttpException` Whoops 页; 任意 GET 无效码 → 控制器返回体(如 `0`) — 区分真实路由靠响应体差异, 不是状态码
- nginx 常对特殊字符(引号/%)路径直接 404 — SQL 注入经 PATH_INFO/query 被路径层拦截时, 换编码或放弃
- 敏感路径(composer/vendor/storage/.env)nginx deny 404 — 用 `index.php/<path>` 或 PATH_INFO 变体试

## Pitfalls
- `Route [login] not defined` = 认证中间件 redirect 到不存在的 login 路由 — 常见于无登录功能的内部 API, 本身是信息(路由存在但 auth 配置残缺)
- 短链/落地页类应用常无登录功能 → 无 cookie 可解, APP_KEY 价值低
- Cloudflare 对 curl 返回 0 字节 200 — 用浏览器通道或带完整浏览器头重试
- 版本指纹失败时: 异常页堆栈里的中间件链(Kernel.php 行号/中间件类名)也是线索

## references
- `references/version-fingerprint-case.md` — 8gtg.vip 案例: 行号验证全过程 + CVE 实测排除记录
