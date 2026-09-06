---
name: 幻页·露底
description: "Use when PHP debug pages leak env, routes, or RCE surfaces."
version: 1.0.0
created_by: agent
---
# PHP 框架 Debug 模式利用（Laravel / ThinkPHP）

PHP 站（尤其宝塔部署）开着 debug 时，异常页 = 配置金矿 + 路由 oracle + RCE 入口。典型触发链：找任意能抛异常的端点（未认证中间件 500、方法不符 405、SQL 报错、路由不存在）。

## 1. 异常页触发点（无认证）

| 触发方式 | Laravel | ThinkPHP 6 |
|---|---|---|
| 未认证 API（auth 中间件 + login 路由缺失） | `/api/user` → 500 `Route [login] not defined` + 全堆栈 | — |
| 方法不符（GET-only 路由 POST） | 405 `MethodNotAllowedHttpException` + 堆栈 | — |
| 任意 POST 到 catch-all 短链路由 | 405（catch-all 只注册 GET） | — |
| SQL 报错 | — | `/api/index` → 400 `SQLSTATE...` + 完整 trace + **数据库名/表名** |
| 404 页 | — | ThinkPHP 404 页带版本横幅（`ThinkPHP V6.1.1`） |

## 2. Whoops 环境变量提取（核心）

Laravel debug 异常页 HTML 的 Environment Variables 面板含 **$_ENV 实际值**（不只键名）：
- `DB_PASSWORD`、`APP_KEY`、`DB_HOST/DATABASE/USERNAME`、`APP_URL`、`SERVER_ADDR/SERVER_NAME`（内网 IP）、`DOCUMENT_ROOT`、`SESSION_DRIVER`、`MAIL_*`
- 提取正则（值在 sf-dump span 里）：
  `<td>([A-Za-z0-9_]{2,60})</td>\s*<td><pre[^>]*>(.*?)</pre>` 再取 `class="sf-dump-str"[^>]*>([^<]*)</span>`
- 页面很大（20-50 万字符）：用 page_eval 分块读 outerHTML（每块 15KB）落盘再正则。
- **APP_KEY 是 Laravel 加密基础**：可解密 session/cookie；CVE-2018-15133（unserialize RCE）仅 Laravel 5.5-5.6.30，5.6.30 后 EncryptCookies 不再反序列化——先版本指纹再决定是否用 phpggc。

## 3. 路由枚举 oracle 与陷阱

- **POST 到任意路径 → 405 Whoops = 路由存在**——但**带 catch-all 短链/单路由的应用全部假阳性**（catch-all 匹配一切 GET，POST 全 405）。必须 GET 再测：真实路由返回 HTML/JSON，catch-all 无效码返回 "0"/404。
- 版本指纹：异常页堆栈行号（RouteCollection.php methodNotAllowed ~242-255 → 5.8/6.x）、vendor 路径、`fideloper/proxy`（TrustProxies，5.x-6.x 标志）。
- composer.json/vendor/installed.json/.env 通常被 nginx 404 挡；`/index.php/xxx` PATH_INFO 可控可确认但注入会被 nginx 特殊字符拦截（见下）。

## 4. RCE 探测顺序

1. **CVE-2019-11043（PHP-FPM）**：PATH_INFO 可控 + nginx fastcgi_split_path_info 时试；快速判定 = `?a=` + N×`%0a`（N=1..2000）全 200 OK 则 PHP≥7.4 已修复，放弃。
2. **CVE-2018-15133（Laravel APP_KEY）**：版本 5.5-5.6.30 才适用；phpggc `Laravel/RCE1-9` 按版本选 gadget；payload 放 X-XSRF-TOKEN。
3. **Ignition RCE（CVE-2021-3129）**：`/_ignition/*` 常被 nginx 单独 deny（404）——先确认端点可达再谈 gadget。

## 5. nginx/宝塔部署特征

- **nginx 路径层拦截**：路径含 `'` `"` `%00` `..` 等特殊字符直接 404/400（请求到不了 PHP）——**路径参数 SQL 注入被挡死**，改走 query/body 或放弃。
- 宝塔面板 8888：domain.conf 域名限制（Host 头校验，IP/localhost/已知子域全拒）+ 未备案域名 8888 显示 ICP 拦截页。
- 宝塔 MySQL 3306 对外开放但**用户绑定 localhost**（远程 Access denied）——远程爆破无意义，突破口是应用 RCE 后本地连库。
- **登录接口 error() 分支崩溃 ≠ 接口全坏**（如 TP6 `Undefined property: think\facade\App::$config`）：失败响应 500 崩溃页、**成功路径可能正常返回 JSON**——需要正确凭据+验证码才能区分，别误判为"登录不可用"。

## 6. 验证码处理

- 图形验证码（200x62 干扰线）：tesseract 多预处理（二值化/反色/中值）仍失败就 **MEDIA 发图给用户人工识别**（用户可协助），配合泄露密码组合试登录；验证码需带 session cookie 获取。
- 登录接口崩溃时响应无法区分"验证码错/密码错"——每尝试都要新验证码。

## References

- `references/8gtg-embracedream-chain.md` — 实战链路：8G 盘 → 8gtg.vip(Laravel .env 泄露) → 源站 47.107.94.222(阿里云) → CRMEB/TP6.1.1 dysjkcom 库、失败路径清单。
