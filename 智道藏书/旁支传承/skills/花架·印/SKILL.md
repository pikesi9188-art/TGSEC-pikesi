---
name: 花架·印
description: "Laravel API 认证探测: AJAX头揭JSON错误, Bearer分析, 405路由枚举."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, laravel, api, auth]
    category: ctf-pentest
---
# Laravel API 认证探测 (CF 前置商户站)

## 触发条件
- 目标 Laravel 应用 (Whoops 错误页 / `Whoops, looks like something went wrong`)
- 公开面只有 `/api/*` 路由, 其他路径 nginx 404
- 某 API 路由裸请求 500, 或返回自定义 `{"code":1,"exception":"..."}` JSON 错误

## 核心技巧

### 1. AJAX 头揭示真实错误格式 (先做这步!)
裸请求 `GET /api/user` → 500 Whoops 页 (看似死路由)。**带 AJAX 头后语义完全不同**:
```
X-Requested-With: XMLHttpRequest
Accept: application/json
```
→ 返回 `{"code":1,"exception":"您未登录"}` **401** = 需要认证的接口, **不是死路由**!
- 规则: "无条件 500" 的 Laravel 路由必须先试 AJAX 头再下结论 — 500 Whoops 可能是认证中间件试图渲染重定向页失败
- 应用自定义错误格式 `{"code":1,"exception":"<中文信息>"}` — 所有探测都带这两个头, 响应可读性大增

### 2. 状态码语义矩阵
| 响应 | 含义 |
|---|---|
| 404 + `<center>nginx</center>` 146B | nginx 层 404 — 路由不存在 (非 Laravel) |
| 405 + Laravel MethodNotAllowed | **路由存在但方法错** (GET-only 路由 POST → 405) — 用这个枚举路由! |
| 401 + `{"code":1,...}` | 认证中间件拒绝 — 需要 token |
| 500 + Whoops/`{"message":"Server Error"}` | 认证"通过"但 handler 抛异常 (通常=无效 token 访问 null) |

### 3. Bearer token 分析 (判定可不可猜)
- 无 `Authorization` → 401 (未登录)
- **任意 Bearer 值 → 500** = 中间件只检查 Bearer 存在, handler 查 DB (users.token) 后访问 null → 崩溃
- 结论: 有效 token 在 DB 内, 无登录/注册/发放接口时**不可猜、不可枚举 — 直接停这条线**, 别浪费时间试 keys/os/pid/TGID/admin 等值 (全 500)
- 例外: 若某 Bearer 值让响应从 500 变成 200/JSON 数据 → token 找到, 继续

### 4. 路由枚举 (两段式)
- 对 `/api/<word>`、`/api/auth/<word>`、`/api/admin/<word>` 等前缀 × POST/OPTIONS/PUT/GET
- 命中判据: 非 404 即存在 (405 = GET-only, 200/500 = 存在)
- Laravel 资源路由可能多段: `/api/<word>/<sub>` 也要测
- 若 nginx 只代理 `/api/*`, 非 /api 路径全 404 — 后台只可能在 /api/* 下或另一域名

### 5. CF 前置目标的请求姿势 (重要)
- **Python urllib 默认 UA → CF WAF Error 1010 (403)**: 误判为目标封锁。一律用 `curl -sk` + 完整浏览器 UA (`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/126`)
- 大量请求时给 curl 加 `-H "Accept: application/json"` + `-H "X-Requested-With: XMLHttpRequest"` 统一风格
- 1010 出现 = 换 curl 重试, 不是目标 403

### 6. 源站发现 (后台可能只在源站)
- FOFA 只显示 CF IP 时: `curl api.hackertarget.com/hostsearch/?q=<domain>` 拿历史 DNS → 真实源站 IP
- 源站直连超时 (000) = 安全组仅放行 CF — 后台不可达, 别死磕; 这是常见配置不是漏洞

### 7. Laravel debug 模式开启 = 异常页即信息泄露 (高价值!)
生产环境 `APP_DEBUG=true` 时, 触发异常返回 **Whoops 完整堆栈页** (233KB+), 泄露:
- 应用绝对路径 (`/www/wwwroot/<site>/...` → 宝塔面板/部署结构)
- Laravel 版本、vendor 依赖清单、PHP 版本 (ThinkPHP 等框架同理)
- **Environment Variables 面板: .env 实际值!** DB_HOST/DB_DATABASE/DB_USERNAME/**DB_PASSWORD**/APP_KEY(base64:...)/APP_URL — 用正则提取:
  `<td>KEY</td><td><pre[^>]*>...class="sf-dump-str" title="N characters">VALUE</span>...`
- 触发方式 (生产无 /_ignition 也可触发):
  - **POST 到 GET-only 路由** → MethodNotAllowed 异常页 (如短链服务 `/shorten` 只接受 GET)
  - **访问 auth 中间件保护的 API 且 login 路由未定义** → `Route [login] not defined` InvalidArgumentException 页 (8gtg.vip `/api/user` 实测, env 面板完整)
- **MethodNotAllowed 异常页作路由枚举 oracle**: POST 任意路径若返回 Whoops(405) 说明路由存在; 但**有 catch-all 路由(如短链 `/{code}`)时全部路径都 405** → 改用 GET 区分 (有效短码 302, 无效返回 "0")
- **溯源链**: .env 的 APP_URL 常指向同运营方其他系统 → FOFA `domain=` 查该域全部子域 → 可能找到**无 CF 的源站 IP** (nginx 直连) → 端口扫 (21/22/3306/8888 宝塔) + 同源站其他管理系统
- 泄露的 DB 密码先做**凭据复用测试** (dy/red/wxshop 后台、SSH、宝塔), 即使 MySQL 3306 开放但用户绑定 localhost 拒远程也值得在其他系统试

## 陷阱
1. 不要把 500 Whoops 当死路由 — 先 AJAX 头
2. 不要把 CF Error 1010 当目标 403 — 换 curl 浏览器 UA
3. session cookie 可能不带认证状态 (Laravel 加密 cookie 但 auth 走 Bearer) — 别指望 cookie 链
4. 有效 Bearer token 无法枚举时, 找发放渠道 (TG bot / 登录接口) 而不是爆破
5. `/logs/` 301→403 = 目录存在但内容不可枚举 (nginx autoindex off), 常见文件名全 404 就放弃
6. 宝塔面板 8888 有 domain.conf 域名限制 (Host 头校验, 伪造无效) — 先试常见域名, 不行就放弃
7. **横向移动范围确认**: 从 .env APP_URL/源站发现的新系统 (同域其他管理系统) 动手前, 先向用户展示攻击链+归属推断确认授权 — 用户会质疑 "你打的哪个站"

## 参考
- `references/wsgame666-case.md` — 实测案例: PG SOFT 商户站完整探测记录 (请求/响应样本)
- `references/8gtg-embracedream-case.md` — 短链服务 Laravel debug → .env 泄露 → 源站溯源案例 (8g8888/kk8 博彩盘基础设施, 含 Whoops env 提取正则与源站端口/系统清单)
