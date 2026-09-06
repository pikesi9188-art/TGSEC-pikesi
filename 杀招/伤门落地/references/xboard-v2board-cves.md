# Xboard / V2Board 系机场面板漏洞速查

触发：目标是 Xboard（v2board 二次开发）VPN/机场面板。前端特征 `/theme/Xboard/assets/umi.js`（1.3MB 左右），版本号形如 `20260826-8ecb762`（日期+commit）。登录页标题常带品牌名（如「极卫」）。

## 版本与攻击面获取
- 前端 umi.js 可被 CF 缓存/浏览器直取（curl 可能被拦，headless Chrome 过 JS challenge 可拿）。
- 版本号：首页 HTML 内 `window.settings`、umi.js 内都含版本；`grep -oE '2026[0-9-]*|8ecb762'` 可定位。
- API base 拼接：`(window.routerBase||"/") + "api/v1"`；grep umi.js 提取全量端点（/user/*、/admin/*、/passport/*、/client/*、/server/*）。

## CVE-2026-37505 — Admin ORDER BY SQL 注入（高危）
- 位置：POST `/api/v1/admin/user/fetch`，`sort[].id` 未白名单直接拼 ORDER BY。
- POC：`{"page":1,"pageSize":10,"sort":[{"id":"(SELECT password FROM users WHERE email='x' LIMIT 1)","desc":false}]}`
- 前置：需要 admin token。可拖 users 表密码哈希/邮箱/余额/订阅 token；DB 高权限可 INTO OUTFILE 写 shell → RCE。
- 修复：sort.id 白名单 + `orderByWhiteList`。

## 主题上传 Zip Slip → 任意文件写入/RCE（高危）
- 位置：POST `/api/v1/admin/theme/upload`。
- 原理：ZIP 内 `config.json` 的 `name` 未清洗，拼 `base_path('storage/theme/')`，`../../../public/uploads` 可写出 web 目录 → PHP webshell → RCE。
- 前置：需要 admin token。管理员→RCE 最短链。
- 修复：`basename()` + 正则 `^[a-zA-Z0-9_-]+$` + realpath 校验。

## 中危项
- 前端 umi.js 泄露全量 API 端点（30+）。
- `server_token` 出现在 URL（`/api/v1/admin/server/machine/getToken/{id}`），被 nginx 日志记录 → CVE-2026-37504。
- `custom_html` 存储型 XSS → CVE-2026-37503。
- 管理后台路径基于 `hash('crc32b', config('app.key'))` 可预测（需 app.key 泄露）。

## 已修复（别浪费时间去打）
- CVE-2026-39912 未授权账户接管（loginWithMailLink verify 参数泄露）——2026-04-09 已修复。

## 防护特征
- 常前置 Cloudflare WAF：`/api/` 路径级全拦（静态放行、API 403），需找源站或 admin token。
- 前后端均有 Turnstile/reCAPTCHA；密码错误 5 次锁 60 分钟。

## 源站溯源线索
- 节点子域带独立 Let's Encrypt 证书（n2/n3/e2.ji-wei.com 类命名），FOFA `cert="域名"` 可反查节点 IP；节点服务器可能带宝塔面板（888 端口）。
- 邮件服务器/SPF include 常指向托管商共享 IP。
- 域名新注册时无历史 DNS，只能靠 FOFA cert 反查 + 子域证书枚举（certspotter/crt.sh）。
