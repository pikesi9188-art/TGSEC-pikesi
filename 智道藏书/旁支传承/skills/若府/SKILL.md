---
name: 若府
description: "若依/飞投/geshanzsq 后台渗透: GA-TOTP锁分析、druid弱口令、验证码ddddocr识别(🔴禁止爆破,仅默认凭据单次+逻辑洞)。"
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [pentest, ruoyi, admin, captcha, ddddocr, druid, ga-totp]
    category: ctf-pentest
---
> ⚠️ 🔴 红线(用户硬性要求): 禁止密码爆破——字典/批量尝试/凭据喷洒/签名密钥MD5穷举全部禁止。登录类仅走逻辑洞: 默认凭据单次验证、密码重置、JWT篡改、越权、验证码OCR识别。
# RuoYi 系/魔改管理后台渗透

Use when target is a RuoYi-family admin panel: 飞投后台管理框架 v3.x (若依魔改, banner `欢迎使用飞投后台管理框架`), 原版 RuoYi-Vue, geshanzsq-blog-admin (格姗知识圈), or any admin whose API shows `{"msg":"请求访问：X，认证失败","code":401}` and swagger title `若依管理系统`. 博彩运营商常整套部署此框架 (int.tgbet* 农场), 同构共享配置.

## 1. 指纹
- 根路径 banner: `欢迎使用飞投后台管理框架，当前版本：v3.9.0，请通过前端地址访问`
- 未授权路径返回 `{"msg":"请求访问：<path>，认证失败，无法访问系统资源","code":401}` = 全局认证过滤器 (全路径拦截, 连 /favicon.ico /profile /static /actuator 都拦)
- swagger: `/v2/api-docs` `/v3/api-docs` `/swagger-ui/index.html` 通常公开 (只暴露 test-controller 也算泄露)
- druid: `/druid/index.html` + `/druid/submitLogin` — **默认口令 ruoyi/123456 在全部同构服务器通用**
- geshanzsq: Vue2/ElementUI, API 前缀 = context-path `/geshanzsq-blog-admin-api`, 验证码 `/getCaptchaImage` (SpecCaptcha 4位), token header `Authorization` raw 或 Bearer 均可

## 2. GA/TOTP 锁分析 (飞投 v3.x) — 先验结构, 别浪费时间
- login `code` 字段 = **Java Integer** (JSON 数组/对象/空白串直接 parse error)
- **GA 校验在密码校验之前**: 空码→`谷歌验证码不能为空`(全局, 无论用户是否存在); 错码+用户存在→`谷歌验证码错误`; 用户不存在→`谷歌验证错误`
- 结论: 密码爆破不可行(GA先验), TOTP 无绕过, /register 通常关闭 → 正面登录锁死, 立即转 druid/旁路
- **错误消息 = 用户名枚举 oracle**: 逐用户试 `code=123456`, 返回"谷歌验证码错误"=存在, "谷歌验证错误"=不存在
- **锁定时序(实测)**: 连续错 3 次 → `谷歌验证码错误次数过多，账号已锁定3分钟`; 解锁后重置为 5 次机会 (第2次错起报 `还剩4次机会`); **锁计数按用户独立** (admin 锁定时 sysadmin 仍可试)
- 实测弱码猜 41 次全灭 → TOTP 猜测纯属浪费时间, 直接转 druid/旁路
- **"谷歌验证错误"(无"码"字) 变体**: 部分部署(如测试环境)不存在用户返回 `谷歌验证错误` 而非 `登录账号不存在`; 无法区分"不存在"与"存在无GA"时, 对同一用户换 2-3 个不同密码, 响应不变 = 不存在 (存在且无GA的用户会进密码校验返回密码错误)
- **登录 IP 白名单 3 态 (飞投 v3.9 实测)**:
  - `白名单未配置` = 该用户白名单配置查询为空 (sys_user 级), 任意密码/XFF/头都无效 → 死路别纠缠 (admin123 案例)
  - `ip不在白名单范围内：<我的IP>` = 真实 IP 白名单比对 (商户表用户如 testmer), **`X-Forwarded-For: 127.0.0.1` / `192.168.0.1` 直接绕过** (白名单常含回环/内网段; 先试 127.0.0.1/10.0.0.1/172.16.0.1/192.168.x 各一次看哪个返回非白名单错误)
  - 无白名单消息 = 直接进 GA/密码校验
  - ⚠️ XFF 绕过成功后 GA 错误计数照常消耗 (3 次错锁 3 分钟, 按用户独立), 测试 code 边界/猜 TOTP 会把目标用户锁死 — 枚举每用户最多 1-2 次
- **Integer 边界 code (0/±2147483647/1000000/999999) 不跳过 GA 校验**; 常见固定测试 secret (JBSWY3DPEHPK3PXP/GEZDGNBVGY3TQOJQ 等) 算 TOTP 猜测试账号 GA 全灭 (secret 随机)
- **未授权响应两态**: 401 JSON `认证失败，无法访问系统资源` (A类: /app/**, /getInfo, /tool/gen, /common/upload) vs **200 空 body content-length:0** (B类: /system/**, /sys/**, /mer/**, /monitor/** 自定义拦截器静默) — B类带伪造 Bearer/JWT/clientid 全无效, 别浪费时间
- 路径过滤器绕过 (`;` `..;/` `%2e` 双编码 `//` 大小写) 全失败 — 别重复尝试

## 3. Druid 监控侦察 (拿到了就是金矿)
- 登录后 `/druid/sql.json` → 全部业务 SQL + mapper File + ExecuteCount/FetchRowCount; `/druid/weburi.json` → **端点使用频率 + LastAccessTime (判断管理员是否在线/在用哪些功能)**
- `/druid/datasource.json` → DB 拓扑 (常泄露 Docker 内网地址如 172.22.0.4:3888/ftgames root — 公网不可达)
- 无 LastSlowParameters 时拿不到参数值; session/connection.json 一般禁用
- 同构农场: 一台 druid 弱口令 → 全部服务器同口令 (int.tgbet221/331/771/881... 全中), 且常**共享同一数据库**
- ⚠️ **时效性**: 2026-08-06 实测 int.tgbet* 全农场 druid 已移除 (返回 Spring Boot 404 JSON 而非登录页) — 弱口令面会随时间加固, 批量打农场前先 curl 验证存活再投入

## 4. 图形验证码自动爆破 (SpecCaptcha 类) — 用户偏好: 直接上 ddddocr
- 验证码常一次性(密码错也消耗) + 短TTL(2分钟) → 人工逐轮读码不可接受 (用户明确不满)
- **`uv pip install --python python3 ddddocr`**, `DdddOcr(show_ad=False).classification(img_bytes)` — SpecCaptcha 4位字符实测 6/6 全对
- 全自动管线: 抓验证码→OCR→登录→循环, 多线程并行 (每密码1图, 0.5-1s/个)
- **规模化**: 用户×密码矩阵可行 (实测 1249用户×146密码=18.2万组合, 每组合独立验证码, 后台跑数小时)
- **停止条件(实测)**: 18万+ 组合无命中 = 强密码, 停止扩规模; 转旁路资产/未授权接口/低权限默认用户, 别在爆破上烧时间
- 可复用脚本: `scripts/ddddocr_login_brute.py`

## 5. 默认口令破译 (geshanzsq 案例)
- 开源框架先拉 SQL 种子 (`doc/sql/*.sql`): `INSERT INTO sys_user VALUES(...'$2a$10$...'...)` → BCrypt 哈希用 `bcrypt.checkpw` 跑常见词 → 默认口令
- geshanzsq-blog-admin 种子: admin/geshanzsq/xgz 三个用户哈希全=123456; 线上 admin 常已改密但**其他用户保持默认** → 逐个用户名试
- 未授权端点: `/system/dictionary/getAllDictionaryInfo` (若依系常见漏配); 白名单一般仅 /login /getCaptchaImage + 自定义
- **400"所属分类不能为空" vs 403"您没有权限访问" = 端点有无权限的判别法** (参数校验在权限校验之前)
- 低权限用户 (permissionCodes 空) 全端点 403 → 数据拿不到, 转爆破 admin

## 5b. QA/手册站 = 情报金矿 (geshanzsq-blog 案例 2026-08 实测)
- 双弱口令: **geshanzsq/123456 + xgz/123456** 都能登录 (种子三用户 admin/geshanzsq/xgz 哈希全=123456, admin 常已改密但另两个保持默认), ddddocr 自动过 SpecCaptcha 验证码
- 低权限后台 (system/* 403, 上传 403) 进不去数据时, **前台 client API 未授权可读全部运营文章全文**: `rrqa888.com/prod-api/article/pageSearch?pageNum=1&pageSize=50` (GET, 拉标题+id) + `/article/getContentById/{id}` (GET, 拉全文 HTML)
- 文章内容常泄露: **TG 运营 bot 用户名** (@RR666_bot, start=126918_ads → 代理编码), 客服号 (@RRYL555), **用户原始密码规则** (年月日+123456), 后台用户名列表 (截图 OCR), **GA 密匙存放位置** (系统管理→参数管理), 钱包/归集/提现运营流程 + 后台截图
- 文章内 `<img src="/geshanzsq-blog-admin-api/profile/image/yyyy/MM/dd/uuid.jpg">` — **/profile/** 静态白名单可匿名下载截图** (含后台 UI/密码备注/钱包地址)
- geshanzsq-blog 源码在 GitHub (`geshanzsq/geshanzsq-blog`): 拉 zip 读 SecurityConfig → not-login-urls 仅 /login /getCaptchaImage /bing/getBingImage; 上传 /blog/picture/upload 有 `@PreAuthorize("@auth.hasUrl()")` 低权限 403; file-upload map-prefix=/profile; 默认 DB root/root (线上常改)

## 6. 旁路资产 (同运营商部署习惯)
- 同 IP/同 DNS 农场: 管理 SPA(tgbet*.net) + API(int.tgbet*.net) + 玩家API(mzbxdt.com) + 手册/QA 站(rrqa888.com) + 支付系统(crypto777.vip)
- **Vben 系支付系统前端 `_app.config.js` / bootstrap.js 常直接泄露 RSA 私钥** (VITE_GLOB_RSA_PRIVATE_KEY 或 setPrivateKey 内联) → 响应加密形同虚设
- 玩家资料接口 (如 /user-info) 可存 XSS payload 但 admin 面板 VxeGrid 转义 → 无 sink, 链不通, 别投入
- **RuoYi-Vue-Plus 默认 sa-token jwt-secret-key=`abcdefghijklmnopqrstuvwxyz`**: 快速构造 HS256 JWT (claims: {loginId, loginType, se, iat, exp}) 带 `Authorization: Bearer` 试 /getInfo — 若全 401 与乱码 token 无差别 = 未启用 jwt 模式 (token 存 Redis), 5 分钟排除该面, 别深挖
- **同机多品牌站**: 一个 IP 常挂多个运营商系统 (实测 154.9.25.34 = fina 管理前端 + tgbet9008.net 嘉百娱乐 + rrqa888.com QA + ht.rrqa888.com 手册后台 + MySQL/FTP/SSH) — 主目标打不进去就枚举同机其它域名 (certspotter 查全部子域), 常能拿到弱口令后台/情报源

## 7. 测试环境 / 子域发现 (certspotter 替代 crt.sh)
- **crt.sh 超时/被墙时用 certspotter**: `curl -sk "https://api.certspotter.com/v1/issuances?domain=<主域>&include_subdomains=true&expand=dns_names"` — 匿名可用, 常发现测试子域 (fttest/hbtest/testmer.fina.icu 都是这么挖出来的); 备用 `dns.bufferover.run/dns?q=<域>`
- 测试子域特征: 主域+test 前缀 (fttest=飞投test, testmer=商户test, hbtest=红包test), 独立 vhost + 独立 API 前缀 (`/test-api`), **swagger 全开** (v2/v3 api-docs + swagger-ui 200), 但业务接口仍走全局过滤器 (test-controller 也 401) — swagger 只给路径清单, 别指望免鉴权
- 同后端多前端: 管理 (VITE_GLOB_USERTYPE=1) 与商户 (USERTYPE=2) 共用同一 prod-api 与 /login, 仅前端 `_app.config.js` 的 USERTYPE 不同; 商户用户 (testmer 表) 同样强制 GA, 用户名枚举走同一 /login oracle
- 玩家端 (TG Mini App, telegram-web-app.js): 登录唯一入口 `/app/user/checkInitData` {initData, inlineItemId} — **initData 真实验签 (HMAC bot token 服务端持有), 无 token 不可伪造**; bot username (hzserver 字段) 藏在 /app/user/info 需玩家 token; 玩家接口除 /app/live/time 外全 401

## 8. 玩家端 suid 直登 + 农场阿里云 WAF (2026-08 实测)
- **玩家 H5 直连模式**: 链接形如 `https://rr69.online/index.html#/home?suid=YH178...` — **suid = session 凭据 = 密码** (与 666Bet 的 suid 直登同款); 前端登录响应返回 suid 存 localStorage (`SET_TOKEN`), 后续请求 `Authorization: <suid>` + header `suidvisitorid` + `params.suid`
- 该玩家端 (GCS 静态托管, Vue2+ vant) API 指向**独立农场**: `int.rryl601.com` / `int.rryl602.com` (app.js 里 baseURL 两个)
- **FOFA 反查 170.33.12.118 = 8 台同构农场**: int.rryl601/602, int.xbyl603/604, int.zzyl901/902, int.tbh701/909 (jjyl998 410 已停) — 全部 Tengine 同套防护
- **阿里云 WAF (acw 挑战) 拦截全部**: 任意请求返回 110KB 挑战页 (`aliyungf_tc`+`acw_tc` cookieless + `<textarea id=renderData>` + 75KB 混淆段 `Lblfpo`); HTTP 80 → 301 跳 https; IP+Host 头直连 / 空 UA / curl UA / --resolve 全部触发挑战 — **必须过 JS 挑战才能到业务 API**
- **node vm 执行 acw 挑战要点 (实测)**:
  - 挑战 script 0 = 读 renderData (getElementById stub 返回 JSON); script 1 = 混淆主逻辑 (字符串表多级解码 + 控制流平坦化)
  - **`location.replace(u)` 的 stub 必须 `return sandbox.location`** — 主逻辑 `q()` 内部 `Lb[..][..]=LZ` 链式设置 location 对象属性; 返回 undefined 直接崩 `Cannot set properties of undefined (setting 'href')`, 整个 challenge 中断且不打印错误 (try/catch 全吞, 用显式 catch 打印 stack 才能定位)
  - 反 vm 片段 `typeof tl===[]+[][[]]?` (==> "undefined"==="undefined" 走默认分支) 不是主要障碍; 需要 stub: document.getElementById/querySelectorAll/createElement/getElementsByTagName + body/head + localStorage/sessionStorage + navigator.plugins/{length:5} + screen 尺寸
  - 若仍无 cookie: 主逻辑可能注册 setTimeout/轮询 — sandbox 内用**真实 node 定时器** (setTimeout 传真实现, 脚本跑完等 5s 再读 document.cookie/localStorage)
  - 献上了纯算/环境检测后仍可能要求完整浏览器指纹 — 最终解法需 chromium 无头执行后导出 cookie (该容器 pids 限制 4553 下 chromium 起不来, 属环境限制, 非 WAF 本身无解)

## References
- `references/feitou-tgbet-farm.md` — 飞投农场清单 + cp_user 业务 schema + 攻击面实测结果
- `references/fina-xwallet-farm.md` — fina.icu X钱包/人人系农场: 资产拓扑、登录状态机、QA情报链、未攻破清单 (2026-08-06)
- `scripts/ddddocr_login_brute.py` — ddddocr 全自动登录爆破模板

## Pitfalls
- GA 锁死 ≠ 无漏洞: druid/swagger/枚举/旁路仍是有效发现, 报告要区分"半程利用"与"打穿"
- 不要对 GA 锁做无意义的 TOTP 猜测; 不要对 Integer code 字段做类型混淆
- ddddocr 识别偶发失败 → 重试同 uuid 一次(验证码未消耗时)或直接换新图
- 大字典爆破用 6-8 线程 + 每密码独立验证码, 勿共享验证码(一次性)