---
name: 租云
description: "Use when 打多租户SaaS/云平台: 临时邮箱注册→会话→租户隔离(BOLA/IDOR)→明文密钥存储→侦察。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, saas, multitenant, bola, idor, api]
    category: ctf-pentest
---
# 多租户 SaaS 平台渗透 (类级总纲)

适用: 目标是多租户云平台(每个用户一个 project/tenant, 数据按租户隔离), 常见于加密交易机器人、量化/跟单、TG 托管、SaaS 后台。核心目标通常是"全平台用户密钥/数据"。

## 触发条件
- "平台所有用户的数据/API密钥/订单/钱包" / "打穿 SaaS" / "租户越权"
- 已确认授权(与 pentest-workflow 一致, 仅 authorized scope)

## P0 资产面 (先画地图再动手)
1. 营销站(Webflow/静态) ≠ 攻击面; 找 `app.*` SPA + `api.*` 后端
2. 抓 SPA bundle(`/assets/main-*.js`), 提取:
   - API base (`https://api.<domain>/api`)、WSS base、硬编码 hostname map(找**兄弟环境**: staging/dev/beta/typhoon 类, `app.typhoon-dev.org` 这类 dev 后端常独立且更弱)
   - OpenAPI 客户端操作名(`postXxx`/`getXxx` 正则 `\b(get|post|put|patch|delete)([A-Z]\w+)\s*[:({]`) → 全端点地图
3. **FastAPI 指纹 → 直接拉 `/api/openapi.json` + `/api/docs` + `/api/redoc`**(常全公开):
   - 101+ 路径, securitySchemes, 每个 op 的 `security: null` = 公开
   - 重点找: 返回明文密钥的 schema(`AccountReadSchema` 类: api_key/secret_key/passphrase 同响应返回)
   - 注意 query/header 参数差异: 有的端点缺租户 header(潜在隔离缺口)
4. S3/CDN 子域: `cdn.<domain>` 常是公开 ListBucket(逐前缀枚举 users/keys/admin/backup)

## P1 注册拿合法会话 (临时邮箱绕过验证码)
邮箱验证码注册/找回流程 → **不用爆破验证码(2次错误即429), 直接收信**:
1. `api.mail.tm`: `POST /accounts {address,password}` → `POST /token` → `GET /messages` / `GET /messages/{id}`
   - 响应是 hydra:Collection, 邮件在 `hydra:member`; 验证码在 `text` 里, 6位数字, 秒级送达
2. 注册: `send_mail` → 收 code → `confirm` → `POST /auth/token` (OAuth2 password grant)
3. **助手输出坑: terminal 输出会把 JWT/长 token 截断成 `eyJhbG...wU2M`** → 所有含 token 的响应必须 `curl -o file` 落盘后再用 python 解析文件, 绝不能从 stdout 解析
4. 建租户: 多租户平台注册后需自建 project/tenant 才有数据上下文(如 `POST /projects/`)

## P2 租户隔离测试矩阵 (BOLA/IDOR 系统化)
拿到自己租户 id 后, 每个数据端点按此矩阵测:
1. **基线**: 自己租户 id → 200; 不存在的 id(1..30)→ 404 → 注意"非成员"和"不存在"可能都返回 404(用邻居 id 对比区分)
2. **枚举**: `X-TENANT-ID` 头用数字自增 / 字符串名(前端默认租户串如 "origami-tech")各试一遍; 列表端点 vs 单对象端点分开测
3. **ID 空间判断**: 新建对象拿自增 id → 测 id±N 邻居(若全局连续, 邻居=别人数据)
4. **邀请横向**: `invites/confirm/{id}` 全 id 扫 → 确认是否校验**收件邮箱**(绑定校验则 404, 无校验则可强行加入任意项目)
5. **成员/角色端点**: `PUT members/{username}`、role 枚举(Owner/Admin/Editor/Viewer) 是否越权改角色
6. **隐藏参数**: openapi 里没列出的 query(project_id/user_id/all) 全试一遍
7. **旧版 API**: JS 里残留 `/api/v1/*` 路径常已下线(404), 但值得确认

## P3 密钥/数据端点 (核心目标)
- 找 `accounts`/`keys`/`wallets` 类端点: 响应 schema 是否含 `api_key`/`secret_key`/`passphrase`/`privateKey` **明文**
- 若创建账号会**回源校验真实密钥**(如调交易所 API)→ 错误响应会泄露内部代理 IP(如 `proxy_ip":"10.4.2.96:8089"`) → 记入内网情报
- 前端 localStorage: 搜 `auth_state`/`privateKey`/`createRandom` → 客户端存 token/钱包私钥 → **拿到 XSS 即全盘**, 列为剩余攻击面
- JWT: decode header/payload(HS256, sub=邮箱); 测 alg=none + 常见弱密钥; 密钥强且 alg 校验则跳过
- 限流: 登录/确认端点通常 3 次/窗口 → 429, **XFF/Forwarded 头无法绕过**(CF 按真实 client IP 限) → 爆破需代理池轮换, 放最后

## P3.5 Firebase 后端平台 (altfins/goodcrypto 类)
平台用 Firebase(前端 firebase_cfg.json 含 apiKey/authDomain/projectId)→ 直连 Google REST:
1. **拿 apiKey**: 从 bundle 提取 firebaseConfig(apiKey 通常被 domain-restrict, 但 projectId/appId 可拿); `firebase_cfg.json` 结构: {apiKey, authDomain, projectId, storageBucket, appId}
2. **登录**: `POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={apiKey}` body {email,password,returnSecureToken:true} → idToken/refreshToken/localId(UID)
   - **403 处理(实战踩坑)**: ① `API_KEY_HTTP_REFERRER_BLOCKED` → 加 `Referer: https://<domain>/` + `Origin` 头可过; ② `API_KEY_SERVICE_BLOCKED`(method 级禁)→ 换走 Web3Auth/OAuth 等其他认证路径, 该 apiKey 直连此方法已死; ③ `API_KEY_INVALID` → key 已轮换, 重新从最新 bundle 提取
3. **数据**: RTDB `https://<projectId>-default-rtdb.firebaseio.com/{path}.json?auth={idToken}`(读自己数据, 试 IDOR /users/{uid}); Firestore REST 需 App Check token(前端可提取)
4. **高价值**: 从 RTDB/Firestore 读回 RSA 密钥对/API key/订阅凭据(RevenueCat 类); 找 `firebase-adminsdk-*@<project>.iam.gserviceaccount.com` 私钥 → 全库读写
5. **token 有效期**: OAuth2/accessToken 会过期(实测 25h 后 401)→ 用 refreshToken 刷新(`POST /v1/token?key={apiKey}` grant_type=refresh_token)或重新走认证; 测试前先解析 JWT exp 判断是否过期
6. 案例: `references/altfins-goodcrypto-case.md` (Firebase 认证链+token+RTDB 数据)

## 基础设施侦察
- `/accounts/ip`、`/projects/proxy_ips` 类端点直接泄露代理池/源站 IP → nmap top200
- 主机命名规律枚举: `rb-{0..3}-ip{0..9}.<domain>`、`db./pg./redis./k8s.` 全 526(CF 源站证书失效)= DNS 存在但不可达
- FOFA: `domain="x"` 只有 CF IP 时, 用泄露 IP 反查; 公开代码搜索用 sourcegraph stream API(`/.api/search/stream?q=context:global+"api.x.com"`)
- WS: 根路径带 Origin+Authorization 可连但订阅 payload 全 "Bad request"(协议未知)→ 别耗时间, 记录后跳过
- SSRF 点: 自定义对接端点(`base_url`/`path`)先查 schema 是否枚举限定(enum 'API'/'ONBOARD' 类 = 无 SSRF)

## 收尾 (诚实交付)
- 证据落地: openapi.json + session_tokens + creds + infra(见 pentest-working-report)
- 报告 MD: 已达成 / 打不穿的墙(带验证矩阵) / 剩余方向
- **半程利用 ≠ 打穿**: ACL 严密、无 RCE/IDOR/JWT 弱点时明说"未达成全量数据"
- 案例: `references/origami-tech-case.md` (端点地图+测试矩阵+凭证路径)