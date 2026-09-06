---
name: 行库
description: "Supabase/PostgREST 全链渗透：anon key提取→RLS审计→GraphQL绕过→security-definer RPC IDOR→邮箱确认JWT(GET verify坑)→Storage bucket→Vault→业务API信任user_id→多环境/多项目→PGRST hint表名枚举。触发：supabase.co、PostgREST、RLS、PGRST2xx。"
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [supabase, rls, postgrest, api, pentest, saas]
    category: daaixianzun
---
# SKILL: Supabase / Postgres-RLS SaaS Penetration Testing

## 适用范围
目标后端是 **Supabase**（或自托管 PostgREST + GoTrue + PostGraphile）时的 authorized pentest。
典型信号：前端 JS 里有 `supabase.co` URL、`eyJ...` anon key、`/rest/v1/`、`/auth/v1/`、`/graphql/v1/`、`/storage/v1/`、`/functions/v1/` 端点。

> 与 `api-security`（通用 REST/GraphQL）、`jwt-oauth-token-attacks`、`unauthorized-access-common-services` 联合用。本 skill 专注 **Postgres RLS / Supabase 专有攻击链**。

## 核心思维：多入口权限面
Supabase 有多个并存的 API 入口，**每个入口的 RLS/权限可能不同**，分开穷举：
1. **PostgREST** `/rest/v1/` —— 标准 REST，列/表/行级权限体现为 401/42501/空
2. **GraphQL (PostGraphile)** `/graphql/v1` —— 可能绕过 REST 的表级 GRANT（写操作例外），schema 完整暴露
3. **Storage** `/storage/v1/` —— bucket 对象列表可能可枚举
4. **Edge Functions** `/functions/v1/` —— 走函数级 auth
5. **RPC** `/rest/v1/rpc/<fn>` —— security-definer 函数可能绕过 RLS（IDOR 高发）

## 0. 提取 anon key
- 从 JS bundle 抓所有 `https://<ref>.supabase.co` 和相关长 JWT。
- anon key 是 HS256 JWT，payload 含 `{"role":"anon","ref":"<project_ref>"}`。
- 用 `apikey: <key>` + `Authorization: Bearer <key>` 两个 header 调用。
- 注意多环境：web app 一个 project，mobile 可能有 dev/staging 另两个 project（不同 RLS 配置，全部测）。

## 1. 表发现与 RLS 审计（REST）
- 猜表名 `GET /rest/v1/<table>?select=*&limit=1`：
 - `PGRST205` + **"Perhaps you meant the table 'public.X'"** → 泄露真实表名（hint 是金矿，迭代枚举）
 - `content-range: 0-N/total` + 数据 → **该表 RLS 缺失 / 该角色可读全量**（高危）
 - `[]`（空 array，200，content-range `*/0`）= 表存在但查询被 RLS 行级过滤 → 已保护
 - `42501 permission denied` = 表级无权限
- 用 `Prefer: count=exact` + `-D -` 抓 `content-range: 0-999/73765` → **拿到表总数**，判断泄露规模。
- **列级权限**：挨个 `select=<col>`，`42703`=列不存在；返回数据/42501=列存在且有保护。单列探测 = 列名枚举 + 权限探测一步完成。

## 2. GraphQL 入口（PostGraphile）—— 与 REST 权限不同
- 端点 `/graphql/v1`，`POST` + `{"query":...}`。
- 匿名 `__schema { queryType { fields { name } } }` → 列出全部集合。若有 `Mutation` → 读出所有 insert/update/delete + 业务函数。
- **关键：GraphQL 能看到列名**（REST 里 `select` 报 42501 的 `credentials`/`secret_key` 列，GraphQL 的 `__type(name:"<table>"){fields{name}}` 会列出）——用这个探明文密钥列是否存在。
- **GraphQL mutation 可绕过 REST 表级 GRANT**：REST insert 报 `42501`，但 GraphQL `insertInto<Table>Collection` 可能直接通过（返回 affectedCount）——写权限 vs 读权限**分开测**。要点：字段用 snake_case（`exchange_id`,`user_id`）；字符串值需正确 JSON 转义；RLS 行级 INSERT 仍拦他人 user_id（`new row violates row-level security policy`）。
- GraphQL RLS 流行保护：`node(nodeId:...)`、filter in/neq/or/not、cursor/last 分页 **都遵循 RLS**——PostgreSQL 层强制，无 SQLi / 无 service_role 时读他人行不可行。

## 3. security-definer RPC IDOR（高价值）
- `POST /rest/v1/rpc/<fn>` 带 JWT。
- **签名挖掘**：传错参数后 `PGRST202` 会 hint 真实参数名：`Perhaps you meant to call the function public.<fn>(<args>...)` / `Searched for the function public.<fn> with parameter <name>`。
- 找到 `settings_user_id` 这类**用调用方参数当身份**的函数 = **IDOR 读/写他人机密**。例如 `fill_user_settings_secrets(settings_user_id)` 能让任意 authenticated 用户获取他人加密 key 句柄 —— 能调即说明它漏校验 auth.uid()==settings_user_id（security-definer 校验严格会 42501）。**批量证明：对泄露的 user_id 列表逐个调，统计成功率**。
- 枚举别用超大词表（超时）；用 hint 链 + 已知业务函数名定向。

## 4. Supabase Vault / 加密密钥
- 密钥列（`exchange_credentials.credentials` 等）密文存在 **vault 表**，`/rest/v1` 不暴露 vault schema（`Accept-Profile: vault` 被 PGRST106 白名单挡回 public/storage/graphql_public/pgmq_）。
- 表列 `secret_key_id`（关联 vault secret）；解密需 `auth_secret` **实际值**——只有云后端 bot 运行时持有，外部拿了 `auth_secret_id` 也解不开。
- **写读不对称**：GraphQL 能 insert 凭证（可写），但 credentials 列 SELECT 对 authenticated 动态隐藏（schema 列出但查询报 `Unknown field 'credentials'`）——"写可入、读不可出"架构。

## 5. 邮箱确认 → authenticated JWT（拿高权限）
- Supabase `signup` 后 `mailer_autoconfirm:false` 需确认邮箱，响应无 access_token。
- **用临时邮箱**（mail.tm：`GET api.mail.tm/domains` → `POST /accounts` → `POST /token` → `GET /messages/<id>` 读 html 里 `token=`）。
- **必须 GET 访问 verify endpoint**（`/auth/v1/verify?token=..&type=signup&redirect_to=...`）才 303 回带 `#access_token=` 的跳转；**POST /auth/v1/verify 报 otp_expired 是坑**。GET 后拿 fragment，再 `POST /auth/v1/token?grant_type=password` 登录拿 JWT。
- JWT 会过期，用保存的账号密码重新登录刷新。

## 6. Storage bucket
- `GET /storage/v1/bucket` 列 bucket；`POST /storage/v1/object/list/<bucket> {"prefix":"","limit":N}` 枚举对象。
- bucket 列表 `[]` 不代表闭：枚举常见 bucket 名再 list 对象。公开 `object/public/<bucket>/<file>` 和 authenticated 路径都要测。

## 7. 排查清单
```
□ JS bundle 提取 supabase URL + anon key（多环境多 project_ref 全测）
□ REST 表名枚举 + error-hint 迭代 → 找 RLS 缺失表
□ 疑似缺口表 select 带 count → 拿总数
□ 列级权限扫描（select 单列 → 42501 vs 数据）
□ GraphQL introspect 全集合 + __type 列名（credentials/secret_key 明文列是否存在）
□ GraphQL insert/update/delete 测写绕过（先 RLS 行级, 后 secrets 触发器）
□ RPC 名字枚举 + signature hint 挖 → security-definer → 批量 IDOR
□ temp mail + GET verify 拿 authenticated JWT → 刷新
□ storage bucket 枚举 + 对象可读性
□ 结论: 明文密钥列若 RLS 行级保护无误 → 无法读他人（诚实交付, 不夸大）
```

## 8. 交付纪律
- 授权场景打到 **RLS 缺失的匿名大表** 或 **security 函数 IDOR** 即算突破，落证据文件 + PoC。
- 行级 RLS 无 SQLi 时明确写"无法横向读他人"，**不把"能动"说成"拿到了"**。
- 测试产生的记录（插入的凭证/密钥）用完即删，避免污染。

## ★ 优先测表（PGRST hint 迭代）

**优先猜测以下表名（最常漏 RLS）**：`user_profiles`/`profiles`、`users`、`exchange_credentials`、`user_api_keys`、`api_keys`、`credentials`、`user_settings`、`bots`、`bot_configs`、`subscriptions`

- `GET /rest/v1/user_profile` → PGRST205 "Perhaps you meant the table 'public.user_profiles'" → 真实表名泄露，反复迭代
- anon 匿名 SELECT 通但 INSERT 42501 = 只读泄露漏洞
- Expo/React Native web entry 常含完整 env 配置块：正则 `createBrowserClient`、`supabaseAnonKey`、`createClient(`
- 生产可能用自定义网关域名指向同一项目，直连网关即可（无需 supabase.co URL）

## ★ JWT 额外坑与升级面

- `GET /auth/v1/settings` 泄露支持的 provider → 可发现 OAuth 路径（Google/GitHub 等）
- refresh_token 刷新：`POST /auth/v1/token?grant_type=refresh_token {"refresh_token":"..."}`
- `POST /auth/v1/resend {type:signup,email}` 可重发确认码（有 429 限速）

## ★ 业务 API 信任 user_id（IDOR 面）

业务端点常 `POST {type:<op>, auth:{user_id, user_email, user_settings_auth_secret_id}, ...}`：
- **信任客户端传入的 user_id** = IDOR 面
- op 名在前端 `fetchBusinessApi(base, ctx, '<op>', params)`；返回 `"unknown request_type"` 可枚举 op
- Edge Functions `/functions/v1/<name>`：不存在返回 NOT_FOUND JSON

## ★ 加密密钥的上限

- `exchange_credentials` 可能连 authenticated 角色都无 GRANT SELECT（42501）
- 密文解密在 bot/worker 进程内，API 只返回 auth_secret_id 引用
- **`auth_secret_id`（解密句柄）≠ 明文**；这是 IDOR 上限，报告时明说

## Pitfalls

- `uid` 是 bash readonly 变量 → 用 `TUID` 等别名
- anon key 也能查公开内容表（exchanges/products/news）→ 先区分公开 vs 用户私有，别把公开数据当漏洞
- 跨项目 JWT 不通用（各项目独立 key），报 PGRST301

## 参考
- `references/octobot-cloud-case.md` — OctoBot Cloud 完整案例（74,644 用户泄露 + fill_user_settings_secrets IDOR + write-vs-read asymmetry）

## 真源

- 手法：`传承/万我·信门.md`
- 工具：`python3 炼蛊房/logic_vuln_probe.py --help`

