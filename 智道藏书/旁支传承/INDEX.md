# 扩展包索引（按作业面）

路径：`智道藏书/旁支传承/skills/<name>/SKILL.md`

业务专链（假支付 / Actuator / GVA / ACG / Sticker 云控）命中时 **不要**先读本表。

## 1. 白标盘口家族（先认族再打）

| Skill | 指纹 |
|-------|------|
| `1z-gambling-family-pentest` | 1Z.com / qpuserapi / 点选 SVG captcha |
| `m8-manba-gambling-pentest` / `m5ba-manba-family-pentest` | 曼巴 / m8 |
| `m9-hsbox-gambling-pentest` | HSBox |
| `mm8bet-gen-whitelabel-pentest` / `gen-mm8bet-gambling-family` | MM8 / GEN 白标 |
| `dingyi-whitelabel-gambling-pentest` | 鼎艺 / verifyKey 注册 |
| `aks-gofun-gambling-pentest` | GoFun / 66U |
| `lsm-mclsm-gambling-pentest` | LSM |
| `daanrox-br-gambling-pentest` / `br-gambling-trpc-spa-pentest` | 巴西 tRPC SPA |
| `666bet-tma-pentest` / `kk8-tma-platform-pentest` / `wali-tg-tma-pentest` | 各 TMA 白标 |
| `laravel-gambling-tma-pentest` / `gen-rails-gambling-pentest` | Laravel / Rails 盘口 |
| `whitelabel-gambling-pentest` | 认不出具体族时的兜底 |
| `gambling-saas-pentest-workflow` | 加密 API / webpack 注入 / 宝塔 / 聚合商 launcher |
| `gambling-deposit-chain-pentest` | 绑卡+KYC+凭证伪造充值 |
| `gambling-password-reset-ato` | 盘口重置接管 |
| `gambling-platform-odds-audit` / `pc28-odds-ws-intel` | 盘口/PC28 |
| `gambling-api-crypto-reversal` | 前端签名 + 加密 WS |
| `pg-operator-session-chain` / `pg-soft-launcher-pentest` | PG Soft 聚合会话 |

Cursor 入口：`gambling-family-router`

## 2. 芋道 / 若依 / TMA

| Skill | 指纹 |
|-------|------|
| `yudao-tma-pentest` | `/runtime/app-config.js` + `/app-api/` + AES-ECB+RSA+`X-Ca-Token` |
| `yudao-web-appapi-pentest` | `/app-api/encrypt` + `sk_encrypt.json` |
| `telegram-gambling-tma-pentest` | `<title>Qzino</title>` + `POST /api.html` |
| `telegram-gambling-yudao-pentest` | 芋道后端的 TG 赌 bot |
| `tma-encrypted-api-reversal` / `tma-web-asset-discovery` | TMA 加密/静态资产 |
| `feitou-ruoyi-admin-pentest` / `feitou-admin-framework-pentest` / `ruoyi-fork-admin-pentest` | 飞投/若依叉 |

Cursor 入口：`yudao-appapi-pentest` · `telegram-tma-gambling`

## 3. TG 云控 / 营销 / 支付通道

| Skill | 何时 |
|-------|------|
| `tg-cloud-control-pentest` | 「系统选择」+ `/tgcloud_pc` + OSS STS（与 Sticker/Fernet 族不同） |
| `tg-bot-pool-panel-pentest` / `tg-marketing-saas-pentest` | Bot 池 / 营销 SaaS |
| `tg-payment-channel-pentest` / `tg-card-license-backend` | TG 支付通道 / 卡密授权 |
| `telegram-bot-discovery` | 找 bot / Mini App 入口 |
| `tg-account-session-intake` | 投递 `.session` / 发货包验活（本库根 `_tg_accounts/`） |
| `tg-account-library-ops` | 按区号清库 / zip 重建 |
| `autonomous-social-engagement` | 技术面穷尽后盯 TG 对接人推进 |

Cursor 入口：`tg-account-library` · `tg-social-engage`

Sticker / Fernet / `:8000` 仍走现有 `tg-cloud-panel`。

## 4. 支付 / 发卡 / 加密网关

| Skill | 何时 |
|-------|------|
| `epay-admin-pentest` | 「支付管理中心」/ `api.php?act=` / `admin_login.lock` |
| `faka-card-shop-pentest` / `faka-shop-pentest` | 非异次元发卡（异次元仍走 `acg-faka`） |
| `encrypted-api-gateway-reversal` | `/app-api/encrypt` + 静态密钥文件 |
| `spa-protocol-reverse` / `spa-frontend-reversing` / `spa-backend-api-pentest` | SPA 协议 |
| `js-reverse` | 前端签名/密钥 |

Cursor 入口：`encrypted-api-spa`；假支付矩阵仍走 `payment-callback-forgery`。

## 5. 认证绑死 / 多租户

| Skill | 何时 |
|-------|------|
| `account-takeover-chain` | API key 绑 token、IDOR 直读失败 |
| `register-bypass-idor` | 注册绕过 + 越权 |
| `saas-multitenant-pentest` / `saas-multitenant-acl-testing` / `saas-signup-multitenant-testing` | 多租户 ACL |
| `oauth2-password-grant-login-testing` | OAuth password grant |

## 6. 框架 / 面板 / 调试泄露

| Skill | 何时 |
|-------|------|
| `laravel-pentest` / `laravel-api-auth-probing` | Laravel debug / APP_KEY |
| `php-debug-mode-exploitation` / `php-framework-debug-leak-pentest` | Whoops / `.env` 异常页 |
| `bt-panel-pentest` | 宝塔 8888 / 安全入口（细于现有面板探针） |
| `supabase-pentest` / `supabase-rls-pentest` | Supabase / RLS |
| `cloud-metadata-harvesting` | SSRF → 云元数据 |

## 7. 路由 / 工作流（本包内部）

`attack-router` · `skill-routing` · `nine-stage-auto-router` · `pentest-workflow` · `target-triage` · `mcp-toolkit-router`

大爱仙尊作业入口仍是 `keyword-router` / `campaign-router` / `extended-skill-router`，不要把外部路径当命令跑。
