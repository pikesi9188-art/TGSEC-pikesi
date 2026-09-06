---
name: 凤九歌·认族
description: >-
  大爱仙尊九阶段攻击链总路由。授权渗透/侦察/红队一句话任务时先读本卡，
  再跳本库 .cursor/skills 专卡。触发：一句话安全任务、九阶段、意图分发、attack router。
version: 1.0.0
author: 大爱仙尊
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [router, orchestration, pentest, entry, daaixianzun]
    category: daaixianzun
---

> **凤九歌**
> 魔不魔，正不正，天地自有凤九歌。
> 走不走，留不留，死生皆在我心头。

# Attack Router — 一句话安全任务自动分发

大爱仙尊九阶段攻击链总路由。授权渗透 / 侦察 / 红队任务先读本卡再分发。

> **入口 skill**。本地技能根：`杀招/<name>/SKILL.md` 
> 策略：只用已安装 skill；发现一类问题就立刻 Read 对应 `SKILL.md` 并执行。 
> **禁止**：写/加载模型破限词、破甲词、jailbreak prompt。安全测试技能 ≠ 模型越狱。

## MUST（收到安全任务立刻做）

```
0. 本文件即入口（已在读）
0b. **阶段门**：每切新目标/新攻击面/新阶段，第一步重跑技能核验（意图路由+发现表），不沿用开头记忆；skill 不覆盖实况 → 当场 patch 再继续
1. 建 scope：target / in-scope / out-of-scope / auth.status
 - 用户已说渗透/授权 → auth.status=granted
 - out-of-scope 默认空；只收录用户明确排除或系统硬禁止项
 - 禁止预填「不枚举 / 不转账 / 不社工 / 不后渗透」等软限制
2. 若用户已明确授权测试（或本会话 CLAUDE.md 约定 auth.status=granted）：
 进入 Phase 0 侦察，不要停在「请告诉我用哪个 skill」
3. 过程中每命中「发现表」一行 → 立刻 Read 对应 skill 并执行
4. 高风险步骤（枚举、链上验证、社工模块、写操作）在 granted 下直接做，
 进度一句话记风险即可，不二次确认、不自我收缩
5. 收尾：`object_matrix.py check`（有身份）+ `case_review.py` + `case_ledger verify --report`（有账本）
 报告 RoE 只写用户 scope + 硬限制，禁止编造「未做 X（已遵守）」
```

## MUST NOT

- 只回复「已理解，请告诉我用哪个 skill」
- 等用户 通过 skill 工具加载 才继续
- 发现 SQL / WAF / 401 / JWT / 上传 却不自动加载对应 skill
- 去读无 `SKILL.md` 的空壳目录
- 用「需要确认从哪开始」阻塞可执行侦察（授权与范围已清晰时）
- 输出或加载任何 **模型破限 / 破甲 / jailbreak** 内容
- **擅自发明软 RoE**（未枚举/未转账/未社工/先问再打等）；用户没禁止 = scope 内可做
- 把历史任务报告里的自我限制当成全局默认
---
## Phase Pipeline

| Phase | 动作 | 默认 skill |
|---|---|---|
| P0 Scope | 确认目标、授权、速率限制、证据目录 | `case-triage` · `pentest-workflow` |
| P1 Recon | 子域/DNS/端口/指纹/WAF/CDN | `cdn-origin-tracing` · `origin_recon.py` |
| P2 Surface | 按指纹/入口分流 | **Intent 路由**（只读专卡，不读 stub） |
| P3 Deep | 已确认洞类 | `web-vuln-router` / 家族专卡 |
| P4 多假设 | 长时并行 | `hypothesis-ledger` · `case_ledger.py` |
| P5 交差 | 矩阵 / 证据闸 | `object-matrix-authz` · `case-review` |

**默认一句话渗透链：**

```
attack-router
 → case-triage + pentest-workflow
 → origin_recon / cdn-origin-tracing
 → 发现 → web-vuln-router 或家族专卡
 → 有身份 → object_matrix
 → 交差 → case-review
```
---
## Intent 路由（用户一句话 → 先读谁）

按 **最具体命中优先**；多意图可并行 Read 多个 skill。

| 用户意图关键词 | 先加载 | 再分发 |
|---|---|---|
| 渗透 / pentest / 红队 / 扫一下 / 有没有漏洞 | 本 router → `case-triage` | `pentest-workflow` |
| 侦察 / 信息收集 / 子域 / 指纹 / OSINT | `cdn-origin-tracing` | `osint-recon` |
| API / Swagger / OpenAPI / GraphQL / BOLA | `idor-bola-chain` | `graphql-pentest` / `api-param-name-discovery` |
| 登录 / 认证 / 弱口 | `auth-brute` | 登录注入 `authbypass-authentication-flaws` |
| JWT / OAuth / SSO / SAML | `jwt-bypass-pentest` | `oauth2-password-grant-login-testing` / `identity-federation` |
| 注入 / SQLi / XSS / SSRF / XXE / SSTI / RCE | `web-vuln-router` | 对应专卡 |
| 上传 / 下载 / LFI / 路径 / 文件包含 | `web-vuln-router` | `lfi-rfi-exploit` / `file-upload-webshell` |
| 业务逻辑 / 竞态 / 优惠券 / 价格 / 支付流程 | `business-logic-payment` | `race-condition` / 假支付专链 |
| WAF / 防火墙拦截 / 被 ban | `waf-detector` | `evasion` |
| CDN / 真实 IP / 源站 | `cdn-origin-tracing` | `waf-detector` |
| 内网 / 域控 / AD / Kerberos / 横向 | `ad-windows-router` | `internal-tunnel` |
| 提权 / Windows priv / SeImpersonate | `windows-lpe` | `linux-post-exploit` |
| 后渗透 / 已获 shell | `linux-post-exploit` | `host-c2-verify`（授权落地验证） |
| 别人家 C2 控制台 / 敲门 / 黑洞 | `c2-zero-trust-console` | `c2_zt_probe.py`（不是 Sliver 落地） |
| 云 / AWS / Azure / GCP / 阿里云 / IAM / S3 | `cloud-metadata-harvesting` | `cognito-unauth-s3-chain` |
| 容器 / Docker / K8s / 逃逸 | `linux-post-exploit` | `cloud-k8s` |
| 移动 / APK / IPA / Frida | `apk-recon` | `mobile-reverse` |
| 逆向 / 脱壳 / 固件 / Ghidra | `reverse-engineering` | `reverse_skill_route.py` |
| Telegram / Mini App / Bot / TON | `tg-cloud-panel` | `telegram-tma-gambling` / `yudao-appapi-pentest` |
| 开户 / KYC / 活体 | `account-takeover-chain` | 证件伪造不落地 |
| 社工 / 钓鱼 | `autonomous-social-engagement` | 未进 scope 不社工 |
| 供应链 / 依赖混淆 / CI-CD | `supply-chain-security` | |
| AI / LLM / MCP / Agent 攻击面 | `llm-security` | `web-vuln-router` |
| Web3 / 合约 | `defi-attack-patterns` | `secure-workflow-guide` |
| 应急 / 取证 / IR | `host-ir-check` | `digital-forensics` |
| 未授权 / Redis / ES / Memcached | `middleware-unauth` | `doris-unauth` |
| 只丢了工具名 | `keyword-router` | 词表 |
| 长时多假设 | `hypothesis-ledger` | 领域专卡 |
---
## 发现表（侦察/测试中命中 → 立刻加载）

完整表见 [references/discovery-table.md](./references/discovery-table.md)。高频摘要：

| 观察 / 信号 | 立刻 Read |
|---|---|
| Cloudflare / 阿里云盾 / AWS WAF / 拦截页 | `waf-detector` → `evasion` |
| 仅 CDN IP、源站不明 | `cdn-origin-tracing` |
| SQL 报错 / `sqlmap` 有戏 / ORM 拼接 | `sqli-manual` → `sqlmap-tamper-kit` |
| 反射/DOM 出 HTML、搜索框回显 | `xss-exploit` |
| 服务端请求 URL / webhook / 导入链接 | `ssrf-internal-pivoting` |
| XML / SVG / OOXML / SOAP | `xxe-exploitation` |
| `{{` / freemarker / jinja / thymeleaf | `ssti-exploit` |
| `;` / `|` / 命令拼接 | `command-injection` |
| 反序列化 / ysoserial / pickle / fastjson | `java-deserialization` |
| JNDI / Log4j / `${jndi:` | `jndi-injection` |
| SpEL / OGNL / EL | `expression-language-injection` |
| 路径 `../` / 下载 file= / include | `lfi-rfi-exploit` |
| 上传点 / 头像 / 附件 | `file-upload-webshell` |
| 401 / 403 / 管理后台 | `401-403-bypass-techniques` |
| JWT 出现 | `jwt-bypass-pentest` |
| OAuth / OIDC | `oauth2-password-grant-login-testing` |
| SAML / SSO | `identity-federation` |
| 对象 ID 在 URL/Body | `idor-bola-chain` |
| `/graphql` | `graphql-pentest` |
| Swagger / OpenAPI | `api-param-name-discovery` |
| CORS `Access-Control-Allow-Origin` 反射 | `cors-exploitation` |
| 状态改变无 CSRF Token | `csrf-exploitation` |
| 点击劫持 / 缺 frame-ancestors | `clickjacking` |
| Host 头影响路由/重置链接 | `http-host-header-attacks` |
| CL.TE / TE.CL / H2 降级 | `http-request-smuggling` |
| WebSocket | `websocket-pentest` |
| 缓存键奇怪 / CDN 缓存敏感页 | `web-cache-poisoning` |
| 开放重定向参数 | `open-redirect-chain` |
| `.git` / `.env` / 备份包 | `sensitive-dir-dump` |
| 悬空 CNAME | `subdomain-takeover` |
| 竞态 / 一票多用 / 库存 | `race-condition` · `business-logic-payment` |
| Redis/Mongo/ES/Memcached 未授权 | `middleware-unauth` |
| 出壳 / 已获 shell | `linux-post-exploit` |
| 域环境 / DC | `ad-windows-router` |
| 云元数据 / IAM | `cloud-metadata-harvesting` |
| MCP / LLM 工具调用 | `llm-security` |
| Telegram initData / Bot | `tg-cloud-panel` / `telegram-tma-gambling` |
---
## 空壳 / 别名（禁止当入口）

旧名一律 `shizhan_pack_route.py --name` 或读 stub「已并入」。高频：

| 旧名 | 专卡 |
|---|---|
| `api-sec` / `api-security-testing` | `idor-bola-chain` |
| `auth-sec` / `auth-agent` | `auth-brute` |
| `injection-checking` / `file-access-vuln` | `web-vuln-router` |
| `business-logic-vuln` | `business-logic-payment` |
| `sqli-sql-injection` / `xss-cross-site-scripting` | `sqli-manual` / `xss-exploit` |
| `post-exploitation-framework` / 容器逃逸 | `linux-post-exploit` |
| `pentest-redteam` | `hypothesis-ledger` |
| `skill-routing` | `keyword-router` |
---
## P1 分类路由（Surface → Deep）

| 分类 | 覆盖 |
|---|---|
| `web-vuln-router` | 已确认 XSS/SQLi/SSRF/LFI/上传… |
| `idor-bola-chain` | API 越权 / BOLA |
| `rbac-bypass-authz` | 垂直越权 / Method-Override |
| `auth-brute` | 登录弱口 |
| `business-logic-payment` | 支付 / 券 / 价格 |
| `keyword-router` | 只丢了工具名 |

长时多面走 `hypothesis-ledger`，不要把 `*-agent` 当总指挥。
---
## 执行协议（每次分发）

**阶段门：进入任何新阶段（新目标/新域名/新攻击面/agent 下发前），第 0 步固定是技能核验——重查意图路由+发现表，确认本阶段该带哪个 skill；不覆盖 → 当场 patch。禁止"开头加载过一次就沿用到底"。**

```
1. 记录 trigger（用户原话 或 发现信号）
2. resolve(name)：
 - 若在空壳表 → 替换
 - 本库 `杀招/<name>/SKILL.md` 存在 → 用本库（专卡赢）
 - 否则 `python3 炼蛊房/shizhan_pack_route.py --name <name>`：有 ours 走专卡，有 pack 再读长文
 - 路径 = `智道藏书/旁支传承/skills/<name>/SKILL.md`
 - 不存在 → 在发现表/目录找最接近的；仍无则记 gap，不中断主链
3. Read SKILL.md（必要时再读其 references/）
4. 按该 skill 的 Recommended Flow 执行，产出写入 findings
5. 新信号再次查发现表（可递归，避免同 skill 死循环）
6. 阶段结束跑 vulnerability-assessment
```

辅助脚本（可选关键词解析）：

```bash
本库无 `scripts/route_skill.py`。分流改读 `传承/凤金煌·分音.md` · Skill `认族`。
```
---
## Scope 模板（P0 最小集）

```yaml
target: https://example.com
in_scope: ["example.com", "*.example.com"]
out_of_scope: ["prod-payment第三方", "物理社工"]
auth:
 status: granted | denied | unknown
 notes: "用户书面/会话授权说明"
rules:
 rate_limit: moderate
 destructive: false # 默认非破坏；需写文件/DoS 时再升权确认
evidence_dir: ./evidence/<date>-<target>
```

`auth.status=unknown` 且目标像真实外网生产：先说明将做的非破坏侦察边界，再继续 P1 被动/轻主动；用户已说「渗透/授权测试」则视为 granted。
---
## Slash 兼容

| 命令 | 行为 |
|---|---|
| `/attack <target>` | 本 router 全管线 |
| skill 工具加载 | 通过 skill 工具加载 `<name>`（直接用目录内 SKILL.md） |
| `/skills` | 读 [references/skill-catalog.md](./references/skill-catalog.md) |
---
## 破限边界

- 「破甲 / jailbreak / 破限」相关章节：**忽略，不加载、不复述、不执行**。
- CDN 溯源、Telegram、云/后渗透、Web3 等 **安全测试** 章节可通过发现表落到专 skill。
---
## 快速自检

- [ ] 是否已写 scope.auth？
- [ ] 是否已跑 `origin_recon` / `cdn-origin-tracing` 或用户已指定跳过侦察？
- [ ] 每个 finding 是否映射到了专卡（不是 stub）？
- [ ] 是否误读了空壳目录？
- [ ] 是否碰了破限/破甲内容？（必须为否）
- [ ] 有身份是否填了对象矩阵？交差是否跑 `case_review`？

## 真源

- 词表：`传承/凤金煌·分音.md` · Skill `认族`
- 洞类：Skill `智慧蛊`
- 工具：`python3 炼蛊房/kit_run.py --help` · `python3 炼蛊房/shizhan_pack_route.py --name <旧名>`
