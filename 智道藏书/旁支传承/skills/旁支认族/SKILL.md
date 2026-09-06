---
name: 旁支认族
description: 渗透技能路由总表。当技能库存在冗余/重叠时（API/SSRF/业务逻辑/注入/WAF/认证/Telegram 等家族各有多个技能），按本表先加载 canonical 主手册，再按需加载专项。
---
# Skill 路由总表（冗余家族消歧）

技能库 229 个技能存在家族冗余。**不要一次性加载同一家族的所有技能** —— 会浪费上下文且互相冲突。按本表先加载 canonical 主手册，再按需加载专项。

## 路由原则

1. **先加载 Router/Canonical，再加载专项**：家族内优先加载标「主」的技能。
2. **一个家族只加载 1 个主手册 + 命中的 1-2 个专项**。
3. 若当前任务无法归类 → 加载 `attack-chain`（总指挥）按阶段推进。

## 路由表

| 任务类型 | 主手册（先加载） | 专项（按需） |
|---------|----------------|-------------|
| 渗透总指挥/多阶段 | `attack-chain` | `attack-router` / `nine-stage-auto-router` / `pentest-workflow` |
| API 安全 | `api-sec`（router） | `api-security`（方法论）/ `api-recon-and-docs`（侦察）/ `api-auth-and-jwt-abuse`（认证）/ `api-authorization-and-bola`（越权）/ `api-param-name-discovery`（参数）/ `api-security-testing`（深度）/ `graphql-and-hidden-parameters` |
| 业务逻辑 | `business-logic-vuln`（router） | `business-logic-vulnerabilities`（playbook）/ `business-logic-testing`（深度）/ `race-condition` / `csv-formula-injection` |
| SQL 注入 | `sqli-sql-injection` | `sql-injection-testing`（别名，勿直接加载）/ `database-security` |
| 命令注入 | `injection-checking`（router） | `cmdi-command-injection`（别名）/ `command-injection-testing`（别名） |
| XSS | `xss-cross-site-scripting` | `xss-testing`（深度）/ `csp-bypass-advanced` / `dangling-markup-injection` |
| XXE | `xxe-xml-external-entity` | `xxe-testing`（深度）/ `xslt-injection` / `xpath-injection-testing` |
| SSRF | `ssrf-server-side-request-forgery` | `ssrf-testing`（深度）/ `echo-ssrf-internal-scanning`（回显）/ `ssrf-internal-pivot` / `ssrf-internal-pivoting` / `ssrf-port-probe-classification` |
| 文件上传/访问 | `file-access-vuln`（router） | `file-upload-testing`（别名）/ `path-traversal-lfi` / `webshell-evasion` |
| 认证绕过 | `authbypass-authentication-flaws` | `auth-sec`（router）/ `auth-agent` / `401-403-bypass-techniques` |
| JWT/OAuth | `jwt-oauth-token-attacks` | `oauth-oidc-misconfiguration` / `oauth2-password-grant-login-testing` / `saml-sso-assertion-attacks` |
| IDOR/BOLA | `idor-broken-object-authorization` | `idor-testing` / `register-bypass-idor` / `api-authorization-and-bola` |
| 验证码 | `captcha-ocr-bypass`（ddddocr 通用） | `geetest-captcha-bypass` / `recaptcha-bypass` |
| WAF | `waf-bypass-techniques` | `waf-detector`（先探测）/ `waf-js-challenge-bypass` / `cloudflare-origin-bypass` |
| 反序列化 | `deserialization-insecure` | `deserialization-testing` / `jndi-injection` / `expression-language-injection` |
| 模板注入 | `ssti-server-side-template-injection` | `expression-language-injection` |
| Telegram 平台 | `telegram-mini-app-bot-security` | `telegram-bot-discovery`（侦察）/ 各垂直（telegram-gambling-* / tg-*） |
| TG 账号库 | `tg-account-session-intake` | `tg-account-library-ops` |
| 内网/AD | `network-penetration-testing` | `active-directory-lateral-movement` / `windows-privilege-escalation` / `linux-privilege-escalation` / `post-exploitation-framework` |
| 免杀/反取证 | `anti-forensics`（索引，按需读 parts/） | `webshell-evasion` / `edr-bypass-re` / `redteam-opsec` / `nine-stage-fusion/parts/part-01` |
| C2 框架 | `c2-framework` | `network-tunneling` / `shellcode-loader-evasion` |
| 隧道/代理 | `network-tunneling` | `c2-framework` |
| Shellcode 加载/免杀 | `shellcode-loader-evasion` | `nine-stage-fusion/parts/part-01` / `edr-bypass-re` |
| 逆向 | `reverse-engineering` | `ida-reverse` / `radare2` / `binary-diff` / `patch-diff-exploit` / `dotnet-reverse` / `dsl-vm-reverse` |
| 移动端 | `mobile-reverse` | `apk-reverse` / `mobile-app-security-testing` |
| 侦察/OSINT | `recon-and-methodology` | `recon-for-sec` / `fofa-search` / `quake` / `cdn-origin-tracing` / `subdomain-takeover` / `src-hunter` / `tma-web-asset-discovery` |
| 报告 | `pentest-working-report` | `docs-generator` / `security-report-templates` / `diagram-generator` |
| 漏洞扫描 | `security-scanning` | `vulnerability-assessment` / `pentest-tools` |
| AI/LLM | `ai-llm-attack-surface` | `llm-security` |

## 巨型技能使用规范

- `nine-stage-fusion` / `anti-forensics` 是**索引**：只读 SKILL.md 路由表，然后按需 Read `parts/part-XX.md`。**禁止整体加载**。
- 其余 >100KB 技能（data-exfiltration / password-attacks / post-exploitation-framework 等）在命中时才整读。

## 反模式（禁止）

- ❌ 同时加载 `xss-testing` + `xss-cross-site-scripting` + `csp-bypass-advanced` 三个
- ❌ 加载 `sql-injection-testing`（别名壳，应加载 `sqli-sql-injection`）
- ❌ 一次 Read 整个 `nine-stage-fusion/SKILL.md`（是索引，不是内容）
