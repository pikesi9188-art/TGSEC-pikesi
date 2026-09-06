---
name: 九转·再
description: "授权渗透意图分流路由器：按用户关键词快速定位本库最匹配的 Skill/Playbook，覆盖 API/注入/认证/业务/云/移动/逆向/Telegram/Web3 全链。触发：不知道用哪个技能、打哪个卡、工具链分流、intent dispatch。"
---
# 授权渗透意图分流路由器

> 本卡是大爱仙尊本地路由，按用户关键词直接指向本库真实 Skill。
> 九阶段详解走 `nine-stage-router`；综合路由走 `attack-router`。

---

## 快速路由表（意图 → 优先加载 Skill）

| 用户意图 / 关键词 | 优先加载 | 备用 |
|---|---|---|
| API安全 / Swagger / OpenAPI / BOLA / 接口越权 | `api-security` | `idor-bola-chain` |
| JWT / OAuth / SSO / SAML / 认证绕过 | `jwt-bypass-pentest` | `2fa-bypass` |
| SQL注入 / 注入 / sqlmap | `sqli-manual` | `sqlmap-tamper-kit` |
| XSS / 跨站脚本 | `xss-exploit` | `csrf-exploitation` |
| SSRF / 内网 / 云元数据 | `ssrf-internal-pivoting` | `cloud-metadata-harvesting` |
| SSTI / 模板注入 | `ssti-exploit` | `command-injection` |
| 文件上传 / WebShell / LFI / 路径穿越 | `file-upload-webshell` | `lfi-rfi-exploit` |
| XXE / XML外部实体 | `xxe-exploitation` | — |
| 命令注入 / RCE | `command-injection` | `file-upload-webshell` |
| 反序列化 / Java / ysoserial / Shiro | `java-deserialization` | — |
| 原型污染 / Prototype Pollution | `prototype-pollution` | — |
| CORS / 跨域 | `cors-exploitation` | — |
| CRLF / HTTP头注入 | `crlf-injection` | — |
| 缓存投毒 / Web Cache | `web-cache-poisoning` | — |
| WebSocket | `websocket-pentest` | — |
| GraphQL | `graphql-pentest` | — |
| 请求走私 / HTTP Smuggling | `http-request-smuggling` | — |
| 竞争条件 / 并发 / race condition | `race-condition` | — |
| 批量赋值 / mass assignment | `mass-assignment` | — |
| IDOR / 越权 / BOLA | `idor-bola-chain` | `rbac-bypass-authz` |
| 支付逻辑 / 假支付 / 回调伪造 | `payment-callback-forgery` | `business-logic-payment` |
| 弱口令 / 爆破 / 后台登录 | `auth-brute` | — |
| 开放重定向 | `open-redirect-chain` | — |
| WAF / 防火墙 / 绕过 | `waf-detector` | `evasion` |
| CDN / 源站溯源 / 真实IP | `cdn-origin-bypass` | `cdn-origin-tracing` |
| 子域名 / 枚举 / 资产 | `subdomain-enum` | `fofa-search` |
| 云 / AWS / S3 / Cognito | `cognito-unauth-s3-chain` | `cloud-metadata-harvesting` |
| Kubernetes / K8s / 容器 | `ssrf-internal-pivoting` | `host-ir-check` |
| Windows AD / 域 / Kerberos | `windows-ad-pentest` | `kerberos-attack` |
| 内网横向 / 隧道 | `internal-tunnel` | `smb-lateral-movement` |
| 提权 / LPE / 容器逃逸 | `linux-privilege-escalation` | `windows-lpe` |
| 渗透总控 / 验证闸 / 证据链 | `pentest-methodology` | `case-triage` |
| 政务小程序 / SM2 / tokenRequired / rkbm | `gov-wxmini-audit` | `wxmini-static-audit` |
| iOS 内核 / AKS / 65343 | `ios-kernel-exploitation` | `ios-pentest` |
| APK / 移动 / iOS 应用 / Frida | `apk-recon` | `ios-pentest` |
| IDA / 二进制 / 逆向 / ELF | `ida-reverse` | `binary-pwn` |
| .NET / C# 逆向 | `dotnet-reverse` | — |
| Telegram / Mini App / TMA / Bot | `tg-bot-webhook-hijack` | `telegram-tma-gambling` |
| 芋道 / ruoyi-vue-pro / yudao | `yudao-appapi-pentest` | `yudao-daifu-mock-file-rce` |
| Spring Boot / Actuator / heapdump | `spring-actuator-cloud-takeover` | — |
| GIN-VUE-ADMIN / GVA | `ginvue-admin-stealth-takeover` | — |
| RuoYi / 飞投 / 若依 | `ruoyi-fork-admin-pentest` | — |
| FastAdmin / ThinkPHP / 代付 | `fastadmin-daifu-pentest` | `fastadmin-shop-tenant-bola` |
| Laravel | `laravel-api-auth-probing` | `php-framework-debug-leak-pentest` |
| WordPress / WP | `wp-shell-drop-hunt` | `wordpress-plugin-unauth-takeover` |
| Supabase / PostgREST / RLS | `supabase-rls-pentest` | — |
| Docker / etcd | `etcd-unauth` | — |
| Redis / ES / Mongo 未授权 | `middleware-unauth` | — |
| Doris / StarRocks / :9030 | `doris-unauth` | — |
| 域名 / FOFA / Shodan / 空间测绘 | `fofa-search` | `subdomain-enum` |
| SRC / 漏洞赏金 / 众测 | `src-hunter` | `pentest-workflow` |
| 代码审计 / 白盒 | `deepaudit-code-audit` | `semgrep` |
| 情报 / CVE / 日报 | `cve-daily-intel` | `1day-nuclei-kit` |
| 博彩 / 白标 / 加密API | `gambling-family-router` | `extended-skill-router` |
| 多租户 SaaS / 租户隔离 | `saas-multitenant-acl-testing` | — |

---

## 一键打站链（不知道打哪儿时）

```
pentest-methodology + case-triage
 → 指纹命中？→ 对应家族 Skill（上表）
 → 无专用？ → strike_probe S1–S8 + core-web-vuln-kit + auth-brute
 → 有 JWT？ → jwt-bypass-pentest
 → 有 API 文档？→ api-security-testing + idor-bola-chain
 → 有支付？ → payment-callback-forgery
 → 有身份？ → object_matrix.py check（对象矩阵闸）
```

## 真源

- 手法：`传承/凤金煌·分音.md`
- 综合总路由：`attack-router`
- 九阶段技能包：`nine-stage-router`
- 家族专卡库：`extended-skill-router`
- 工具：`python3 炼蛊房/kit_run.py --help`
