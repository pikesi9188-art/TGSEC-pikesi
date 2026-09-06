# Skill → 九阶段 / 业务恢复 映射

路径前缀：`智道藏书/九转/skills/<name>/SKILL.md`  
工具脚本：`waf-detector` / `cdn-origin-tracing` 在 `tools/vendor/`。

Agent 请读：`杀招/九转/SKILL.md`。

---

## 按九阶段

### 01 信息收集
| Skill / 工具 | 何时用 |
|--------------|--------|
| `recon-and-methodology` | 总方法论、范围与资产表 |
| `recon-for-sec` | 子域/端口/爬链流程 |
| `api-recon-and-docs` | OpenAPI / JS 挖接口 |
| `subdomain-takeover` | 悬空 CNAME |
| **cdn-origin-tracing** | CDN 遮源找源站 IP |

### 02 漏洞扫描
| Skill | 何时用 |
|-------|--------|
| `vulnerability-assessment` | 扫描结果排序与验证 |
| `security-scanning` | 工具选型 |
| `vuln-analysis-agent` / `poc-agent` | 候选洞裁决 |

### 03 Web/API 利用（高频·业务相关加粗）
| Skill | 何时用 |
|-------|--------|
| **`api-auth-and-jwt-abuse`** | JWT/会话票（含 PB） |
| **`api-authorization-and-bola` / `idor-*`** | 越权/IDOR |
| **`401-403-bypass-techniques`** | 403 绕过 |
| **`race-condition`** | 并发入账/注册 |
| **`business-logic-vulnerabilities`** 等 | 支付/状态机 |
| **`telegram-mini-app-bot-security`** | Mini App / initData |
| `sql-injection-testing` / `sqli-*` | SQLi |
| `ssrf-*` / `ssti-*` / `xxe-*` / `xss-*` | 经典洞 |
| `path-traversal-lfi` / `file-upload-testing` / `file-access-vuln` | 文件面 |
| `deserialization-*` / `jndi-injection` | Java 反序列化 |
| `request-smuggling` / `web-cache-deception` | 走私/缓存 |
| `oauth-oidc-misconfiguration` / `saml-sso-*` / `jwt-oauth-*` | 联邦登录 |
| `graphql-and-hidden-parameters` | GraphQL |
| `cors-*` / `csrf-*` / `clickjacking` | 浏览器侧 |

### 04 绕过
| Skill / 工具 | 何时用 |
|--------------|--------|
| `waf-bypass-techniques` + **waf-detector** | 认 WAF / 生成变异 |
| `webshell-evasion` | 仅实验室；真源官方 |

### 05–08 内网
| Skill | 何时用 |
|-------|--------|
| `network-penetration-testing` | 隧道/内网入口 |
| `password-attacks-credential-access` | 凭据攻击面 |
| `linux-privilege-escalation` / `windows-privilege-escalation` | 提权 |
| `active-directory-lateral-movement` | AD 横向 |
| `persistence-mechanisms` / `post-exploitation-framework` | 维持（实验室） |
| `data-exfiltration` | 外带路径（授权） |

### 09 辅助 / 专项
| Skill | 何时用 |
|-------|--------|
| `reverse-engineering` / `mobile-app-security-testing` | APK/二进制 |
| `database-security` / `cloud-security-*` / `container-security-testing` | 库/云/K8s |
| `secure-code-review` / `incident-response` | 白盒/应急 |
| `ai-llm-attack-surface` | LLM 面 |
| `dns-pollution-hijacking` / `dns-rebinding-attacks` | DNS 类 |

---

## 按业务恢复链（你的强项）

| 恢复步骤 | 优先 Skill / Playbook |
|----------|----------------------|
| ③ 信息收集 | recon-* + cdn-origin-tracing + `main.py fofa` |
| ④ 上传/读文件 | file-upload / path-traversal / file-access |
| ④ 假支付 | **`杀招/秦百胜·回响`**（高于通用 business-logic） |
| ④ 后台/JWT/规则 | api-auth-jwt + 401-403 + bola；PB 用 **pocketbase-horizons-recovery** |
| ④ Spring/Actuator | **rule + `tools/spring-gateway-killchain`** |
| ⑤ 验证可用 | finding 口径见 WORKFLOW；勿只信扫描器 |
| TG Bot / Mini App | telegram-mini-app-bot-security + `main.py bot` |
| Node/.node/BPP | **bpp-node-exploit-chain** |

冲突时：**业务 Cursor skill / Playbook > 九阶段通用 Skill > 广谱扫描。**
