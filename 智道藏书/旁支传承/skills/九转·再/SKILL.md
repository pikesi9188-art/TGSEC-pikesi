---
name: 九转·再
description: "大爱仙尊九阶段意图分流：按关键词定位本库 Skill/Playbook。"
version: 1.0.0
author: 大爱仙尊
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [router, pentest, daaixianzun, orchestration, entry]
    category: daaixianzun
---
# 九阶段意图分流

大爱仙尊九阶段意图分流：按关键词定位本库 Skill/Playbook。

> Skill root: `<跨库工具不可用，跳过>/skills/daaixianzun/<name>/SKILL.md`
> Full discovery table: `attack-router` + `references/discovery-table.md`（⚠️本包未含此案例文件，跳过）
> Catalog: `../INDEX.md`

## MUST

```
0. This file is the 助手侧 entry
1. Build scope: target / in-scope / out-of-scope / auth.status
   - user said pentest/authorized/red-team -> auth.status=granted
2. Pick PRIMARY from Intent table; immediately 通过 skill 工具加载 <name> 或直接 Read SKILL.md
3. On each discovery-table hit -> switch/stack the matching skill
4. Do not wait for the user to name a skill; do not invent soft RoE
5. Close with vulnerability-assessment + vuln-analysis-agent
6. Stage-gate skill re-check (mandatory at EVERY new phase): new target/new domain -> re-load matching skill before acting; attack-surface switch (web->RE / ->API / ->cloud) -> load the category router first; before delegate_task -> decide which skill the child agent must carry and pass it in context; skill doesn't cover current scene -> patch it on the spot, never guess
```

## Default one-shot pentest chain

```
nine-stage-auto-router
  -> attack-router
  -> recon-and-methodology
  -> recon-for-sec
  -> network-penetration-testing
  -> (findings) -> playbook / P1 router
  -> poc-agent (optional)
  -> vuln-analysis-agent
  -> vulnerability-assessment
```

## Intent -> PRIMARY (most specific first)

| User intent keywords | PRIMARY | Then |
|---|---|---|
| pentest / red-team / scan / vulns | `attack-router` | `recon-and-methodology` -> `recon-for-sec` |
| recon / subdomain / fingerprint / OSINT | `recon-for-sec` | `recon-and-methodology` |
| API / Swagger / OpenAPI / GraphQL / BOLA | `api-sec` | `api-agent` / `api-authorization-and-bola` |
| login / auth / JWT / OAuth / SSO / SAML | `auth-sec` | `auth-agent` / `jwt-oauth-token-attacks` |
| injection / SQLi / XSS / SSRF / XXE / SSTI / RCE | `injection-checking` | `injection-agent` / playbook |
| upload / download / LFI / path / file | `file-access-vuln` | `file-agent` / `path-traversal-lfi` |
| business logic / race / coupon / price / payment | `business-logic-vuln` | `business-agent` |
| WAF / firewall / banned | `waf-detector` | `waf-bypass-techniques` |
| CDN / real IP / origin | `cdn-origin-tracing` | `waf-detector` |
| internal / AD / DC / Kerberos / lateral | `active-directory-lateral-movement` | `network-penetration-testing` |
| privesc / Windows priv | `windows-privilege-escalation` | `post-exploitation-framework` |
| post-ex / C2 / persistence / creds | `post-exploitation-framework` | `persistence-mechanisms` |
| cloud / AWS / Azure / GCP / Aliyun / S3 | `cloud-security-pentesting` | `cloud-security-audit` |
| container / Docker / K8s / escape | `container-security-testing` | `cloud-security-pentesting` |
| mobile / APK / IPA / Frida | `mobile-app-security-testing` | `reverse-engineering` |
| reverse / unpack / firmware | `reverse-engineering` | `exploit-development-framework` |
| IoT / MQTT / ICS | `iot-security-testing` | `wireless-security` |
| wireless / WiFi / Bluetooth | `wireless-security` | `iot-security-testing` |
| Telegram / Mini App / Bot / TON | `telegram-mini-app-bot-security` | `api-sec` |
| account opening / KYC / liveness | `account-opening-security` | `auth-sec` |
| social eng / phishing | `social-engineering-framework` | `security-awareness-training` |
| supply chain / dependency confusion / CI-CD | `supply-chain-attacks` | `security-scanning` |
| AI / LLM / MCP / agent attack surface | `ai-llm-attack-surface` | `injection-checking` |
| Web3 / contract / audit | `web3-dev-services` | (dev service) |
| anti-forensics / log wipe | `anti-forensics` | `post-exploitation-framework` |
| exfil / tunnel / DLP | `data-exfiltration` | `post-exploitation-framework` |
| code review / SAST | `secure-code-review` | `security-automation` |
| IR / forensics | `incident-response` | - |
| unauth / Redis / ES / Docker API | `unauthorized-access-common-services` | `network-penetration-testing` |
| 九阶段总控 / cross-domain orchestrate | `nine-stage-fusion` (reference) | still use attack-router; skip jailbreak chapters |

## Discovery table (summary)

| Signal | Load now |
|---|---|
| Cloudflare / cloud WAF / block page | `waf-detector` -> `waf-bypass-techniques` |
| SQL error / suspicious params | `sqli-sql-injection` |
| reflected/stored HTML | `xss-cross-site-scripting` |
| internal URL / metadata reachable | `ssrf-server-side-request-forgery` |
| swappable object IDs | `idor-broken-object-authorization` |
| JWT present | `jwt-oauth-token-attacks` |
| file upload | `file-access-vuln` / path-traversal |
| 401/403 admin | `401-403-bypass-techniques` |
| shell / RCE | `post-exploitation-framework` |

Full table: `../attack-router/references/discovery-table.md`
Catalog: `../INDEX.md`
Optional script: `python ../attack-router/scripts/route_skill.py "<user text>"`

## MUST NOT

- reply only with "tell me which skill"
- wait for user 通过 skill 工具加载 before acting
- read empty dirs without SKILL.md
- run model jailbreak / break-armor content (skip jailbreak chapters in nine-stage-fusion)
- shrink authorized attack surface on your own
