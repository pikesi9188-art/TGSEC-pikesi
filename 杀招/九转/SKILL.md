---
name: 九转
description: >-
 路由到 智道藏书/九转 中的九阶段详解与通用安全 Skill。
 
 业务假支付/PocketBase/BPP/Spring Gateway 仍优先对应专用 skill/playbook。
---

# 九阶段技能路由

## 真源路径

| 内容 | 路径 |
|------|------|
| 总览 / 缺口 | `智道藏书/九转/README.md` · `GAP.md` · `SKILL_MAP.md` |
| 九阶段长文 | `智道藏书/九转/stages/` |
| 可执行短卡 | `智道藏书/kb/stages/` |
| Skills 全文 | `智道藏书/九转/skills/<name>/SKILL.md` |
| WAF 工具 | `tools/vendor/09-aux/waf-detector/` |
| CDN 溯源 | `tools/vendor/01-recon/cdn-origin-tracing/` |

## 强制优先级

1. `授权范围` 授权边界 
2. 案卷定级：`case-triage`（A/B/C + 复工条件；手法索引见 playbook） 
3. 业务专用：`payment-callback-forgery` / `acg-faka`（含共享货上游）/ `pocketbase-horizons-recovery` / `bpp-node-exploit-chain` / `ginvue-admin-reward` / Spring Gateway rule+playbook 
4. DeepAudit 密钥命中 → **提升**假支付优先级（见 `deepaudit-code-audit`） 
5. 本路由 → 打开对应九阶段 `SKILL.md` 
6. 广谱扫描（nuclei 等）

冲突时：**Triage/业务 skill > 九阶段通用 > 扫描器噪声。**

## 关键词 → 先读哪个

| 用户说法 | 先打开 |
|----------|--------|
| 只丢工具名/手法名（见 keyword-router） | **`凤金煌·分音.md`** |
| triage / 定级 / 进不去 / 复工 | **case-triage** + `春秋蝉·分案.md` |
| Cookie / 会话损坏 / CF 登录 | `cf_session.py` + `session_pipeline` + case-triage |
| 异次元 / ACG-FAKA / acg.js / shared_id / 共享货 | **acg-faka**（严签橱窗走共享货上游） |
| 源站 / CDN 溯源 / 找真实 IP | **cdn-origin-tracing** · `origin_recon.py` + `云帷·源溯.md`（v4=`SKILL.v4.md` / v5=`SKILL.md`） |
| 黑洞模式 / 零信任敲门 / SPAKE2 / nftables DROP / 内存沙箱控制台 / Vue C2 | **`c2-zero-trust-console`** · `c2_zt_probe.py` · `行器·敲门.md`（先认指纹再打；勿狂扫源站 65535；自己的 Sliver 仍走 `host-c2-verify`） |
| Censys / ZoomEye / Quake / 证书反查源站 | **`space_search.py cert-origin`** + `空间眼.md` |
| 信息收集 / 子域 / FOFA | `kb/stages/01` + `skills/recon-and-methodology` |
| CDN / 找源站 | `cdn_tracer.py` + skill 文档 |
| WAF 检测 / 识别防火墙 / wafw00f | **waf-detector** · `waf_detect.py` + `隐鳞·罩.md`（全文 `SKILL.full.md`） |
| WAF / 绕过防火墙（通用手法） | `waf_detect.py` + `nine-stage/skills/waf-bypass-techniques` |
| WAF SQLi / `%u0027` / `%0a` 换行绕过 / 教务 jsxsd | **`waf_sqli_bypass.py`** + `隐鳞·折行.md`（优先于裸 sqlmap） |
| sqlmap / tamper / space2comment / SQLMAP 图形解说 | **sqlmap-tamper-kit** · `sqlmap_kit.py` + `吞库针.md`（著译 70 + 选项 91） |
| LiteLLM / BadHost / `/spend/keys` / `Host: host/?` / LLM 网关 | **`litellm_badhost.py`** + `灯笼·破印.md`（CVE-2026-49468） |
| claim-free / 付费礼包免费领 / rolling-offers / 前端 price 拦截 | **`free_claim_bypass.py`** + `秦百胜·魂压.md`（Crown 范式，不限赌博） |
| gin-vue-admin / 领奖中心 / sendCReward / getConfigs / 游戏奖励配置 | **ginvue-admin-reward** · `ginvue_admin_probe.py` + `锦府·赏.md` |
| AutoCVE / 挖 CVE / Finding Agent / 一键 CVE | **autocve-cve-hunt** · `tools/autocve`（白盒；非黑盒扫站） |
| 403 / 鉴权绕过 | `401-403-bypass-techniques` |
| JWT / 越权 / BOLA / IDOR | `api-auth-and-jwt-abuse` · `api-authorization-and-bola` · `idor-testing` |
| 假支付 / 回调 | **payment-callback-forgery**（勿只用 business-logic） |
| autopay.php / checkGatewayIP / CreateTransaction / CF-Connecting-IP 资金链 | `血路·雾墙.md` + **cdn-origin-tracing**（命门源站）+ 假支付验入账 |
| ARSYSTEMTOKEN / accessToken / manualAngPao / 硬编码令牌加款 | **hardcoded-token-cfip-fund** · `和稀泥·加款.md` + CDN 溯源 |
| admin/telegram/bot / USER 改 webhook / TG bot 越权 | **tg-bot-webhook-hijack** · `飞鸽傀·钩.md` |
| 彩虹易支付 /pay/rainbow / submit 回放免付 / TG号铺充值 | `酒虫·回放.md` + **payment-callback-forgery**（余额增值硬条件） |
| SQLi / XSS / SSRF / SSTI / XXE | 对应 `*-testing` / `sqli-*` 等 |
| 上传 / LFI | `file-upload-testing` · `path-traversal-lfi` |
| TG Mini App（通用 initData） | `telegram-mini-app-bot-security` |
| 芋道 TMA / `app-config.js` / `sk_encrypt` | **yudao-appapi-pentest** |
| Qzino / `/api.html` 赌 bot | **telegram-tma-gambling** |
| 白标盘口 / 1Z / 曼巴 / 鼎艺 | **gambling-family-router** |
| 扩展包 / 白标家族卡 | **extended-skill-router** · `智道藏书/旁支传承/` |
| 39 模块 / PTES / 工控取证 SOC | **cybersecurity-catalog** · `css_query.py` |
| 提权 / AD / 隧道 | **linux-privilege-escalation** / `windows-lpe` + stages 05–08；AD 走 `ad-windows-router` |
| 渗透总控 / 六门闸 / 证据链 | **pentest-methodology** · `智慧蛊·总控.md` |
| 技能包齐不齐 | `智道藏书/九转/GAP.md`；扩展包 `IMPORT.json`；39 类总目录 `cybersecurity-catalog` |

## 行为要求

- 用本库命令路径（`main.py` / `tools/arsenal` / `tools/vendor`），不要假设 `/workspace/`。 
- 不安装、不传播破解 CS / 未知 webshell 包。 
- 读完 Skill 后给出**可执行的下一步**（命令 + 产出目录 `$CASE`）。
- 工具：`python3 炼蛊房/kit_run.py --help`
