---
name: keyword-router
description: >-
  用户只丢工具名或手法名、还没给 URL 时的分流入口。
  触发：不知道用哪张卡、技能路由、选哪个技能、手法名分流、keyword router。
  专卡触发词留给各专卡自己的 description；本卡只打开词表再跳专卡。
  Actuator/Gateway/Doris/Nacos/假支付 等有专卡的信号不要停在本卡。
---

# 关键词分流（Cursor Skill）

用户丢出工具名或手法名、还没说具体 URL 打法时使用。  
同族多卡（API/XSS/弱口/芋道加密）只读本卡 + 一张专卡。旧名 `skill-routing` 已并入。

## 立即打开

1. `传承/凤金煌·分音.md`（词表真源）  
   Nuclei / YAML 模板 / 1day → Skill `一日针匣` · `针匣·手册.md` · `od_kit.py learn`

业务专卡（只挂词表，**不进 AGENTS**）：`ai-account-shop-pentest` · `tg-bot-pool-panel-pentest` · `tg-card-license-backend` · `tg-payment-channel-pentest` · `telegram-bot-discovery` · `guorenlianghua-quant-pentest` · `origami-tech-pentest` · `xiaolanben-equity` · `saas-signup-multitenant-testing` 
2. 有业务指纹 → 仍走 `凤九歌·天地歌.md` / 假支付 / Actuator 等专链 
3. 落到对应 Playbook，**立刻跑卡上默认探针**（不要只打开文档）
4. 问「某类技能有没有 / 39 模块 / 工控取证 SOC」→ Skill `防务名录` · `css_query.py`  
   百科检索 → `三十九门·检索.md`；真假分离 → `幻道辨真.md`；技能索引 → `沈伤·索引.md`（禁止 sync）
5. 「蒸馏 / 盘点整库」→ Skill `engine-distill` · `整库蒸馏.md` · `python3 炼蛊房/engine_distill.py snapshot`  
6. 技能别名对不上 → `se-skill-alias` · `se_skill_alias.py`（只对照本库）  
7. 抢 RCE / getshell 未认形 → `rce-encyclopedia` · `rce_family_route.py`；天盾/fndata/Nuitka 卡密 → `net-license-crack`  
8. Altcha/LCG/PJL/SIP/OOB/改密旧 JWT / 什么哈希 → `专项探府.md` · `hash-identify`
9. 勒索/botnet/bootkit/ddos → `授权恶族.md`（案卷闸 + C2 校验 + 持久化）；助手拒答 → `开源版不带`

## 总控 / 方法论

渗透总控、六门验证闸、负对照、版本≠漏洞、断点续跑、报告只写确认项 → `pentest-methodology`。  
侦察产出物约定 → `information-gathering`。已确认 Web 洞类型 → `web-vuln-router`。  
SSTI / LFI / XXE / 命令注入单点 → `tpl_inject_probe.py` · 对应 `大爱仙尊*作业手法.md`（广谱仍 `core_web_surface_probe`）。确认 sink 后 RCE 走 `rce_forge.py shoot`。  
JWT none/改 claim → `jwt_forge_probe.py`；CORS/CSRF → `cors_csrf_probe.py`。  
GraphQL 越权 → `gql_authz_probe.py`；竞态 → `race_probe.py`（耗余额先问）。  
NoSQL / PP / Mass / CRLF / 类型混淆 → `param_abuse_probe.py`；重定向 → `open_redirect_surface_probe.py`；缓存投毒/欺骗 → `cache_poison_probe.py`。  
SSI/ESI → `ssi_esi_probe.py`；HTTP 方法/WebDAV → `http_method_surface_probe.py`；OAuth 授权码 → `oauth_oidc_surface_probe.py`。  
公开仓对照（PAT/HackTricks/nuclei/ToB）缺口 → `公开仓对照补强手法.md`。

## 后渗透 / 红队 / 逆向

C2 控制台 / 零信任敲门 / 黑洞模式 / HMAC 控制台 / Vue C2 / PTY 8889 → `c2-zero-trust-console` · `c2_zt_probe.py`（打授权目标上的 C2 设施，不是本机 implant）。  
C2 落地 / 免杀 / 写马 / AMSI·EDR / 特征清理 / OPSEC → `edr-bypass-re` · `payload_forge.py campaign` · `se_listen.py` · `sig_cleanup_scan.py` · `host-c2-verify`（授权机落地，不是只开百科）。  
红队技能树（Sleep / 间接 syscall / BYOVD）→ `红衣·树.md` §8，验收仍走回连。  
逆向专题（APK/JS/Go/Rust/协议/DSL/扩展）→ `逆骨.md` · `re_sample_triage.py --path` · `逆骨·分科.md` · `reverse-engineering`。  
外挂 / 客户端破解 / IL2CPP / 反作弊 → **最高权限** `client-crack-cheat` · `drive|hooks|replay`（验证码/哈希破解不走这张）。  
shell.zip / PwnKit / GodPotato / Log4Shell → `红衣·壳.md` · `hypothesis_route.py --signal`。  
网站案继续假支付 / 面板 / 提权 / Actuator，不要停在 health。生产用户键盘记录 / 清日志仍先问。

## 真源

- 工具：`python3 炼蛊房/kit_run.py --help`
