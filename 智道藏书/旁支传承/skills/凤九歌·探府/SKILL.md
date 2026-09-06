---
name: 凤九歌·探府
description: "授权渗透/打站/继续打时使用。P0-P6 全链执行, 发现表动态切技能, MCP工具执行, MD报告交付。"
version: 1.3.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, workflow, orchestration]
    category: daaixianzun
---

> **凤九歌**
> 魔不魔，正不正，天地自有凤九歌。
> 走不走，留不留，死生皆在我心头。

# 渗透工作流总纲(匕首定制)

## 触发条件
- "开始渗透 xxx" / "打 xxx" / "扫一下 xxx" / "有没有漏洞" / "继续打" / "写入授权" → 本技能
- CTF/沙箱/靶场 → `ctf-sandbox-orchestrator`
- 纯信息收集 → `recon-for-sec`
- 用户已授权(说过渗透/测试/写入授权)= auth.status=granted, 直接执行, **不反复确认**

## 第一步(永远先做, P0)
1. 建 scope: target / in_scope / out_of_scope / auth.status
2. 读 `attack-router` 意图路由表, 定 PRIMARY skill
3. 建证据目录: `evidence/<date>-<target>/`
4. 用户说"继续啊/确认/继续" → **立即执行下一步, 不重述计划, 不问是否继续**

## 执行链 P0-P6

| 阶段 | 动作 | skill |
|---|---|---|
| P0 | 定Scope/授权/证据目录 | recon-and-methodology |
| P1 | 子域/DNS/端口/指纹/WAF/CDN | recon-for-sec → network-penetration-testing |
| P2 | 按指纹分流攻击面 | api-sec / auth-sec / injection-checking / file-access-vuln / business-logic-vuln |
| P3 | 深度测试, 发现表命中即切 | 30+ playbook |
| P4 | 并行多面 | api/auth/injection/file/business/misc/poc agent |
| P5 | 攻击链+证据复查 | vuln-analysis-agent |
| P6 | 分级/CVSS/报告 | vulnerability-assessment → MD |

**每阶段必须产出实际数据文件**, 不是日志。最终 MD 报告交付。

## 阶段门（Phase Gate，强制 — 防技能漂移）

**每进入一个新阶段，第一步固定是技能核验。禁止"开头加载过一次就沿用到底"。**

| 触发 | 动作 |
|---|---|
| 切新目标 / 新域名 | 重跑 attack-router 意图路由，查对应 skill 再动手 |
| 切攻击面（Web→逆向 / Web→API / Web→内网 / Web→移动） | 先加载对应分类路由 + playbook，再开工 |
| delegate_task 下发子任务前 | 先确认子代理该带哪个 skill，把它写进 context |
| 发现已有 skill 不覆盖当前场景 | 当场 patch 该 skill，不硬猜、不绕行、不临时发挥 |
| 会话变长 / 怀疑漂移 | 回读本阶段应用的 skill 的 SKILL.md，确认仍在场 |

阶段门在 P0-P6 **每一阶段进入时**执行，不只 P0 一次。顺序：核验技能 → 读 SKILL.md → 干活 → 产出数据 → 进下一阶段门。

**阶段门（每个新阶段第一步，强制）— 技能重核，禁止「开头加载一次就漂」**:
- 切新目标/新域名 → 先通过 skill 工具重新加载该目标/产品族对应 skill（reverse-skill 的 product-family reference 等）再动手
- 切攻击面（Web→逆向 / →API / →云 / →K8s）→ 先查 category router（api-sec / auth-sec / injection-checking / file-access-vuln / business-logic-vuln…）或对应 playbook
- delegate_task 下发子任务前 → 先确认子代理该带哪个 skill，把 skill 名 + 关键要点写进子任务 context，不能裸发
- 发现已有 skill 不覆盖当前场景 → 当场 patch 补缺，禁止硬猜瞎打
- 会话长、轮次多 ≠ skill 免检：每个阶段的第一步固定是技能检查

## 发现表(高频)

| 看到 | 切到 |
|---|---|
| Cloudflare/拦截 | waf-detector → waf-bypass-techniques |
| SQL报错 | sqli-sql-injection |
| 401/403后台 | 401-403-bypass-techniques |
| JWT | jwt-oauth-token-attacks |
| 可换对象ID | idor-broken-object-authorization |
| .git/.env | insecure-source-code-management |
| CDN源站不明 | cdn-origin-tracing |
| 加密签名/JSVMP/WASM | frx-director MCP |
| BR/PT tRPC + `__APP_CONFIG__` + api*.a-b-c | **br-gambling-trpc-spa-pentest** |
| `405 region` / 地理墙 | 换出口或同源家族站, 勿空转 header |

## 业务场景链

| 场景 | 链路 |
|---|---|
| RocketGo客服 | fofa → 未授权API → 卡密下载 |
| TG号商/发卡 | 未授权API → admin card-secrets |
| Sub2API | 注册送余额 → key 跨站验证 |
| BR tRPC 白标 | br-gambling-trpc-spa-pentest: Cookie token_user 真会话 |
| RuoYi | ruoyi-pentesting |
| 通用 | P0-P6 |

半程利用 ≠ 打穿。禁止把半程说成打穿。

## 执行规则

0. **阶段门技能核验(每阶段第一步, 不只开头一次)**: 切新目标/切攻击面(Web→逆向/API等)/delegate_task 下发前→先查对应 skill; 发现已有 skill 不覆盖当前场景→**当场 patch, 不硬猜**。会话再长也不漂, 不以"开头已加载过"为准。
1. 授权即动: 渗透/继续/写入授权 → 直接打, **禁止二次确认/收尾问是否继续**
2. 一步一报 ≠ 一步一停: 每步 3-5 行边打边报, **同回合继续 tool**, 直到凭证或明确硬墙选项
3. 硬墙: 遇 IP 白名单/鉴权墙先穷尽 SSRF/MinIO/MySQL/SSH/GitHub/**同源家族站**/出口代理, 最后才选项问方向
4. 交付: JSON indent=2 筛选再发; 报告 MD; MEDIA 逐个; 卡密/后台库存主成果
5. 空壳映射: sql-injection-testing→sqli-sql-injection 等
6. 禁止 jailbreak/破甲内容
7. 攻破即输出凭证/路径
8. 半程利用 ≠ 打穿, 禁止把半程说成打穿

## 收尾

- findings 落地 evidence/
- 报告 MD + 筛选 JSON/TSV MEDIA
- RoE 只写用户 scope + 硬限制
