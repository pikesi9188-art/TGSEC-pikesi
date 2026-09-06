---
name: 七十二层防
description: >-
  实战 SRC / 众测 / Bug bounty 漏洞挖掘工作流（已集成大爱仙尊约定）。
  包含：5 阶段方法论（scope-gate → intake → recon → enum → hunt → report）、
  19 个攻击类 playbook、305 个结构化 payload、176 个 WAF/EDR 绕过 payload、
  2900+ 份 HackerOne High/Critical 已披露案例（2836 条 / 144 类索引）、
  88,636 份 WooYun 统计、国产 OA / 中间件指纹库、银行 / 电信垂直 playbook。
  触发词：SRC 挖洞 / Bug bounty / 众测 / HackerOne / 漏洞赏金 / WAF 绕过 /
  如何挖某目标 / 怎么测某接口 / 任意 X 漏洞。
argument-hint: "<target-or-program-or-phase>"
level: 2
---

# 72stack-sec · 实战漏洞挖掘工作流（大爱仙尊版）

这是一个**带强制 checkpoint 的工作流**，不是参考手册。每个阶段有 MUST 输出，未通过不进下一阶段。
详细 payload / playbook / H1 案例**按需 Read**，不准凭记忆生成。

## 何时进 / 何时不进

命中任一即进本卡：
- SRC / 众测 / Bug bounty / HackerOne / 漏洞赏金
- 「如何挖 / 怎么测 / 怎么打」+ 某目标 / 某接口 / 某参数
- WAF 绕过、任意账号、任意修改、密码重置、未授权、默认凭据
- 用户丢一个 URL / API / APK 要按众测流程挖

**不进**（交给别的卡）：
- 纯白盒源码审计 → `deepaudit-code-audit`
- CTF / AWD / 靶场 → `ctf-sandbox`
- 已有专卡指纹（Actuator / 芋道代付 / FastAdmin 代付 / GVA / Doris）→ 先专卡，本卡补位

数据规模、目录树见卡内 `references/`。本文件只管做什么、何时做、去读哪个文件。

**本 skill 所有 references 的绝对根路径**（Read 时用这个前缀）：
```
/Users/sancai/Desktop/大爱仙尊/杀招/七十二层防/
```

---

## 反幻觉硬约束（全程适用）

1. **不准凭记忆出 payload**。要给任何 SQLi/RCE/SSRF/XSS payload 前，先 Read 对应 playbook 文件（路径见 Phase 4 路由表）。
2. **不准编造案例编号**。引用 H1/WooYun 前必须 Read `references/h1-reports/by-weakness/` 下的实际文件，说不出路径就不引。
3. **无证据不下结论**。无 HTTP 包/截图时只能写"待验证"，不写"已确认/发现漏洞"。
4. **scope 闸**：出 scope 立即停，回 Phase 0 重核；大爱仙尊用 `python3 炼蛊房/scope_expand.py --grant` 写入新目标。

---

## Phase 0 · Scope 闸（大爱仙尊专用）

**每次开测前必过，缺失即停：**

```bash
# 查目标是否已授权
python3 炼蛊房/scope_expand.py --check <域名>
# H1 案例 / payload 检索（本库）
python3 炼蛊房/h1_search.py --keyword <关键词>
python3 炼蛊房/payload_lookup.py --type <类型>

# 目标不在 scope → 先写入（SRC/众测授权场景用 --note 注明来源）
python3 炼蛊房/scope_expand.py --grant <域名> --case <案卷> --note "SRC授权/众测项目/H1 program"
```

- 确认 in-scope 后在 `案卷/<案卷>_<日期>/STATUS.md` 新建案卷头
- 证据落 `案卷/<案卷>_<日期>/`（HTTP 包 `.txt`、截图 `.png`）

---

## Phase 1 · Intake（接单）

**进入条件**：Phase 0 scope 确认通过。

**MUST 输出 checkpoint**（四项缺一不进 Phase 2，缺什么问用户）：

- [ ] **In-scope**：可测域名 / IP 段 / app / endpoint（逐条列）
- [ ] **Out-of-scope**：禁测项（逐条列）
- [ ] **规则**：payout tier / disclosure window / safe-harbor / 测试 header（如 `X-Bug-Bounty:<handle>`）
- [ ] **时间盒**：6h / 单日 / HVV / 月度

**仅当用户问"哪个最值得先测"时** → Read：
```
杀招/七十二层防/references/methodology/05-srctimebox-priority.md
```

---

## Phase 2 · Recon（被动侦察）

**进入条件**：Phase 1 四项全过。
**禁止**：任何主动发包（端口扫描 / 路径爆破 / payload 测试）。

**MUST 输出**：不发包给目标得到的资产清单 + 历史信息，来源 ≥3 种：
- CT 日志（crt.sh / Censys）
- Wayback / CommonCrawl 历史快照
- GitHub dorks（`org:target` + `password|api_key|SECRET|.env`）
- FOFA / Shodan favicon hash — 可调用 `tools/space-search/`
- SecurityTrails / DNS 历史
- ASN / IP 段（bgp.he.net）

---

## Phase 3 · Enum（主动探测）

**进入条件**：Phase 2 资产清单非空。

**MUST 输出**：活资产矩阵——`域 → 端口 → 服务 → 指纹 → JS endpoint`

**工具**：国内目标子域首选 OneForAll；规模化初筛用下方 nuclei 模板（payload 均出自本库 playbook）：
```
杀招/七十二层防/references/tools/nuclei-templates/
```
命中后回 playbook 走完整流程，不要只拿核扫结案。

**条件触发 Read**（命中就必读）：

| 命中信号 | MUST Read |
|---|---|
| 指纹含 `weaver/seeyon/tongda/landray/yongyou/kingdee/hikvision/dahua` | `杀招/七十二层防/references/dictionaries/chinese-srcfingerprints.md` + `杀招/七十二层防/references/dictionaries/default-credentials-cn.md` |
| 资产含 银行 / 支付 / 网银 / 第三方支付聚合 | `杀招/七十二层防/references/industry/banking-finance.md` |
| 资产含 运营商 / BOSS / 网管 / 物联网卡 | `杀招/七十二层防/references/industry/telecom-isp.md` |

---

## Phase 4 · Hunt（漏洞探测）

**进入条件**：Phase 3 矩阵 ≥1 个候选目标。

**强制流程（每个候选目标走一遍）**：
1. 看目标信号，从下表选 1 个 playbook
2. **Read 该 playbook 文件**（不准跳过、不准凭记忆替代）
3. 按 playbook 的"参数频率表"挑入口
4. 按 playbook 的"payload 库"探测——payload 来自文件，不来自训练记忆
5. 被 WAF 拦 → Read `杀招/七十二层防/references/methodology/02-bypass-toolkit.md` 决策树
6. 命中后立即保存 HTTP 包 / 截图到 `案卷/<案卷>/` → 进 Phase 5

### Playbook 路由表

| 入口信号 | MUST Read |
|---|---|
| Actuator / Swagger / 默认端口 / 弱密码 | `杀招/七十二层防/references/playbooks/unauth-access.md` |
| .git / .svn / .env / heapdump / 路径列举 | `杀招/七十二层防/references/playbooks/info-disclosure.md` |
| 用户态 ID 可遍历 / 任意 X 越权 | `杀招/七十二层防/references/playbooks/arbitrary-x-authz.md` |
| 密码重置 / 支付 / 验证码 / 订单 / 提现 | `杀招/七十二层防/references/playbooks/logic-flaws/00-index.md` |
| OAuth / SAML / JWT / redirect_uri | `杀招/七十二层防/references/playbooks/oauth-saml-jwt/00-index.md` |
| REST API / BOLA / Mass Assignment / 速率 | `杀招/七十二层防/references/playbooks/api-rest/00-index.md` |
| 任何用户输入进 DB | `杀招/七十二层防/references/playbooks/sqli.md` |
| 反序列化 / SSTI / XXE / 原型链 / 框架 RCE | `杀招/七十二层防/references/playbooks/rce/00-index.md` |
| URL 入参 / 缓存 / Host 注入 | `杀招/七十二层防/references/playbooks/ssrf-cache-host/00-index.md` |
| 文件路径入参 / LFI / RFI | `杀招/七十二层防/references/playbooks/path-traversal/00-index.md` |
| 上传点 + 解析漏洞 | `杀招/七十二层防/references/playbooks/file-upload/00-index.md` |
| 用户输入回显到 HTML / JS | `杀招/七十二层防/references/playbooks/xss/00-index.md` |
| 反代 + Content-Length / TE | `杀招/七十二层防/references/playbooks/http-smuggling.md` |
| GraphQL endpoint / introspection | `杀招/七十二层防/references/playbooks/graphql.md` |
| 并发 / TOCTOU | `杀招/七十二层防/references/playbooks/race-conditions.md` |
| ReDoS / 资源不限速 / 算法爆炸 | `杀招/七十二层防/references/playbooks/dos.md` |
| APK / IPA / 移动端 | `杀招/七十二层防/references/playbooks/mobile.md` |
| LLM agent / prompt 入口 / 工具调用 | `杀招/七十二层防/references/playbooks/llm-prompt-injection/00-index.md` |
| 已拿到 shell / 凭据 / 内网 | `杀招/七十二层防/references/playbooks/intranet-postexp/00-index.md` |

**两步 Read 模式（目录形式 playbook）**：
`rce/` / `oauth-saml-jwt/` / `ssrf-cache-host/` / `api-rest/` / `logic-flaws/` /
`file-upload/` / `path-traversal/` / `xss/` / `llm-prompt-injection/` / `intranet-postexp/`
→ 第一步只 Read `00-index.md`（含子文件路由），**不要把 00-index 当 payload 库**，
再据路由 Read 具体子文件（如 `rce/14-ssti.md` / `oauth-saml-jwt/12-jwt.md`）。
单文件 playbook（`sqli.md` / `arbitrary-x-authz.md` 等）直接 Read。

### 通用方法论（卡壳时 Read，不要预加载）

| 场景 | Read |
|---|---|
| 不知道下一步打什么 | `杀招/七十二层防/references/methodology/01-attack-priority.md` |
| 被 WAF / EDR 拦 | `杀招/七十二层防/references/methodology/02-bypass-toolkit.md` |
| 怀疑幻觉 / 检查证据链 | `杀招/七十二层防/references/methodology/03-evidence-discipline.md` |
| 找不到漏洞点 | `杀招/七十二层防/references/methodology/04-control-gap-hunting.md` |
| 对齐 2026 一线打法 | `杀招/七十二层防/references/methodology/06-hunter-methodology-2026.md` |
| SPA endpoint / 隐藏路由 / 密钥 | `杀招/七十二层防/references/methodology/07-js-recon.md` |

### 与大爱仙尊专卡的分工

有指纹先专卡。本卡只补**没有专卡的通用 SRC/众测面**。

| 目标信号 | 优先走 |
|---|---|
| `/actuator` + `gateway/routes` / heapdump | `spring-actuator-cloud-takeover` |
| Nacos `/v3/auth/user` | `nacos-authscope-unauth`（先 `--check-only`） |
| FastAdmin 代付 / 卡商 | `fastadmin-daifu-pentest` |
| 芋道 `mock-enable` / `file-config` / TMA | `yudao-daifu-mock-file-rce` / `yudao-appapi-pentest` |
| GVA 开放注册 / authorityId | `ginvue-admin-stealth-takeover` |
| Doris / StarRocks `:9030/:8030` | `doris-unauth` |
| 假支付 / USDT 归属 / `wallet_id` | `payment-callback-forgery` / `usdt-deposit-attribution-hijack` / `fund-edge-ops` |
| 白标盘口 / 不确定哪一家 | `gambling-family-router` |
| 开放目录 / `.env` / Index of / 猎杀者 | `sensitive-dir-dump` |
| Next.js / `Next-Action` / React2Shell | `nextjs-ssr-hunt`（NEXTAUTH/Kyber 先 `tg-bot-nextauth-takeover`） |
| TG Bot webhook / Token | `tg-bot-webhook-hijack` |
| 微信小程序 / wxapkg | `wxmini-static-audit` |
| JS / Webpack / JSVMP / 加密 API | `js-reverse` / `encrypted-api-spa`（本卡 `07-js-recon` 只做抽面） |
| APK 情报 / 完整反编译 | `apk-recon` / `apk-reverse` |
| 已拿 shell 提权 | `linux-lpe` / `windows-lpe` |
| 无专用栈、侦察后突击 | `strike-probe`（S1–S8） |

---

## Phase 5 · Report（提交 + 落证据）

**进入条件**：Phase 4 至少一个 finding 具备可重现 HTTP 包 / 截图 / 视频。

**MUST 流程（顺序执行）**：

1. 先认轨：SRC/众测读合规红线；授权自检按本库闸，不要用平台「证明即止」卡住 L2。
   ```
   杀招/七十二层防/references/compliance.md
   ```
2. SRC/众测再读报告模板（CVSS 4.0 三段式）：
   ```
   杀招/七十二层防/references/templates/report-submission.md
   ```
3. 三段式输出（SRC 提交用；授权自检同样要可复现）：
   - **标题**：≤80 字，精确到 endpoint + 漏洞类型
   - **重现步骤**：每步可执行，带 HTTP 包 / curl / 截图
   - **影响 + 修复建议**：CVSS 4.0 vector + 业务影响段
4. **落大爱仙尊证据**（两条轨都要落）：
   ```
   案卷/<案卷>_<日期>/
     STATUS.md          ← SRC 写 REPORTED；授权自检写 CONFIRMED / 可验证
     <漏洞类型>_PoC.txt ← 完整 HTTP 包
     <漏洞类型>_证明.png ← 截图
   ```

---

## MCP 工具集成

默认 `mcp__jshook__search_tools` + `mcp__jshook__activate_tools` 按需激活。
完整索引仅在用户问"用什么工具 / Burp / Frida / adb"时 Read：
```
杀招/七十二层防/references/tools/mcp-jshook.md
```

2026 工具框架选型（OneForAll / httpx / nuclei / feroxbuster 等）：
```
杀招/七十二层防/references/tools/frameworks-2026.md
```

## 真源

- 手法：`传承/春秋蝉·分案.md`
- 工具：`python3 炼蛊房/h1_search.py --help`
