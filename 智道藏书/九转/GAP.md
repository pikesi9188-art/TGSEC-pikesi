# 九阶段技能缺口

> 结论先看：**方法论与 Skill 正文已补齐；二进制武器库你本来就强；缺口主要是「图中国产综合扫描器 GUI」和「内网/提权官方包未预置」。**  
> 策略：**能开源官方装的写进 vendor；破解/未知源坚持不收录**（与 `kb/TOOLS-INDEX.md` 一致）。

图例：✅ 已有可用 · 📦 源码在 vendor · 📥 本轮已接入 · ⚠ 缺（可官方补） · 🚫 不收录 · ↔ 本库等价替代

---

## 总览

| 板块 | 笔记/技能包 | 本库现状 | 缺口等级 |
|------|-------------|---------|----------|
| 01 信息收集 | 长文 + recon skills | FOFA/uncover/subfinder/amass/httpx/katana/nmap/OneForAll/LinkFinder | **低**（已补 CDN 溯源） |
| 02 漏洞扫描 | xray/afrog/fscan 等 | nuclei/nikto/ferox/sqlmap/引擎 pentest | **中**（综合扫描器未预置） |
| 03 利用/GetShell | webshell/反序列化图 | 逻辑脚本+杀伤链 Playbook；无 webshell 包 | **中**（合规缺口，按需自备） |
| 04 免杀/绕过 | WAF/流量马 | sqlmap tamper + **waf-detector 已接入** | **低** |
| 05 隧道 | frp/suo5 等 | proxy 池文档；隧道工具自备 | **中**（实验室） |
| 06 弱口令 | hydra 等 | hydra/medusa/john/hashcat/字典 | **低**（cewl 可选） |
| 07 提权 | linpeas 等 | 文档有；peas 未预置 | **中**（实验室官方 release） |
| 08 横向 | AD/CS | enum4linux/smbmap；CS 🚫 | **中** |
| 09 辅助 | 编解码/JD-GUI | jwt_tool/gitleaks/frida/gdb | **低** |
| Agent Skills | 110 个（盘点 2026-08-17） | 全文在 `skills/` | **已补全文** |

---

## 01 信息收集

| 图中/笔记 | 本库 | 状态 |
|-----------|------|------|
| FOFA / FofaViewer | `python main.py fofa` + VIP Key | ✅ |
| 鹰图 / Goby GUI | 本机自装 GUI；被动用 FOFA+uncover | ↔ |
| OneForAll / dddd | `tools/vendor/01-recon/OneForAll` | 📦 |
| enscan / appinfo | 无专用二进制；企业信息用公开检索+授权 FOFA | ⚠ 可选 |
| apitool / vuescan / webpackscan | katana + LinkFinder + `tools/web-reverse/` | ↔ |
| dirsearch / ferox | arsenal + vendor | ✅ |
| CDN 找源 | **`tools/vendor/01-recon/cdn-origin-tracing/`** | 📥 |
| Skill: recon-* | `nine-stage/skills/recon-*` | 📥 |

```bash
# CDN 溯源（仅授权域）
python3 tools/vendor/01-recon/cdn-origin-tracing/cdn_tracer.py 授权域.com -o 案卷/.../cdn.json --no-verify
```

---

## 02 漏洞扫描

| 图中/笔记 | 本库 | 状态 |
|-----------|------|------|
| nuclei | `tools/arsenal/bin/nuclei` | ✅ |
| xray / afrog / fscan / kscan | 未预置 | ⚠ 官方 release → `tools/vendor/02-scan/` |
| ThinkPHP / 若依专项 | Playbook `传承/若府·云控.md` + `炼蛊房/ruoyi` 探针 | ✅ 业务向 |
| Java 反序列化全家桶 | 文档+原理卡；yso 等实验室自备 | ⚠/🧪 |
| Seay-Svn / supersql | 待核验/自备；通用：`.git`/备份用引擎 backup-fetch | ↔ |

建议补装（官方）：

```bash
mkdir -p tools/vendor/02-scan
# 自行从 GitHub Release 下载 afrog / xray 到该目录后 chmod +x
# 不写进仓库破解镜像
```

---

## 03 利用与权限获取

| 图中/笔记 | 本库 | 状态 |
|-----------|------|------|
| sqlmap | ✅ arsenal | ✅ |
| 蚁剑/冰蝎/哥斯拉 | 🚫 破解包不收录 | 官方渠道实验室自备 |
| 支付/逻辑/越权 | `vendor/04-logic` + Playbook + Cursor skills | ✅ **你的强项** |
| Spring Gateway heapdump | `tools/spring-gateway-killchain/` | ✅ |
| PocketBase / TG MiniApp | `杀招/*` + 九阶段 `telegram-mini-app-bot-security` | ✅/📥 |

---

## 04 免杀与流量绕过

| 图中/笔记 | 本库 | 状态 |
|-----------|------|------|
| WAF 识别/绕过库 | **`tools/vendor/09-aux/waf-detector/`** | 📥 |
| 未知免杀 EXE / 流量马合集 | 🚫 | 不收录 |
| sqlmap tamper / 降速换 UA | ✅ | ✅ |

```bash
python3 -m pip install -r tools/vendor/09-aux/waf-detector/requirements.txt
python3 tools/vendor/09-aux/waf-detector/waf_hunter.py detect -t https://授权站
```

---

## 05–08 隧道 / 弱口令 / 提权 / 横向

| 项 | 状态 | 动作 |
|----|------|------|
| 出口代理池 | ✅ `config/proxy.yaml` | 继续用 |
| frp / suo5 / Neo-reGeorg | ⚠ 自备实验室 | 见 `kb/stages/05` |
| hydra/medusa/john/hashcat | ✅ | — |
| cewl | ⚠ | 有 brew 时再装；可用 crunch 替代 |
| linpeas/winpeas | ⚠ | 官方 release 自备 |
| netexec / crackmapexec | ⚠ | 可选 |
| Cobalt Strike / Mimikatz / 开源 C2 | ⚠ | 作业机自备；授权主机 L3 走 `host_c2_verify.py` |

---

## 09 辅助

| 项 | 状态 |
|----|------|
| jwt_tool / gitleaks / trufflehog / frida | ✅ |
| JD-GUI | ⚠ 可选 GUI 自装 |
| 编解码方法论 | 📥 `stages/09-*.md` |

---

## Agent Skills（112）接入状态

| 位置 | 说明 |
|------|------|
| `智道藏书/九转/skills/` | **全文已落盘** |
| `杀招/九转/` | 路由：按关键词读对应 SKILL |
| `杀招/` 业务三条 | 支付回调 / PB Horizons / BPP — **保留优先于通用包** |
| `智道藏书/SecAtlas/` | 原理库（目录名没改）；与九阶段并存不覆盖 |

业务恢复时优先级：

1. 授权 scope  
2. 业务 Cursor skill / Playbook  
3. 九阶段对应漏洞类 Skill  
4. 通用扫描器  

---

## 本轮已补齐清单

- [x] 九阶段长文 → `nine-stage/stages/`
- [x] 110 Skills → `nine-stage/skills/`
- [x] waf-detector → `tools/vendor/09-aux/waf-detector/`
- [x] cdn-origin-tracing → `tools/vendor/01-recon/cdn-origin-tracing/`
- [x] GAP / SKILL_MAP / README
- [x] kb/stages 短版加「详解链接 + 本库命令」
- [x] TOOLS-INDEX / kb README 入口
- [x] `杀招/九转`

## 仍建议你本机补（不强制进仓）

1. afrog 或 xray 官方 release → `tools/vendor/02-scan/`  
2. Go 环境 → 编译 `ffuf-src`、`gau`、`waybackurls` 到 arsenal bin  
3. 实验室：linpeas、frp（官方）  
4. GUI：Burp 社区版、JD-GUI、Goby（自装）  
