---
name: 巨阳·群使
description: >-
 Pentest-Swarm-AI 蜂群渗透系统集成：stigmergic 黑板协同、RECON/CLASSIFY/EXPLOIT/REPORT
 四个独立 Agent、ProjectDiscovery 工具链（subfinder/httpx/nuclei/nmap 等）。
 授权目标广谱侦察入口，发现后交专用 Skill 深挖。
 
 /actuator 指纹 → 切 spring-actuator-cloud-takeover；支付链 → pay_matrix；
 源码 → deepaudit；本 Skill 负责广谱发现与结构化报告。
---

> **巨阳**
> 鸿运齐天福禄多，天下不过一掌中！
> 家天下里血脉长，镇运天宫坐夕阳。

# Pentest-Swarm-AI 蜂群集成

**前提**：目标必须在 `授权范围` 或 `授权范围/`。`psa_scan.py` 会自动门控，未授权直接拒绝。

## 何时启用

- 新站点入手，需要广谱侦察（子域名/端口/技术栈/CVE匹配）
- 想并行跑多 Agent 而非单脚本逐步推进
- 需要结构化 SARIF/HTML 报告存证
- 用户说「用蜂群扫」「PSA」「external-asm playbook」

## 强制顺序

### 1. 确认授权
```bash
python3 炼蛊房/scope_lib.py check <target> # 或直接看 scope.company.json
```
没有就先 `scope_expand.py` 写入，再开打。

### 2. 首次安装（只需一次）
```bash
bash tools/pentest-swarm/bin/install.sh
# 需要设置: export PENTESTSWARM_ORCHESTRATOR_API_KEY="sk-ant-..."
# 或: export ANTHROPIC_API_KEY="sk-ant-..."
```

### 3. 发起扫描

**广谱侦察（推荐入口）**
```bash
python3 tools/pentest-swarm/bin/psa_scan.py <target> --playbook external-asm
```

**完整蜂群模式（stigmergic，黑板协同）**
```bash
python3 tools/pentest-swarm/bin/psa_scan.py <target> --swarm
```

**Bug Bounty 模式**
```bash
python3 tools/pentest-swarm/bin/psa_scan.py <target> --playbook bug-bounty
```

**自定义输出**
```bash
python3 tools/pentest-swarm/bin/psa_scan.py <target> \
 --out 案卷/<case>_<date>/pentest-swarm/
```

### 4. 关注 Agent 输出，做分流

| PSA 输出 | 下一步 |
|---------|--------|
| `/actuator` 端点 | → `spring-actuator-cloud-takeover` Skill |
| `/actuator/gateway/routes` | → `spring-actuator-cloud-takeover` rule |
| 支付/回调路径 | → `payment-callback-forgery` Skill + `pay_matrix.py` |
| 发卡站指纹 | → `acg-faka` Skill |
| Admin 后台路径 | → `ginvue-admin-reward` Skill |
| SQLi 发现 | → `sqlmap-tamper-kit` Skill |
| CVE ≥ 7.0 | → 查 `tools/autocve/` 是否有 PoC |
| 高价值 JS/源码 | → `deepaudit-code-audit` Skill |

### 5. 报告落盘与 STATUS 更新

PSA 自动写报告到：
```
案卷/<site>_<date>/pentest-swarm/
├── report.md
├── report.html
├── report.json
└── report.sarif
```

执行完后更新 STATUS.md：
```
## Pentest-Swarm-AI 扫描
- 时间：<datetime>
- 目标：<target>
- 报告：pentest-swarm/report.md
- 重要发现：<列出 CVE/路径>
- 下一步：<接哪个 Skill>
```

## Playbook 速查

| 名称 | 适用 |
|------|------|
| `external-asm` | 外部资产测绘（**默认首选**） |
| `bug-bounty` | 公开 BB 计划 |
| `ctf` | CTF 靶机 |
| `internal` | 内网 / VPN 后 |
| `ci-cd` | GitHub Actions / Jenkins 等 |

## Swarm 工作原理（简述）

```
TARGET_REG 写入黑板
 │
 ├─ RECON agent（触发：TARGET_REG）
 │ subfinder/httpx/nuclei/naabu/katana/dnsx/gau/nmap
 │ → 写 SUBDOMAIN/PORT_OPEN/HTTP_ENDPOINT/TECHNOLOGY
 │
 ├─ CLASSIFY agent（触发：raw recon + pheromone > 0.2）
 │ CVE映射/CVSS v3.1/误配评分
 │ → 写 CVE_MATCH/MISCONFIGURATION/EXPLOIT_CHAIN
 │
 ├─ EXPLOIT agent（触发：CVE_MATCH + pheromone > 0.5）
 │ 构建攻击链，验证可利用性
 │ → 写 EXPLOIT_RESULT
 │
 └─ REPORT agent（触发：CAMPAIGN_COMPLETE）
 聚合黑板 → md/html/json/sarif
```

pheromone 会随时间衰减，旧路径自然消亡，资源向高价值发现聚集。

## 禁止

- 未经 scope 验证直接传 `--scope` 绕过 `psa_scan.py`（禁止手动调 docker run 绕门控）
- 把 PSA 生成的 SARIF/报告里的第三方 UAT 域名扩进 company scope
- `/actuator` 确认后继续跑 PSA 完整链，应立即切 spring-actuator Skill 更深

## 真源

- 工具：`tools/pentest-swarm/`
- 镜像：`ghcr.io/armur-ai/pentestswarm:latest`
- PSA 上游：https://github.com/Armur-Ai/Pentest-Swarm-AI
- 报告目录：`案卷/<site>/pentest-swarm/`
- 手法：`传承/春秋蝉·分案.md`
