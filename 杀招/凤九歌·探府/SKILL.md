---
name: 凤九歌·探府
description: >-
  大爱仙尊渗透总控方法论 — 流程脊柱。范围管控、六门验证闸、证据导向、
  断点续跑、对象矩阵、报告生成。处理任何授权渗透、SRC 众测、攻防演练时首先加载。
  触发：渗透测试方法论 / 总控流程 / 验证闸 / 报告模板 / 测试范围管控 /
  证据链 / 断点续跑 / SRC 众测流程 / 攻防演练编排。
---

> **凤九歌**
> 魔不魔，正不正，天地自有凤九歌。
> 走不走，留不留，死生皆在我心头。

# 渗透总控方法论

大爱仙尊所有攻击面 Skill 的**流程脊柱**。专卡打穿一格，本卡保证不跑偏、不结假案。

先读：`传承/智慧蛊·总控.md`

```bash
python3 炼蛊房/scope_expand.py --grant <域> --case <案> --note "用户授权"
python3 炼蛊房/case_triage.py board
python3 炼蛊房/object_matrix.py init --case <案>
python3 炼蛊房/object_matrix.py check --case <案>
```

## 铁律

1. **范围先行**：不在 `授权范围` 就先 `--grant`，禁止手改整份 company.json。
2. **每请求核对范围**：payload 发出前对照 host。
3. **先记录后分析**：请求/响应落盘后再读。
4. **范围歧义就停**：问清楚再打。
5. **先问只剩破坏业务**：耗余额下单、删站/清数据、改原超管密。授权内 L2/L3 本库命令直接跑。
6. **有身份先填矩阵**：`案卷/object_matrix.md`。专卡阴性必须回表换格子。
7. **用户说暂停**：立刻停进攻面。

## 六门验证闸

```
现象 → G1 可复现 PoC → G2 HTTP/日志原件 → G3 影响已验证
     → G4 在授权范围 → G5 真洞（非版本猜测）→ G6 可独立复现
     ├─ 全过 → VALIDATED（案卷/findings.md）
     ├─ 有缺 → NEEDS-WORK
     └─ G4/G5 失败 → REJECTED
```

负对照：注入/延时至少一次无 payload。版本命中 CVE 只是线索，sink 不可达不算洞。

## 工作流

```
授权 → case-triage 定级 → 对象矩阵（有身份就填）
  → recon / 指纹
    → 专卡分发（AGENTS 决策树）
      → 六门闸
        → STATUS + findings + coverage
```

| 指纹 | 先走 |
|------|------|
| 漏洞类型明确 | `web-vuln-router` |
| 无专用栈 | `strike_probe.py` S1–S8 |
| `/actuator` | Spring Gateway 全链，禁止只扫 health |
| `.hprof` / heapdump | 立刻 `heap_cred_scan.py` |
| 支付 / 白标 | 家族卡 + 假支付并行 |
| Linux 低权 shell | `linux-privilege-escalation` |
| 政务小程序 | `gov-wxmini-audit` |
| 通用 Web 长文 | `nine-stage-router` |

每个攻击面读上一阶段产物，不重复枚举。

## 产出

统一 `案卷/<案>/`：

| 文件 | 内容 |
|------|------|
| `STATUS.md` | 进度与复工条件 |
| `案卷/object_matrix.md` | 自己 vs 他人 × 读/写/加款/配置 |
| `案卷/findings.md` | 仅 VALIDATED |
| `案卷/coverage.md` | 已测未发现也写 |
| `案卷/tech-stack.md` | 栈指纹 |
| `接管/` · `支付/` | 证据原件 |

## 失败处理

| 现象 | 下一步 |
|------|--------|
| 专卡全阴 | `object_matrix.py next`，换对象/他人 |
| 缺工具 | coverage 记「未测」，不报阴性结案 |
| WAF / 本国封 | `evasion-kit` 或 `config/proxy-nodes.txt` |
| 想 SSH 用户主机当出口 | 禁止；只换代理节点 |

## 报告

合并 VALIDATED → 执行摘要 + 复现 + 修复。模板：`pentest-working-report`。未确认进覆盖表。

## 不走这张卡

| 指纹 | 走 |
|------|-----|
| 具体漏洞类型 | `web-vuln-router` |
| AD 域 | `ad-windows-router` |
| 只定级 | `case-triage` |
| 只写报告格式 | `pentest-working-report` |

## 真源

- 手法：`传承/智慧蛊·总控.md`
- 定级：`传承/春秋蝉·分案.md`
- 矩阵：`传承/万我.md`
- 总册：`传承/春秋蝉·分案.md`
- 工具：`python3 炼蛊房/case_triage.py board` · `python3 炼蛊房/object_matrix.py check --case <案>`
