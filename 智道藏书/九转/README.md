# 大爱仙尊九阶段技能包

> 九阶段长文 + 通用 Skill。打站仍先走业务专卡与 `杀招/`。  
> 只保留方法论 / 开源工具脚本；破解 CS、未知 webshell 包、灰产网盘工具 **不装进 arsenal**。

打站流程脊柱是 `杀招/凤九歌·探府`，不是本包长文。本包补通用手法；业务专卡优先。

## 30 秒入口

| 你要什么 | 去哪 |
|----------|------|
| 九阶段详解 | [`stages/`](./stages/) |
| Agent Skill | [`skills/`](./skills/) |
| 本库缺什么 / 用什么替代 | [`GAP.md`](./GAP.md) |
| Skill → 阶段 / 恢复链 映射 | [`SKILL_MAP.md`](./SKILL_MAP.md) |
| 实战命令 | `../kb/FULL-CHAIN.md` + `../kb/TOOLS-INDEX.md` |

## 目录布局

```
智道藏书/九转/          ← 大爱仙尊九阶段学习真源
  stages/01…09-*.md
  skills/<name>/SKILL.md
  GAP.md / SKILL_MAP.md / README.md

tools/vendor/01-recon/cdn-origin-tracing/
tools/vendor/09-aux/waf-detector/

智道藏书/kb/stages/0N-*.md     ← 短版可执行卡
杀招/九转/ ← 何时读本包
```

## 与两套主链的关系

```
A. 通用九阶段（本包 stages + kb/stages）
B. 业务恢复九步（大爱仙尊使用/WORKFLOW.md）

实战自有站：先 B（授权/闭环），卡点时按栈去 A/Skill 补手法。
```

## 快速自检

```bash
cd ~/Desktop/大爱仙尊
ls 智道藏书/九转/stages | wc -l
ls 智道藏书/九转/skills | wc -l
python3 tools/vendor/09-aux/waf-detector/waf_hunter.py -h
python3 tools/vendor/01-recon/cdn-origin-tracing/cdn_tracer.py -h
```
