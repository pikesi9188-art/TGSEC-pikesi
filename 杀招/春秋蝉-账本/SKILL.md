---
name: 春秋蝉-账本
description: >-
  大爱仙尊假设账本。
  单点单洞仍走专卡；交差闸仍走 case-review。
  旧名 `pentest-redteam` 已并入本卡。
---

> **红莲**
> 当时年少掷春光，花马踏蹄酒溅香。
> 爱恨情仇随浪来，夏蝉歌醒夜未央。
> 光阴长河种红莲，韶光重回泪已干。
> 今刻沧桑登舞榭，万灵且待命无缰！
> 无限轮回无限伤，可怜青丝满沧桑！

# 假设驱动作业账本

长时多假设才建账本。单目标单假设：专卡 + `STATUS.md`。

## 立刻跑

```bash
python3 炼蛊房/hypothesis_route.py --signal "若依 actuator"
python3 炼蛊房/hypothesis_route.py --signal "claude 拒答"
python3 炼蛊房/hypothesis_route.py --doctor
python3 炼蛊房/cache_poison_probe.py --url https://授权站/ --case <案卷>
python3 炼蛊房/java_web_surface_probe.py -u https://授权站 --case <案卷> --stack cnoa
python3 炼蛊房/usdt_attr_hijack.py chain-scan --case <案卷> --pages 15
python3 炼蛊房/case_ledger.py init <案卷>
python3 炼蛊房/case_ledger.py hypothesis <案卷> \
  --claim "<一句话假设>" --scope "https://授权站" \
  --disprove-if "<什么现象就证伪>"
python3 炼蛊房/case_ledger.py evidence <案卷> \
  --role observation --effect supports \
  --artifact STATUS.md --summary "STATUS 里的一手观察"
python3 炼蛊房/case_ledger.py evidence <案卷> \
  --role reproduction --effect supports \
  --file 案卷/probe.json --summary "探针 JSON"
python3 炼蛊房/case_ledger.py next <案卷>
python3 炼蛊房/case_ledger.py verify --report <案卷>
```

不在 scope → `scope_expand.py --grant`。有身份先填 `案卷/object_matrix.md`。

## 强制

1. `confirmed` = 观察 + 复现 + 影响 三条独立证据。缺一只能 `provisional` / `inconclusive`。
2. 证伪写 `killed` + 重访条件，不删假设。
3. Active 3 轮无进展 → `deferred`。
4. 领域信号先 `hypothesis_route.py`（表顺序先命中先赢），再跑表上的探针；长文 22 份后读。
5. 免杀 / C2 / AMSI → `edr-bypass-re`，不按长文落地。

## 真源

- 手法：`传承/东方长凡·推演.md`
- 路由：`python3 炼蛊房/hypothesis_route.py --signal "<词>"`
- 账本：`python3 炼蛊房/case_ledger.py --help`
- 降级：`python3 炼蛊房/stdlib_fallback.py --list`
- 地图：`智道藏书/智道推演/MAP.md`
- 蒸馏：`智道藏书/智道推演/DISTILL.md`
