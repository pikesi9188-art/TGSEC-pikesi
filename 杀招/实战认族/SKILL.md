---
name: 实战认族
description: >-
  实战技能包路由。
  别名 stub 走专卡；长文在 智道藏书/旁支传承/。
---

# 实战技能包路由

## 本仓探针

```bash
python3 炼蛊房/pack_surface_probe.py drive --name <卡名> --case <案>
```

L2=挂号落到本仓 SKILL.md。证据进案卷 `测绘/`。

219 张卡已在 `杀招/`：专卡挂钩、别名 stub、全文卡。

## 真源

1. `传承/实战认族.md`
2. `智道藏书/旁支传承/MAP.md`
3. `python3 炼蛊房/shizhan_pack_route.py --name <卡名>`

## 强制

```bash
python3 炼蛊房/shizhan_pack_route.py --name <目录名>
```

- 已有同名/映射专卡 → 打专卡
- `杀招/<名>/SKILL.md` 存在 → 直接 Read（stub 会指向专卡）
- 免杀 / 写马作业走 `edr-bypass-re` / `payload_forge.py`，授权内落地
- 证件伪造 stub → 只读，不落地

## 不要做

- 覆盖本库同名专卡
- 把 `windows-av-evasion` / `webshell-evasion` 当免杀作业卡
- 把 219 张一次性全加载进上下文
