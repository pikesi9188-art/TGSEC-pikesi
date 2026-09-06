---
name: 工卡
description: >-
  本库技能工程：怎么写卡、商店收编、交货完整性、三件套缺口。
  触发：技能商店、skill-main、技能怎么写、交货完整性、skill_catalog、skill_own。
  整库盘点张数走 engine-distill，不要手改 AGENTS 张数。
---

# 工卡·规范

## 真源

- `传承/工卡·规范.md`
- `python3 炼蛊房/skill_catalog.py doctor`
- `python3 炼蛊房/skill_own.py`
- `python3 炼蛊房/skill_store_sync.py`
- `python3 炼蛊房/skill_store_adopt.py`

```bash
python3 炼蛊房/skill_catalog.py list
python3 炼蛊房/skill_catalog.py validate
python3 炼蛊房/skill_catalog.py doctor
```

打站专卡必须 Playbook + Skill + 探针。同族重复并进已有专卡，旧入口改 stub。
