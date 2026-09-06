---
name: 行器·对照
description: >-
  大爱仙尊技能别名路由。触发：技能名对不上、别名路由、有没有某张卡、技能别名。
  只对照本库专卡，不灌外来技能包。
---

# 技能别名路由（大爱仙尊）

用户丢来的手法别名对到本库专卡。对照完立刻开对应探针。

```bash
python3 炼蛊房/se_skill_alias.py --name tiandun-reversing
python3 炼蛊房/se_skill_alias.py --signal 天盾卡密
python3 炼蛊房/se_skill_alias.py --list
python3 炼蛊房/hypothesis_route.py --signal <同一句话>
```

开源版不带助手注入通道。  
对照实现：`炼蛊房/se_skill_alias.py` · `炼蛊房/se_skill_route.py`  
真源：`传承/行器对照.md`
