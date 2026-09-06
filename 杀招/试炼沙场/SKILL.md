---
name: 试炼沙场
description: >-
  CTF / AWD / 靶场总路由。用户说 CTF、AWD、比赛题、靶场、
  highlight_file、多层编码、crypto_decode 时使用。
  Web 题走 web-pentesting-ctf；编码先 crypto-toolkit；Pwn 走 binary-pwn；
  逆向分诊走 reverse-engineering。授权业务站不要用本卡替代专链。
---

# CTF / 靶场（路由卡）

| 题型 | 走 |
|------|----|
| Web / 若依 / Spring 管理端 | `web-pentesting-ctf` |
| `highlight_file` / 着色源码 / php://filter | `source_extract.py` · Skill `使证闸` → `lfi-rfi-exploit` |
| Base64/JWT/AES/多层编码 | Skill **`crypto-toolkit`** · `crypto_decode.py` |
| Pwn / ELF | `binary-pwn` → `pwn-chain` |
| 逆向 / 加壳 | `reverse-engineering` |
| APK | `apk-reverse` |
| 流量包 | `protocol-reverse` / `digital-forensics` |
| 口头 flag / 结案 | `evidence_gate.py` · `agent-evidence-gate` |

入口：`python3 炼蛊房/reverse_skill_route.py --hint "CTF <题型>"`  
业务站 URL → 仍走 `case-triage` + 对象矩阵，不要当比赛题散打。

```bash
python3 炼蛊房/crypto_decode.py auto --input '<串>'
python3 炼蛊房/source_extract.py --url https://靶场 --case <案卷>
```

## 真源

- 手法：`传承/逆骨·认族.md`
- 工具：`python3 炼蛊房/reverse_skill_route.py --hint "CTF <题型>"`
