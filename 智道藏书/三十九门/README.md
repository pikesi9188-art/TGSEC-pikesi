# 网络安全技能库（大爱仙尊分类层）

> 分类表：[`CATALOG.md`](./CATALOG.md)  
> 查询：`python3 炼蛊房/css_query.py search --keyword SQL`

技能散在 `杀招/`、实战长文仓、扩展包、Playbook。  
本目录补同一套 39 类索引；打站仍走大爱仙尊命令。

## 怎么用

```text
先认模块（01–39 或 00 业务）
  → 打开该目录 MODULE.md 看本库入口
  → 有专卡/探针就跑本库命令
  → 没有专卡再读该模块 `skills/` 知识卡
```

```bash
python3 炼蛊房/css_query.py list-modules
python3 炼蛊房/css_query.py list-skills --module 05
python3 炼蛊房/css_query.py search --keyword 凭证
python3 炼蛊房/css_query.py get --id 05-002
python3 炼蛊房/css_query.py doctor
```

知识卡全文在各模块 `skills/` 下（不要用模块根路径）。

## 目录

```
00-大爱仙尊业务-大爱仙尊/     ← 本库业务：假支付/盘口/TG号库
01-风闻/
…
39-律道/
CATALOG.md                         ← 39 模块对照 + 195 逐条
```

## 和另外两包的关系

| 包 | 干什么 |
|----|--------|
| `杀招/` | 自动触发、直接跑命令 |
| `九转` | 九阶段通用洞 |
| `extended-pack` | 白标/芋道/Qzino/号库 |
| **本包** | 39 类总目录 + 工控/取证/SOC |
| 百科检索 | `三十九门·检索.md` · `css_query.py` |
| 逆向作业卡 | `杀招/` 逆向族 + `逆骨·认族.md` |

冲突时：**业务 Skill > 本包分类卡 > 百科检索。**

C2 / 凭证转储 / 键盘记录 / AMSI·EDR：知识卡在 `05` / `03` / `08` 的 `skills/`。用 `css_query.py` 打开。不在本仓库新增 C2 框架、键盘记录器或免杀补丁实现。
