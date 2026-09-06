---
name: 残忆
description: >-
  数字取证路由卡。触发：Volatility、内存 dump、磁盘镜像、PCAP 取证、
  浏览器/邮件伪证保全。授权 Linux 主机排后门仍走 host-ir-check，不要用本卡替代。
---

# 数字取证（路由卡）

## 本仓探针

```bash
python3 炼蛊房/forensic_surface_probe.py drive --path <导出> --case <案>
```

L2=计到凭据类工件；不吐值。证据进案卷 `测绘/`。

```bash
python3 炼蛊房/css_query.py list-skills --module 30
python3 炼蛊房/css_query.py get --id 30-002
```

| 场景 | 走 |
|------|----|
| 已拿 Linux shell 排后门 | `host-ir-check` · `host_ir_check.py` |
| WP 高熵马 | `wp-shell-drop-hunt` |
| 内存 / 磁盘 / 浏览器取证百科 | CSS 30 |
| 流量还原协议 | `protocol-reverse` |

保全优先于分析：先哈希、只读副本，再开工具。

## 真源

- 手法：`智道藏书/三十九门/30-残忆/MODULE.md`
- 工具：`python3 炼蛊房/css_query.py list-skills --module 30`
