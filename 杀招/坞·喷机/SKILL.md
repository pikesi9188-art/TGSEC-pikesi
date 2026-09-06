---
name: 坞·喷机
description: >-
 授权 WordPress 上 Crocoblock JetEngine CVE-2026-66613 未认证 SSTI/RCE 版本指纹。
 
 只核对 readme 版本，禁止自造 SSTI。其它 WP 插件 ATO 走
 wordpress-plugin-unauth-takeover。
---

# JetEngine 未授权 RCE（版本闸）

**前提**：目标在 `授权范围`。无公开 sink，**禁止自造 `{{` / Twig**。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `jet-engine/readme.txt` 且 Stable tag ≤3.8.14 | 插件目录 403；`3.8.14.1+` 已修 |
| L2 | 默认停，等公开注入点 | 把「插件在」写成已 RCE |

```bash
python3 炼蛊房/jetengine_surface_probe.py --base https://授权站 --case <案卷>
```

## 四刀

1. **GET readme** — `/wp-content/plugins/jet-engine/readme.txt`  
2. **比版本** — `Stable tag` ≤ `3.8.14` 才报 L1  
3. **停** — 没有公开参数/路由就不要喷模板表达式  
4. **同站其它插件** — 切 `wordpress-plugin-unauth-takeover` / `wordpress-attack-router`

真源：`传承/坞·喷机.md`
