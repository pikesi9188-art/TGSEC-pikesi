---
name: 坞·旧令
description: >-
  授权目标上 WordPress xmlrpc.php 暴露面：listMethods、system.multicall、pingback.ping。
  HITCON 多次公开（xmlrpc 暴露 / wp2shell）。默认只探方法列表。
  已落地马走 WordPress高熵PHP马。插件 ATO 走 wordpress-plugin-unauth-takeover。
---

# WordPress xmlrpc 暴露面

**前提**：目标在 `授权范围`。默认 **只 `system.listMethods`**。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | GET/POST `xmlrpc.php` 是 XML-RPC，或 `listMethods` 成功 | 403/404 当已关 |
| L2 | 列表含 `system.multicall` 或 `pingback.ping` | 没爆破也算暴露面 |
| L3 | 凭据碰撞 / pingback SSRF | 探针不默认做；授权内手工 |

```bash
python3 炼蛊房/wp_xmlrpc_probe.py --base https://授权站 --case <案卷>
```

## 四刀

1. **找口** — `/xmlrpc.php` `/wp/xmlrpc.php` `/blog/xmlrpc.php`  
2. **列方法** — 一次 POST `system.listMethods`（探针已带）  
3. **认危法** — `system.multicall`（爆破加速）、`pingback.ping`（SSRF）、`wp.getUsersBlogs`  
4. **停** — 不要 multicall 撞密；已落地随机 `.php` 切高熵狩猎，**不把情报域扩权**

插件假付 / REST ATO → `wordpress-plugin-unauth-takeover`。总分流 → `wordpress-attack-router`。

真源：`传承/坞·旧令.md`
