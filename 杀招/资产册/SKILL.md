---
name: 资产册
description: >-
 授权目标上 UpSnap（Wake-on-LAN）未认证初始超管衔接到 wake_cmd RCE：
 CVE-2026-49819 / CVE-2026-49481。
 广谱 1day 仍走 1day-nuclei-kit；CVE 入库走 cve-daily-intel。
---

# UpSnap 未授权超管 → RCE（Cursor Skill）

## 何时用

- 指纹/标题出现 UpSnap、Wake-on-LAN 自托管面板
- 用户点名 CVE-2026-49819 / 49481 / `init-superuser`
- `nday_route` hit `upsnap`
- FOFA/空间测绘命中 UpSnap 且目标已在 scope

## 真源（按序）

1. `传承/资产册·开天.md`
2. `tools/1day-kit/custom-templates/upsnap-unauth-cve-2026-49819.yaml`
3. `传承/CVE日报-2026-08-13.md` §1
4. 情报：`od_kit.py cvebase lookup --cve CVE-2026-49819 --docs`
5. 顾问：https://github.com/seriousm4x/UpSnap/security/advisories/GHSA-w4jr-728f-5jhq

## 强制步骤

1. 目标在 `授权范围`。
2. 指纹：
 ```bash
 python3 炼蛊房/nday_family_probe.py --family upsnap --base https://授权站 --case <案卷>
  ```
3. **L2（授权内）**：按 Playbook §2 
 - 尚无超管：`POST /api/upsnap/init-superuser` 建探针超管拿 JWT 
 - 已有超管：记 STATUS，转弱口/已知账 + CVE-2026-49481 注入面 
 - 有会话后先 `id`/`hostname` 验证 `wake_cmd`，授权内写马/反弹直接做
4. 证据：`案卷/<案卷>/案卷/1day/` · 票放 `接管/upsnap_token.txt` 
5. 更新 `STATUS.md`（版本、是否已有超管、L2 结论）。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | nuclei/标题确认 UpSnap；`init-superuser` 非纯 404 |
| L2 | 拿到超管 JWT **或** 可验证命令执行回显 |
| 修复线 | ≥ 5.4.0；轮换密与 JWT |

影响版本：`>=4.4.1 <5.4.0`。

## 不要做

- 未授权公网扫 UpSnap
- 只报 CVE 编号不验证
- 改原超管密 / 覆盖生产配置（先问）。写马/反弹授权内直接做
- 命中后仍只跑广谱 nuclei 结案

## 衔接

- 得 shell → `linux-post-exploit` / `internal-tunnel`
- 同机 PocketBase 规则面 → `pocketbase-horizons-recovery`
- 情报入库 → `cve-daily-intel`
- 广谱 → `1day-nuclei-kit`
