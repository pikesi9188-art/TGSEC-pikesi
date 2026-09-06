---
name: 光台无门
description: >-
 Ray 仪表盘未授权作业面：CVE-2025-62593（UA 伪防护 + DNS rebinding）及公网
 :8265 /api/jobs 无鉴权。
 授权内全链（指纹→列作业→提交 job RCE）。CVE 入库走 cve-daily-intel。
---

# Ray 仪表盘未授权作业（CVE-2025-62593）

## 何时用

- 标题/体出现 Ray Dashboard，或端口 8265
- 用户点名 CVE-2025-62593 / ShadowRay / `/api/jobs`
- `nday_route` hit `ray`

## 真源

1. `传承/光台·无门.md`
2. `tools/1day-kit/custom-templates/ray-dashboard-unauth-cve-2025-62593.yaml`
3. `传承/CVE日报-2026-08-17.md`
4. `od_kit.py cvebase lookup --cve CVE-2025-62593`

## 强制步骤

1. 目标在 `授权范围`。
2. 指纹 + 只读：

```bash
python3 炼蛊房/nday_family_probe.py --family ray --base https://授权站 --case <案卷>
```
3. **L2**：用非 Mozilla UA `GET /api/jobs`，对照 Mozilla UA。只记录是否未鉴权。 
4. **L3** 授权内直接提交 job 验证 RCE。 
5. 证据：`案卷/1day/` · STATUS 写版本与 L1/L2 结论。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | `/api/version` 出 `ray_version` 或标题 Ray Dashboard |
| L2 | 未授权列出 `/api/jobs` |
| L3 | 授权内可验证作业执行（直接做） |

影响：`< 2.52.0`。修 `2.52.0+`。

## 不要做

- 未授权扫公网 8265 
- 耗余额/删站/改原超管密码先问 
- 只报 CVE 号结案 

## 衔接

- 得进程 → `linux-post-exploit` / `internal-tunnel` 
- 同机 LLM 编排面 → `langflow` / `llm_surface_probe` 
- 入库 → `cve-daily-intel`
