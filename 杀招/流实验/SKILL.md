---
name: 流实验
description: >-
 授权目标上 MLflow Tracking Server webhook SSRF（CVE-2026-64849）：未认证
 /webhooks/{id}/test 跟随 302 可全回读内网/云元数据。
 默认指纹和未授权 list；协作 URL 可验；授权内直接做。
 CVE 入库走 cve-daily-intel。
---

# MLflow Webhook SSRF（CVE-2026-64849）

## 何时用

- 标题/体出现 MLflow，或路径 `/ajax-api/2.0/mlflow/` `/api/2.0/mlflow/`
- 用户点名 CVE-2026-64849 / Tracking Server webhook
- `nday_route` hit `mlflow`

## 真源

1. `传承/流实验·游方.md`
2. `tools/1day-kit/custom-templates/mlflow-ssrf-cve-2026-64849.yaml`
3. `传承/CVE日报-2026-08-22.md`
4. `od_kit.py cvebase lookup --cve CVE-2026-64849`

## 强制步骤

1. 目标在 `授权范围`。
2. 指纹 + 只读：
 ```bash
 python3 炼蛊房/nday_family_probe.py --family mlflow --base https://授权站 --case <案卷>
  ```
3. **L2**：未带票 `GET /api/2.0/mlflow/webhooks`（**不是** `/webhooks/list`，也不是 Databricks `registry-webhooks`）。要证明出网时只打**你控制的协作 HTTPS URL**。
4. **不要**默认 `/test` 打 `169.254.169.254` 或未授权内网。
5. 证据：`案卷/1day/` · STATUS 写版本与是否未鉴权。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | 标题/API 确认 MLflow |
| L2 | 未授权 `GET /api/2.0/mlflow/webhooks` **或** 协作 URL 被回读 |
| L3 | 授权内读到 scope 内网/元数据（授权内直接做） |

影响：`< 3.15.0`。修 `3.15.0+`。

## 不要做

- 未授权扫公网 5000 
- 默认打 IMDS / 扫未授权网段 
- 只报 CVE 号结案 

## 衔接

- 打到云凭据 → `cloud-metadata-harvesting`（仅授权） 
- 同机 LLM/作业面 → `ray-dashboard-unauth` / `langflow` 
- 入库 → `cve-daily-intel`
