---
name: 流思
description: >-
 授权目标上 Flowise（LLM 低代码编排）内部头密钥泄露衔接到 NodeVM 面：
 CVE-2025-58434 变体（GET /api/v1/apikey + x-request-from: internal）与
 CVE-2026-46442（/api/v1/node-custom-function）。
 授权内全链（指纹→内部头密钥→NodeVM 逃逸→IMDS）。
 广谱 1day 仍走 1day-nuclei-kit；CVE 入库走 cve-daily-intel。
---

# Flowise 内部头 → 密钥 → NodeVM（Cursor Skill）

## 何时用

- 标题/体出现 Flowise，或路径 `/api/v1/apikey` `/api/v1/node-custom-function`
- 用户点名 CVE-2025-58434 / CVE-2026-46442 / `x-request-from: internal`
- `nday_route` hit `flowise`
- `llm_surface_probe` 认出 flowise

## 真源（按序）

1. `传承/流思·内额.md`
2. `炼蛊房/flowise_probe.py`
3. `tools/1day-kit/custom-templates/flowise-apikey-internal-header.yaml`
4. 学习样本：SAE-20260827-822f5b-A005-PUB
5. 同族 Langflow → `langflow-unauth-rce`

## 强制步骤

1. 目标在 `授权范围`。
2. L1 + L2：
 ```bash
 python3 炼蛊房/nday_route.py -u <URL> --case <案卷>
 python3 炼蛊房/flowise_probe.py detect -u <URL> --case <案卷>
 python3 tools/1day-kit/od_kit.py nuclei --url <URL> --case <案卷> \
   -t tools/1day-kit/custom-templates/flowise-apikey-internal-header.yaml
 ```
3. **L2**：无头 vs `x-request-from: internal` 打 `/api/v1/apikey`。阳性 = JSON 含 Key/Secret（值打码）。
4. 授权内直接 POST `node-custom-function` 沙箱逃逸 + `169.254.169.254` IMDS。
5. 证据：`案卷/1day/` · STATUS 写版本、内部头差分、是否 ≤3.1.2。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | 版本/首页确认 Flowise |
| L2 | 带内部头未认证读到 apikey（打码） |
| L3 | 授权内受控命令回显（直接做） |

影响：≤3.1.2。修 **> 3.1.2**。

## 不要做

- 未授权扫公网 Flowise
- 只报 CVE 号结案
- 公开桶只列不拖全量

## 衔接

- 得 shell → `linux-post-exploit` / `cloud-metadata-harvesting`（授权内直接做）
- 同机 Langflow → `langflow-unauth-rce`
- 广谱 LLM 面 → `llm_surface_probe` · `大灵.md`
- 入库 → `cve-daily-intel`
