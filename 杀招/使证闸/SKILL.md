---
name: 使证闸
description: >-
  大爱仙尊证据闸：口头结论对案卷原文、近成功不准结案、
  批量 HTTP 对照、highlight 源码还原。
  
  只读闸门不打点；对照/还原要对授权 URL。交差仍先 case-review。
---

# 证据闸与对照还原

工具原文才是证据。高信号没耗尽不准判死。本卡不替代专链，只闸结案、对照变体、还原着色页。

## 立刻跑

```bash
python3 炼蛊房/case_review.py --case 案卷/<案卷>
python3 炼蛊房/object_matrix.py check --case <案卷> --strict
python3 炼蛊房/evidence_gate.py --case <案卷> --from-status
python3 炼蛊房/case_ledger.py verify --report <案卷>

python3 炼蛊房/http_probe_batch.py --base https://授权站 --case <案卷> \
  --variant '{"label":"clean","path":"/","params":{"id":"1"}}' \
  --variant '{"label":"probe","path":"/","params":{"id":"1 OR 1=1"}}'

python3 炼蛊房/source_extract.py --url https://授权站 --case <案卷>
```

## 档位

| 信号 | 档 | 动作 |
|------|----|------|
| 对照有 DIFF / 抽出 sink | L1 | 记 JSON，交接专卡 |
| DIFF 被注入/越权/LFI 复现 | L2 | 专卡 findings + 本卡 JSON |
| 准备写结案 / 无路 | 闸 | leftover sink/表单/DIFF → 继续打 |
| 有身份 | 矩阵 | 先填 `案卷/object_matrix.md`，专卡阴性回表 |

## 近成功闸（强制）

证据里还有这些之一，不得写「无路 / 结案」：

- 源码 sink（`eval` / `unserialize` / `php://filter`）
- 表单 / 参数面未对照
- `http_probe_batch` 的 DIFF 未解释
- Actuator / JWT / 登录面未按专卡打完
- 对象矩阵仍有「未测」

## 失败

- 闸门 FAIL → 撤回口头结论或补真实输出
- 对照全 SAME → 换面或 `core_web_surface_probe`，不是注入阴性
- 还原无 sink → `sensitive-dir-dump` / `lfi-rfi-exploit`

## 真源

- 手法：`传承/使证闸.md`
- VulnClaw 已并入：`传承/伤门·融合.md`
- 工具：`python3 炼蛊房/evidence_gate.py --help`
- 对照：`python3 炼蛊房/http_probe_batch.py --help`
- 还原：`python3 炼蛊房/source_extract.py --help`
