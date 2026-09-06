---
name: 自掘新伤
description: >-
 使用大爱仙尊封装的 AutoCVE（tools/autocve）做 Agent 驱动 CVE 挖掘：
 多 Agent 审计、Finding、验证、CVE 报告同步到案卷。
 
 线上黑盒仍优先业务专用 Skill；通用白盒可并行 DeepAudit。
---

# AutoCVE × 大爱仙尊

## 真源

| 内容 | 路径 |
|------|------|
| 封装 | `tools/autocve/` |
| 上游（钉扎 v1.0.5） | `tools/autocve/upstream/`（`install_upstream.sh`） |
| Playbook | `传承/自掘新伤.md` |
| 知识缓存 | `tools/autocve/knowledge/` |
| DeepAudit（互补） | `tools/deepaudit/` + `deepaudit-code-audit` |

## 强制行为

1. **只审授权源码/环境**；未进 `scope` 的远程目标禁止用 AutoCVE 当扫站器。 
2. 无 Docker → `ac_pipeline.py knowledge`，不要假装 Agent 已跑通。 
3. 产物进 `案卷/<案卷>/案卷/autocve/`，更新 STATUS 一句。 
4. 密钥/支付相关命中 → 回灌 `payment-callback-forgery`。 
5. 业务专用链（假支付/共享货/Spring…）**优先于** AutoCVE 广谱挖洞。

## 最短命令

```bash
python3 tools/autocve/bin/ac_pipeline.py status
python3 tools/autocve/bin/ac_pipeline.py knowledge --case <案卷>
bash tools/autocve/bin/install_upstream.sh
bash tools/autocve/bin/ac_start.sh # 或 --prod
# UI: http://localhost:3000
python3 tools/autocve/bin/ac_pipeline.py sync --case <案卷> \
 --user <email> --password '<pass>'
```

## 与 DeepAudit

- 粗扫 / 无 Agent：`da_pipeline.py sast` 
- CVE 深挖 / 报告：`ac_start` + Finding / 综合审计 
- 二者可同案卷并行落 `案卷/deepaudit/` 与 `案卷/autocve/`
