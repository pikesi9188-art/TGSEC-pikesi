---
name: 文审
description: >-
 使用大爱仙尊内嵌的 DeepAudit（tools/deepaudit）做白盒代码审计：
 本地 SAST 流水线、知识摘要落案卷、Docker 全栈 Agent/沙箱启动。
 
 线上黑盒仍优先业务专用 Skill / Spring Gateway playbook。
---

# DeepAudit × 大爱仙尊

方法论（十维攻击面 / 假设驱动 / 未验证只标嫌疑）走 `secure-code-review`。本卡只跑流水线。

## 真源

| 内容 | 路径 |
|------|------|
| 工具目录（钉扎 v3.0.0） | `tools/deepaudit/` |
| Playbook | `传承/文审.md` |
| Docker 运行时 | `传承/瓮·运行.md` · `tools/docker/` |
| 入口脚本 | `tools/deepaudit/bin/da_pipeline.py` |
| 装工具 | `tools/deepaudit/bin/install_tools.sh` |
| 启全栈 | `tools/deepaudit/bin/da_start.sh` |

## 强制行为

1. **先确认授权**：远程目标须在 `授权范围`；本工具默认只扫**本地源码路径**。
2. **无 Docker 时**走 `da_pipeline.py sast`，不要假装 Agent 沙箱已跑通。
3. 产物写入 `案卷/<案卷>/案卷/deepaudit/`，并更新案卷 `STATUS.md` 一句进展。
4. 敏感代码优先提示用户用 **Ollama 本地模型**（`backend/.env` → `LLM_PROVIDER=ollama`）。
5. 不把 DeepAudit 沙箱 PoC 自动打到 scope 外域名。
6. **密钥命中回灌**：若出现 `案卷/deepaudit/PAYMENT_PLAYBOOK_HINT.md`（或 `pay-hint` 报 payment_related），**必须**下一步打开 `payment-callback-forgery` / `秦百胜·假契.md`，用 KEY 跑合法签；禁止只报 SAST 结案。

## 最短命令

```bash
python3 tools/deepaudit/bin/da_pipeline.py status
python3 tools/deepaudit/bin/da_pipeline.py knowledge --case <案卷>
python3 tools/deepaudit/bin/da_pipeline.py sast --source <本地源码> --case <案卷>
python3 tools/deepaudit/bin/da_pipeline.py pay-hint --case <案卷>
# 自动发现源码树：
python3 炼蛊房/deepaudit_auto.py --case <案卷> --scan-dir exports/recovery/...
# main.py 钩子：
python3 main.py backup-fetch -u https://站 --scope 授权范围 --case <案卷>
python3 main.py assess -u https://站 --source ./www --case <案卷> --deepaudit
python3 main.py recover --scope 授权范围 -u https://站 --case <案卷>
bash tools/deepaudit/bin/da_start.sh # 全栈需 Docker
```

## 与其它 Skill 的优先级

案卷定级 `case-triage` → 业务假支付 / PocketBase / BPP / Spring Gateway **>** DeepAudit 白盒 **>** 广谱 nuclei。 
DeepAudit 命中支付密钥时：**立即提升假支付优先级**。 
要 **CVE 申报级深挖 / Finding Agent** → 并行 `杀招/自掘新伤`（`tools/autocve`）。
