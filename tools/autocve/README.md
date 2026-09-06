# AutoCVE × 大爱仙尊

上游：[larlarua/AutoCVE](https://github.com/larlarua/AutoCVE)（AGPL-3.0）  
定位：**Agent 驱动的 CVE 挖掘**（筛项目 → 审源码 → 验洞 → 出 CVE 报告）。  
官方致谢 DeepAudit；本引擎已有 工作区 `tools/deepaudit`（开源不带），二者互补而非互斥。

| 路径 | 用途 |
|------|------|
| `bin/install_upstream.sh` | 浅克隆钉扎 `v1.0.5` → `upstream/` |
| `bin/ac_start.sh` | Docker 启动（`--prod` / `--cn` / `--stop`） |
| `bin/ac_pipeline.py` | status / knowledge / api-ping / sync / openapi |
| `knowledge/` | README / 架构 / 用户手册 / API 缓存（无 Docker 也可读） |

## 与 DeepAudit 怎么选

| | DeepAudit | AutoCVE |
|--|-----------|---------|
| 路径 | 工作区 `tools/deepaudit`（开源不带） | `tools/autocve` |
| 强项 | 本地 SAST、通用 Agent、pay-hint | Finding Agent、CVE 报告、一键 CVE |
| 无 Docker | `da_pipeline.py sast` | 仅 `knowledge` / 读文档 |
| 有 Docker | `da_start.sh` | `ac_start.sh` |

建议：粗扫 DeepAudit → 深挖 AutoCVE 智能审计 → 命中支付密钥仍回灌假支付 Playbook。

## 命令

```bash
# 知识落案卷（无需 Docker）
python3 tools/autocve/bin/ac_pipeline.py knowledge --case <案卷>

# 装上游 + 启动（需 Docker）
bash tools/autocve/bin/install_upstream.sh
bash tools/autocve/bin/ac_start.sh
# 或一行预构建：
bash tools/autocve/bin/ac_start.sh --prod

# UI http://localhost:3000  · API http://localhost:8000/docs
# 配置模型 → 导入授权源码 → 创建审计任务

# 同步漏洞到案卷
python3 tools/autocve/bin/ac_pipeline.py sync --case <案卷> \
  --user <email> --password '<pass>'
```

产物：`案卷/<案卷>/测绘/autocve/`

Playbook：`传承/自掘新伤.md`  
Skill：`杀招/自掘新伤/SKILL.md`
