---
name: 羊驼无门
description: >-
  授权目标上 Ollama HTTP API 未授权：/api/version、/api/tags 列模型。
  HITCON ZD-2026-00572 同类。默认只 GET。广谱 1day 走 1day-nuclei-kit。
---

# Ollama 未授权 API

**前提**：目标在 `授权范围`。默认 **只 GET**。禁止 pull/push/真对话。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `/api/version` JSON `version`，或标题 Ollama | 空 200 / 只开了端口 |
| L2 | 未授权 `GET /api/tags` 列出 `models` | 空数组当已接管 |
| L3 | 路径穿越写文件（CVE-2024-37032 / 7020） | 先问；探针不默认做 |

```bash
python3 炼蛊房/ollama_unauth_probe.py --base https://授权站 --case <案卷>
# 假模型探 generate 鉴权（仍不 pull）
python3 炼蛊房/ollama_unauth_probe.py --base https://授权站 --case <案卷> --deep
```

## 四刀

1. **口** — `:11434`，反代常在 `/` 或 `/ollama/`  
2. **GET** — `/api/version` → `/api/tags` → `/api/ps`  
3. **鉴权** — `--deep` 对不存在模型 POST `/api/generate`：400/404 且无 401 = 写面裸奔  
4. **停** — 列到模型就交差；不要 `pull` 占磁盘，不要对真实模型 `generate`

真源：`传承/羊驼·无门.md`
