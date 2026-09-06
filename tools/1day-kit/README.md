# 1day-kit — nuclei + exploitarium + cvebase

把「已知洞扫描」「本地 PoC 归档」「cvebase 情报」收成一条作业入口。  
**学习**：`传承/针匣·手册.md` · `od_kit.py learn` / `explain`  
官方模板默认落在本库 `tools/1day-kit/nuclei-templates/`（gitignore，本机升级）。  
`NUCLEI_TEMPLATES` 可覆盖。**不**把完整树硬塞进 `tools/vendor`。

```bash
python3 tools/1day-kit/od_kit.py doctor
python3 tools/1day-kit/od_kit.py learn
python3 tools/1day-kit/od_kit.py explain --id spring-actuator-unauth
python3 tools/1day-kit/od_kit.py update-templates   # 首次必跑
python3 tools/1day-kit/od_kit.py index
python3 tools/1day-kit/od_kit.py search --q redis

# cvebase.io（匿名约 10/日；可选 CVEBASE_API_KEY）
python3 tools/1day-kit/od_kit.py cvebase trending
python3 tools/1day-kit/od_kit.py cvebase lookup --cve CVE-2026-72898 --docs

python3 tools/1day-kit/od_kit.py nuclei --url https://授权站 --case <案卷> --custom-only
python3 tools/1day-kit/od_kit.py nuclei --url https://授权站 --case <案卷> --tags cve
```

| 路径 | 用途 |
|------|------|
| `od_kit.py` | doctor / **learn / explain / list-templates / validate / tags** / index / search / nuclei / **cvebase** |
| `custom-templates/` | 本库指纹（Metabase/TeamCity/N-central/NGINX-Rift…） |
| 手法卡 | `传承/新伤·在野.md` · `传承/房睇长·耳报.md` · `传承/CVE日报-*.md` · UpSnap / MRBS / Metabase / LoadMaster 等 |

本地研究 PoC：`poc-db/exploitarium/`  
证据：`案卷/<案卷>/测绘/1day/`
