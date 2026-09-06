---
name: 一日针匣
description: >-
 授权目标上的 1day/已知洞作业：nuclei 模板扫描 + poc-db/exploitarium 索引检索 +
 cvebase.io（KEV/EPSS/利用情报）。
 挖新洞走 autocve；「今天新 CVE」入库走 cve-daily-intel；
 UpSnap/MRBS/GeoServer/FreePBX/GitLab GraphQL/Gitea diffpatch CVE-2026-60004/ownCloud WebDAV CVE-2023-49105/MLflow webhook/Zimbra/ICEcoder/JetEngine/Ollama/Langflow/Flowise/PHP-CGI 4577/xmlrpc/Oracle WebLogic Proxy CVE-2026-21962 命中切对应专用 Skill。HITCON ZeroDay 走 hitcon-zeroday-intel。
 芋道 /admin-api mock-enable 命中切 yudao-daifu-mock-file-rce。
 业务专用链（支付/Actuator/GVA）仍优先对应 Skill。
---

> **房睇长**
> 智海观潮耳报先，一纸风闻动五域。
> 睇长不睇眼前利，先听劫云哪边偏。

# 1day / Nuclei 作业（Cursor Skill）

## 何时用

- 指纹明确、要快速过已知 CVE/misconfig
- 需要查本地 `exploitarium` 研究型 PoC 是否相关
- 跟 [cvebase.io](https://cvebase.io/) 近期 KEV / 在野洞补手法
- Tsecbench / 靶场「漏洞利用」类题的默认入口之一

## 真源（按序）

1. `tools/1day-kit/od_kit.py`（`learn` / `explain` / `nuclei`）
2. **`传承/针匣·手册.md`**（官方 v3 YAML + 本库三层；先学这个）
3. `传承/一日针匣.md`（短作业清单）
4. `传承/新伤·在野.md` · **`房睇长·耳报.md`** · 当日 `CVE日报-YYYY-MM-DD.md` · `docs/intel/cve-daily/*.json`
5. `传承/凤九歌·天地歌.md` · 同目录各栈手法卡（Metabase/UpSnap/MRBS/Grafana/Jenkins/XXL-JOB 等）
6. `poc-db/exploitarium/`（研究 PoC，非自动扫）
7. 广谱发现可并行 `pentest-swarm`；出洞后交专用 Skill

## 强制步骤

1. 目标在 scope（情报查询可无目标；扫站必须有）。
2. `python3 tools/1day-kit/od_kit.py doctor`（缺二进制：`bash scripts/install-arsenal-macos.sh`）
3. 要学引擎/YAML：`od_kit.py learn` · `explain --id <模板>` · 手册 `针匣·手册.md`
4. 模板空：`od_kit.py update-templates`（写入 `tools/1day-kit/nuclei-templates/`）
5. 情报（可选）：`od_kit.py cvebase trending` / `lookup --cve CVE-… --docs`
6. 扫：先 `nday_route.py`，再  
 `od_kit.py nuclei --url <URL> --case <案卷> --custom-only`  
 或 `-t tools/1day-kit/custom-templates/<id>.yaml`（与手法卡同一写法）。  
 然后才 `--tags cve,rce`。hits 里的专卡优先于广谱 nuclei。
7. 本地 PoC：`od_kit.py search --q <组件>` → `show --id <目录名>`
8. 证据：`案卷/<案卷>/案卷/1day/`

## cvebase 快捷

```bash
export CVEBASE_API_KEY="cvb_..." # 可选；否则匿名约 10/日
python3 tools/1day-kit/od_kit.py cvebase trending
python3 tools/1day-kit/od_kit.py cvebase lookup --cve CVE-2026-72898 --docs
```

业务站栈（Metabase/UpSnap/MRBS/Grafana/Jenkins/XXL-JOB/Jeecg/Shiro/Druid/ThinkPHP/宝塔PMA/用友致远/WP/Laravel…）：见 `凤九歌·天地歌.md` + 对应手法卡 + `custom-templates/` 
「今天新 CVE」完整落盘：切 Skill **`cve-daily-intel`**（JSON+日报+P0 专卡+Skill），禁止只口头汇总。 
UpSnap → `upsnap-unauth-rce`；MRBS → `mrbs-ssrf`；GeoServer → `geoserver-jsonarraycontains-sqli`；FreePBX → `freepbx-unauth-rce`；WP 插件 8/15 窗 ATO/假付 → `wordpress-plugin-unauth-takeover`；Ray Dashboard → `ray-dashboard-unauth`；GitLab GraphQL → `gitlab-graphql-unauth`；**Gitea / diffpatch / CVE-2026-60004** → `gitea-diffpatch-rce`；MLflow webhook → `mlflow-ssrf-webhook`；Zimbra SNMP → `zimbra-snmp-rce`；ICEcoder → `icecoder-unauth-rce`；JetEngine → `jetengine-unauth-rce`；Ollama → `ollama-unauth`；Langflow → `langflow-unauth-rce`；Flowise → `flowise-internal-header-rce`；CVE-2024-4577 → `php-cgi-cve-2024-4577`；xmlrpc.php → `wordpress-xmlrpc-surface`；信任头 → `trusted-ip-header`；开放重定向 → `open-redirect-chain`；**Oracle WebLogic Proxy / CVE-2026-21962** → 指纹模板 `weblogic-proxy-cve-2026-21962.yaml`。HITCON 学洞 → `hitcon-zeroday-intel`。 
Java 面一条分流：`python3 炼蛊房/java_web_surface_probe.py -u <授权站> --case <案卷>` 
设备/边缘（LoadMaster/Tomcat集群/VeloCloud/PAN…）：情报可留，网站案默认降权

## 不要做

- 未授权扫网段 / 未授权 dump
- 把完整 nuclei-templates 硬 clone 进 `tools/vendor`
- 命中业务指纹后仍只跑 nuclei 结案（Actuator/支付等要切专用链）
- 把 cvebase 匿名配额浪费在无目的广搜上
