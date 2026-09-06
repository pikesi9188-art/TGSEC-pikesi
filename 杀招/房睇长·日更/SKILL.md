---
name: 房睇长·日更
description: >-
 把「今天/本周新 CVE」完整落进大爱仙尊并产出可调用 Skill/专卡：写
 docs/intel/cve-daily JSON、CVE日报 Playbook、P0 手法卡、nuclei 指纹、
 nday_route 挂钩与 .cursor/skills。
 扫站复现走 1day-nuclei-kit；GeoServer/FreePBX/SharePoint/UpSnap/MRBS/WP插件ATO/GitLab GraphQL/MLflow/Zimbra/Ollama/PHP-CGI 4577 命中切对应专用 Skill。HITCON ZeroDay 走 hitcon-zeroday-intel。
---

> **房睇长**
> 智海观潮耳报先，一纸风闻动五域。
> 睇长不睇眼前利，先听劫云哪边偏。

# CVE 情报日报 → 可调用技能（Cursor Skill）

## 本仓探针

```bash
python3 炼蛊房/cve_daily_probe.py drive --case <案>
```

L2=CVE日报-YYYY-MM-DD.md 且抽出 CVE。证据进案卷 `测绘/`。

## 何时用

- 用户问「今天/本周有什么新 CVE」或「完善到大爱仙尊」
- `cvebase trending` / Tenable Newest / Patch Tuesday 后要入库
- 要把口头 CVE 汇总转成 **Skill + Playbook + 模板**，禁止只聊天结案

## 真源（按序）

1. `传承/房睇长·耳报.md`（落盘清单）
2. `docs/intel/cve-daily/README.md` · 当日 `YYYY-MM-DD.json`
3. `传承/CVE日报-YYYY-MM-DD.md`
4. `传承/新伤·在野.md` §3.x
5. 组件专卡 Skill（例：`upsnap-unauth-rce` · `mrbs-ssrf`）· 广谱 `1day-nuclei-kit`

## 强制步骤（完整 = 全做）

1. 拉情报（省配额优先 trending）：
 ```bash
 python3 tools/1day-kit/od_kit.py cvebase trending
 # 必要时：lookup --cve CVE-… --docs
 ```
2. 写 `docs/intel/cve-daily/YYYY-MM-DD.json`（字段见目录 README）。
3. 写 `传承/CVE日报-YYYY-MM-DD.md`（P0/P1 一眼表 + 命令）。
4. **网站向 P0/P1**：各写一张 `传承/<组件>手法.md` + 
 `tools/1day-kit/custom-templates/<组件>-*.yaml`（只指纹，无破坏 payload；`od_kit.py validate`）。
5. **转成能用的 Skill**：在 `杀招/<name>/SKILL.md` 写强制步骤与成功口径 
 （对照 `nginx-rift-cve-2026-42945` / `upsnap-unauth-rce` 模板）。
6. 挂钩：`炼蛊房/nday_route.py` ROUTES · `新伤·在野.md` · 
 `凤九歌·天地歌.md` · `春秋蝉·分案.md` · `scripts/build_clear_entry.sh` 后重建：
 ```bash
 bash scripts/build_clear_entry.sh
 ```
7. 更新 `1day-nuclei-kit` / `keyword-router` 词表一行（若新组件）。
8. 向用户回报：**Skill 路径 + 授权站一条复测命令**（勿只丢 CVE 列表）。

## 优先级口径

| 级 | 动作 |
|----|------|
| P0 | 专卡 Playbook + nuclei + **专用 Skill** + nday_route |
| P1 | 专卡或日报深节 + 指纹；常用则升 Skill |
| P2 / 设备 | 日报记一笔；网站案降权 |

业务专链（Actuator/假支付/GVA）永远优先于「新 CVE 编号」。

## 今日已落地示例（2026-08-30）

| 产物 | 路径 |
|------|------|
| JSON/日报 | `docs/intel/cve-daily/2026-08-30.json` · `CVE日报-2026-08-30.md` |
| ownCloud 预签名 | `杀招/私云` |
| 上次网站 CVE | `2026-08-28.json` · Gitea / WebLogic |

## 上次示例（2026-08-27）

| 产物 | 路径 |
|------|------|
| JSON/日报 | `docs/intel/cve-daily/2026-08-27.json` · `CVE日报-2026-08-27.md` |
| HITCON 分类 | `docs/intel/hitcon-zeroday/2026-08-27.json` · Skill `洞会` |
| Ollama Skill | `杀招/羊驼无门` |
| PHP-CGI 4577 | `杀招/幻页·门廊` |
| WP xmlrpc | `杀招/坞·旧令` |
| 客户端状态 | `杀招/客器` |
| 敏感目录 | `杀招/搜魂蛊` |
| 重置 token | `杀招/夺舍·票面` |
| 信任 IP 头 | `杀招/信头·踪` |
| 开放重定向 | `杀招/暗渡陈仓` |
| 上次 | `2026-08-23.json` · ICEcoder / JetEngine |

## 不要做

- 只口头汇总 CVE、不写 JSON/Skill
- 把第三方 UAT/无关域扩进 scope
- 设备洞（PAN/GP 等）抢网站案 ACTIVE 主线
- 在 nuclei 模板里塞破坏性 exploit

## 衔接

- Banner / 版本先分诊 → Skill `房睇长·分案` · `cve_triage.py`（命中仍是假设）
- 扫站复现 → `1day-nuclei-kit` + `nday_route.py`
- 挖新洞 → `autocve-cve-hunt` / `deepaudit-code-audit`
- 指纹后业务面 → 对应专用 Skill（支付/Actuator/GVA…）
