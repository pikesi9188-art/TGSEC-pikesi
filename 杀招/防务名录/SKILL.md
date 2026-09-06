---
name: 防务名录
description: >-
 大爱仙尊 39 模块网络安全分类目录。
 
 假支付/盘口/TG 仍走 00 业务专卡，不要用百科替代专链。
---

# 39 模块分类目录（Cursor Skill）

## 本仓探针

```bash
python3 炼蛊房/pack_surface_probe.py drive --name ot-ics --case <案>
```

L2=名录能落到本仓卡。证据进案卷 `测绘/`。

## 真源

1. `智道藏书/三十九门/README.md`
2. `智道藏书/三十九门/CATALOG.md`
3. `智道藏书/三十九门/00-大爱仙尊业务-大爱仙尊/MODULE.md`
4. `python3 炼蛊房/css_query.py`

## 强制

```bash
python3 炼蛊房/css_query.py list-modules
python3 炼蛊房/css_query.py search --keyword <词>
python3 炼蛊房/css_query.py get --id 05-002
python3 炼蛊房/css_query.py doctor
```

全文在 `<模块>/skills/*.md`，不要用模块根路径。

命中模块后打开该目录 `MODULE.md`，**先跑本库入口命令**，再读上游 `.md`。

| 用户说法 | 模块 |
|----------|------|
| 子域 / FOFA / 指纹 | 01 |
| nuclei / 扫描 | 02 |
| SQLi / XSS / SSRF / 利用 | 03（业务洞仍走假支付等专卡） |
| 提权 | 04 |
| 隧道 / 横向 / 域 | 06 |
| APK / iOS / Mach-O | 10 + `ios-pentest` + `macos-reverse` |
| 逆向 / Ghidra / Go剥离 / 扩展 / 厚客户端 | 13 + `reverse-engineering` · `reverse_routing.json` · `reverse_skill_route.py` |
| 白盒 / DeepAudit | 12 |
| LLM | 16 |
| 云 / AK | 17 |
| 工控 / SCADA | 19 + `ot-ics` |
| 社工 | 23 + `tg-account-library` |
| CVE / 漏洞管理 | 26 |
| 容器 / K8s | 33 |
| API / GraphQL | 34 |
| 假支付 / 芋道 / 号库 | **00** |
| WP 马 / shell 目录 / 高熵 php | **00** + 15 `host-ir` + `wp-shell-drop-hunt` |
| C2 / Metasploit / 远程控制 | 03-008 · 05-003 |
| 凭证转储 / PtH / Mimikatz | 05-002 · 04-004 |
| 键盘记录 / 截屏 | 05-004 |
| AMSI / EDR / 进程注入 | 08 |

这些主题全文已在对应 `skills/` 卡。打开知识卡即可。

手法：`三十九门·检索.md` · `幻道辨真.md` · `沈伤·索引.md`。  
**不要**把外部整库灌进 `杀招/`。免杀/马/C2 仍只开模块 08 原理卡。  
缺口专卡：`nextjs-ssr-hunt` / `aspnet-viewstate-hunt` / `grpc-reflection-hunt` / `sslvpn-perimeter-fingerprint`。
