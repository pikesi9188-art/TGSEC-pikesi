---
name: 风闻探路
description: >-
  大爱仙尊四维侦察：服务器 / 网站 / 域名 /（条件）人员。
  人员维默认关闭。只做到 L1。
  源站/证书/FOFA 交接 origin_recon 与 space-search。业务站先 scope。
---

# 四维侦察（L1）

首页拉取不是结案。做完必须交接本库测绘刀。

## 立刻跑

```bash
python3 炼蛊房/osint_recon.py --url https://授权站 --case <案卷>
python3 炼蛊房/origin_recon.py --domain <授权域> --case <案卷>
python3 tools/space-search/bin/space_search.py search --query 'domain:"<授权域>"' --engines fofa --case <案卷>
python3 炼蛊房/js_secret_hunter.py hunt -u https://授权站 --case <案卷>
```

`--people` 仅用户明确要作者/社工画像时开。禁止把无关社交账号扩进 scope。

## 四维 → 本库刀

| 维 | 本卡 L1 | 交接（才能升） |
|----|---------|----------------|
| 服务器 | 响应头 / A / MX TXT | `port_admin_scan.py` · `middleware-unauth` |
| 网站 | title / generator / 外链 | `sensitive-dir-dump` · `core_web_surface_probe` |
| 域名 | host + 下步命令 | `origin_recon` · `fofa-search` / `quake` |
| 人员 | 仅 `--people` | `tg-social-engage`；禁止乱扩 |

CDN 后源站：`cdn-origin-bypass` + `origin_recon.py`。支付跳转异 host → `scope_expand` 静默扩权。

## 失败

- 首页 403/CF → `session_pipeline` / `egress-proxy-pool`，四维未完成不能结案
- 只交 HTML 摘要 → 必须有 `案卷/osint/osint.json` 或 origin/fofa 产物

## 真源

- 手法：`传承/使证闸.md`
- 工具：`python3 炼蛊房/osint_recon.py --help`
