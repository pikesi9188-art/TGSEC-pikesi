---
name: 微域
description: >-
  微信小程序静态审计：wxapkg/unveilr、wx.request、AppSecret、云函数、BaseURL。
  触发：微信小程序/wxapkg/unveilr/wx.request/__APPID__/wxml。
  默认跑 run（扫+分析+报告），没有 security_report.md 不许结案。
  不是 TG Mini App（芋道 TMA），不是网页 JS。
---

# wxmini-static-audit — 微信小程序静态审计

目标须在 `授权范围`。抽出的业务域未授权先 `--grant`。

本库一条命令走完全阶段，不需另开子对话。

## 立刻执行（禁止只口头分析）

```bash
python3 炼蛊房/wxmini_static_probe.py doctor
python3 炼蛊房/wxmini_static_probe.py run \
  --dir <反编译目录或.wxapkg> --case <案卷>
# 用户说了「重点看支付 / amount」：
#   ... run --dir ... --case <案卷> --focus "支付 amount"
```

**结案门禁**：案卷 `案卷/wxmini/` 必须有 `security_report.md`、`secrets_full.md`、`api_endpoints_full.md`、`findings.json`。缺一份就继续 `run`，不许用聊天叙述代替。

`--probe-urls` 只打 in_scope host 的 GET，授权域直接打。禁止把 JSON 写回源码目录。

## 阶段映射

| 阶段 | 本库 |
|------------|------|
| 编排器 Phase 0 | `--focus` → `custom_requests.json` |
| 01 反编译 | `scan`：inventory；PATH 有 unveilr 才解 wxapkg；否则本机 `wxapp-unpacker`：`node wuWxapkg.js <包.wxapkg>` 再 `--dir` |
| 1.5 脚本 | `scan`：`raw_secrets.json` / `raw_endpoints.json` |
| 02 密钥 | `analyze` → `secrets_report.json`（丢占位符、按级别排） |
| 03 接口 | `analyze` → `api_endpoints.json`（拼 BaseURL、打 scope） |
| 04 加解密 | `analyze` → `crypto_analysis.json` |
| 05 漏洞 | `analyze` → `vuln_analysis.json`（七维正则 + 隐藏页） |
| 07 定制 | 有 `--focus` 才写 `custom_analysis.json` |
| 06 报告 | `report` → `security_report.md` + 两份全量 md |

拆开重跑：`scan` → `analyze` → `report`。默认只记 `run`。

## 真源

- 手法：`传承/微域·静审.md`
- 专题分流：`传承/逆骨·分科.md`

## 分流

| 说法 | 走 |
|------|----|
| 芋道 / Qzino / `sk_encrypt` / TG 小程序 | `yudao_appapi_probe` / 白标卡 |
| 只有 H5 | `js-reverse` |
| Critical 支付钥 | 假支付 Playbook |
| `<web-view src={{` | `webview-deeplink-bridge` |
| 只有 `.wxapkg` 且无 unveilr | 本机 `wxapp-unpacker`（`wuWxapkg.js`）解包，**不要**把 unpacker 整仓 sync 进本库 |
