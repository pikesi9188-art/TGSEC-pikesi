---
name: 残网·猎面
description: >-
  ASP.NET WebForms 猎面：ViewState 只签不加密、trace.axd/elmah.axd 匿名、
  Telerik RAU 指纹、双解析器误差。触发：__VIEWSTATE、X-AspNet-Version、.aspx、
  elmah.axd、Telerik.Web.UI.WebResource、.ASPXAUTH。
  SharePoint _layouts 先走 sharepoint-unauth-rce。gadget / machineKey 授权内直接做。
---

# ASP.NET ViewState 猎面（Cursor Skill）

## 何时用

- `__VIEWSTATE` / `X-AspNet-Version` / `.aspx` / IIS + WebForms
- `elmah.axd` `trace.axd` `Telerik.Web.UI.WebResource.axd`

`_layouts` / SharePoint 头 → `sharepoint-unauth-rce`。

## 真源

1. `传承/残网·猎面.md`
2. `python3 炼蛊房/aspnet_surface_probe.py --base https://授权站 --case <案卷>`
3. 双解析器：同上加 `--parser-diff`

## 强制步骤

1. 目标在 scope。
2. 跑探针。SharePoint 信号立刻交接专卡。
3. L2：空 `__VIEWSTATEENCRYPTED`、匿名 ELMAH/trace、Telerik RAU、解析器文案分流。
4. 授权内直接发 gadget / 抽 machineKey。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | ASP.NET / ViewState |
| L2 | 只签不加密或匿名日志面或 Telerik 活 |
| L3 | gadget（授权内直接做） |

## 不要做

- 把 SharePoint 当本卡结案
- 超大 ViewState POST 打垮站点
