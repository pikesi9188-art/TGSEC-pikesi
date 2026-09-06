---
name: 窗府·无门
description: >-
 授权目标上 on-prem SharePoint 未授权面：CVE-2026-50522 反序列化 RCE；
 同窗 CVE-2026-55040 JWT 绕过 + CVE-2026-63520 BCS RCE。
 
 广谱 1day 走 1day-nuclei-kit；CVE 入库走 cve-daily-intel。
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# SharePoint 未授权反序列化 RCE（Cursor Skill）

## 何时用

- 头/页出现 `MicrosoftSharePointTeamServices`、`SPRequestGuid`、`_layouts`
- 用户点名 CVE-2026-50522 / 55040 / 63520、machine key、on-prem SharePoint
- `nday_route` hit `sharepoint`
- 授权站疑似 IIS + SharePoint 文档库

## 真源（按序）

1. `传承/窗府·化形.md`
2. `tools/1day-kit/custom-templates/sharepoint-rce-cve-2026-50522.yaml`
3. `传承/CVE日报-2026-08-14.md` §3
4. `python3 tools/1day-kit/od_kit.py cvebase lookup --cve CVE-2026-50522 --docs`

## 强制步骤

1. 目标在 scope。SharePoint Online 不受本卡影响。
2. 指纹：
 ```bash
 python3 炼蛊房/nday_family_probe.py --family sharepoint --base https://授权站 --case <案卷>
  ```
3. **L2（授权内）**：版号 / 补丁级 / `_layouts` 可达。未打 2026-07 相关更新再升。
4. **L3 完整反序列化 / 抽 machine key：授权内直接做。**
5. 证据：`案卷/<案卷>/案卷/1day/sharepoint_*` + STATUS。
 疑似失陷须写「已轮换 machine key」，勿只打补丁结案。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 确认 on-prem SharePoint（头或 `_layouts`） |
| L2 | 版号/补丁级可判断未修 |
| L3 | RCE 回显 **或** machine key 外泄（授权内直接做） |
| 修复线 | 对应 2016/2019/SE 安全更新 + 轮换 machine key |

## 不要做

- 未授权扫公网 SharePoint
- 未授权扫公网发完整反序列化 gadget / 抽密钥
- 把 SharePoint Online 和 on-prem 混成功口径
- 只报 CVE 编号结案

## 衔接

- 得机 / 密钥 → `linux-post-exploit` 不适用时按 Windows/IIS 面打
- 情报入库 → `cve-daily-intel`
- 广谱 → `1day-nuclei-kit`
