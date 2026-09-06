---
name: 信巢
description: >-
 授权目标上 Zimbra Collaboration SNMP 通知命令注入（CVE-2026-73570）：可选
 zimbra-snmp + snmp_notify + swatchdog 时，未认证 SMTP 可以 zimbra 用户执行命令。
 
 授权内全链（指纹→版本→SMTP 注入 RCE）。CVE 入库走 cve-daily-intel。
---

> **气绝**
> 登山寻仙处，寸步间高险。
> 五域九天功，尽在一气中。

# Zimbra SNMP 命令注入（CVE-2026-73570）

## 何时用

- 标题/体出现 Zimbra / ZimbraWebClient，或路径 `/zimbra/` `/zimbraadmin/`
- 用户点名 CVE-2026-73570 / zimbra-snmp
- `nday_route` hit `zimbra`

## 真源

1. `传承/信巢·闻管.md`
2. `tools/1day-kit/custom-templates/zimbra-snmp-cve-2026-73570.yaml`
3. `传承/CVE日报-2026-08-22.md`
4. `od_kit.py cvebase lookup --cve CVE-2026-73570`

## 强制步骤

1. 目标在 `授权范围`。
2. 指纹：
 ```bash
 python3 炼蛊房/nday_family_probe.py --family zimbra --base https://授权站 --case <案卷>
  ```
3. **L2**：抠版本（`ZmSettings.js` 的 `clientVersion` / `zimbraVersion`）。**不要把 `cacheVersion` 当 ZCS 版本。** `< 10.1.20` 记可疑；HTTP 看不到 snmp/swatchdog，勿写成已 RCE。
4. **L3** 授权内直接做 SMTP 注入验证 RCE。
5. 证据：`案卷/1day/` · STATUS 写版本与 SNMP 条件是否未知。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | `/zimbra` 或 ZimbraWebClient 确认 |
| L2 | 版本 `< 10.1.20`（条件满足才可能打） |
| L3 | 授权内可验证命令执行（直接做） |

影响：`< 10.1.20` 且 zimbra-snmp + snmp_notify + swatchdog。修 `10.1.20+`。

## 不要做

- 未授权扫公网邮件网关 
- 耗余额/删站/改原超管密码先问 
- 只报 CVE 号结案 

## 衔接

- 得 zimbra 用户进程 → `linux-post-exploit`（读配置/提权直接做；清数据/改超管先问） 
- 入库 → `cve-daily-intel`
