---
name: 话巢
description: >-
 授权目标上 FreePBX 未授权面：CVE-2026-73665 UCP Socket.IO namespace
 绕过衔 AMI RCE；CVE-2026-73663 missedcall SIP From SQLi 改超管。
 
 广谱 1day 走 1day-nuclei-kit；CVE 入库走 cve-daily-intel。
---

> **气绝**
> 登山寻仙处，寸步间高险。
> 五域九天功，尽在一气中。

# FreePBX 未授权 RCE / 超管（Cursor Skill）

## 何时用

- 页面标题/路径出现 FreePBX、`/admin/config.php`、UCP
- 用户点名 CVE-2026-73665 / 73663、`:8001`/`:8003`、socket.io
- `nday_route` hit `freepbx`
- 授权站疑似 Asterisk/PBX 管理面

## 真源（按序）

1. `传承/话巢·开天.md`
2. `tools/1day-kit/custom-templates/freepbx-unauth-cve-2026-73665.yaml`
3. `传承/CVE日报-2026-08-14.md` §2
4. https://github.com/FreePBX/security-reporting/security/advisories/GHSA-37j8-fhxx-9vhp
5. `python3 tools/1day-kit/od_kit.py cvebase lookup --cve CVE-2026-73665 --docs`

## 强制步骤

1. 目标在 scope。
2. 指纹（含 8001/8003，勿只扫 443）：
 ```bash
 python3 炼蛊房/nday_family_probe.py --family freepbx --base https://授权站 --case <案卷>
  ```
3. **L2（授权内）**：按 Playbook §2 
 - 73665：未认证连 UCP **自定义 namespace**，握手/sid 即证 
 - AMI 注入 / 命令执行：授权内直接做（回显后写马/反弹） 
 - 73663：无 SIP 授权通道则只记版本，勿对公网乱呼 
4. 证据：`案卷/<案卷>/案卷/1day/freepbx_*` + STATUS。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 确认 FreePBX / UCP 口暴露 |
| L2 | 未认证 namespace 可连 **或** 可验证 missedcall 注入面 |
| 修复线 | ucp ≥ 17.0.9；missedcall ≥ 16.0.11 / 17.0.4；封 8001/8003 |

## 不要做

- 未授权扫 PBX 网段
- 改生产超管密（先问）。写马/反弹授权内直接做
- 只扫 CVE 编号结案
- 对无关号码发 SIP 轰炸测 73663

## 衔接

- 得 asterisk 用户壳 → `linux-post-exploit` / `internal-tunnel`
- 情报入库 → `cve-daily-intel`
- 广谱 → `1day-nuclei-kit`
