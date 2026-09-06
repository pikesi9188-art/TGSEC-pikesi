---
name: 春晓苦力
description: >-
  侦察后黑盒突击层 S1–S8。用户或现场出现：黑盒突击、strike_probe、S1攻击面、
  S2 Auth、S1–S8、管理后台/总后台短字典、admin12345、侦察后突击、
  无专用栈先打一遍 时立刻使用。单向量单请求、低噪音。
  只调已有探针深挖，不另起利用。
  有 TP3/XXL/假支付/Actuator 专卡仍先专卡。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# 黑盒突击层（Cursor Skill）

真源：`传承/春晓苦力·突击.md`

## 立刻跑

```bash
python3 炼蛊房/strike_probe.py doctor
python3 炼蛊房/strike_probe.py -u https://授权站 --case <案>
```

侦察（指纹 / `dirbrute` / JS hunt）之后、专卡之前。  
`kit_run web|php` 与 `auto_campaign` 无专用栈时默认带本层。

## 强制

1. 目标在 scope。
2. 先跑本探针，按 `案卷/strike/surface.json` 交接，禁止只贴 payload 百科结案。
3. `--deep` 只调用 `dirbrute` / `auth_brute` / `core_web --fast` / `ssrf scan`；首页命中 Next/ASP.NET/gRPC/VPN 指纹时再拉对应猎面探针。
4. S8 只做 `{{1337*7}}` 算术（看 9359，不要用 49）。RCE gadget / WebShell 授权内直接做。
5. 有身份 → 回对象矩阵。专卡阴性回表，不直接复工。
