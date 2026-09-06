---
name: 潮面探
description: >-
  授权可用性面。触发：ddos、SYN 洪水、反射放大、NTP/SSDP amplifier、压测。
  只做反射器指纹 + 限速小流量（n≤30、rps≤5）。禁止写 SYN/DNS 放大发送器。
---

# 授权可用性面（大爱仙尊）

目标须在 scope。本卡是 **指纹 + 限速自检**，不是洪水工具。  
授权内默认打到 **L2**：授权 IP 上 53/123/19 有 UDP 回包。  
先问只剩：对第三方放大、超过硬顶的压测。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `load` 在硬顶内打完，记下状态码 | 没限速的循环 curl |
| L2 | `amp` 探到开放 UDP 口 | 把回包当「可以打别人」 |
| L3 | 本卡不设 | SYN 发送器 / DNS 放大 |

硬顶写死在探针：`MAX_N=30`、`MAX_RPS=5`。命令行再大也会被裁。

## 立刻跑

```bash
python3 炼蛊房/ddos_surface_probe.py amp --host <授权IP> --case <案>
python3 炼蛊房/ddos_surface_probe.py load --url https://授权站/ --n 10 --rps 2 --case <案>
```

`amp` 各发 **一包**：

- UDP/53 最小查询
- UDP/123 NTP
- UDP/19 chargen

`load`：`GET` 授权 URL，间隔 `1/rps`。

产物：`案卷/ddos/amp.json`、`load.json`。

## 六步

```text
① 确认 IP/URL 在 scope
② amp 看哪些口回包
③ 回包只记「像反射器」，不要拿去打旁站
④ load 用 n=8 rps=2 看 5xx / 429
⑤ 被封换出口走 config/proxy-nodes.txt
⑥ 结案写码分布，不写洪水包
```

## 交接

| 认到 | 走 |
|------|----|
| 本机 IP 被封 | `狼烟.md` |
| WAF 拦小流量 | `evasion-kit` / `waf-detector` |
| 多机 C2 | `authorized-botnet-lab`（禁止把本卡当攻击模块） |

## 真源

- 手法：`传承/授权恶族.md`
- 探针：`炼蛊房/ddos_surface_probe.py`
