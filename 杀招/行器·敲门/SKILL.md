---
name: 行器·敲门
description: >-
  打授权目标上的 C2 零信任控制台：nftables 黑洞、两步 API 敲门、CF 仅回源、
  时间窗 HMAC / SPAKE2、Vue Console / PTY 8889 / WebRTC H.264、内存沙箱。
  触发：C2 控制台、零信任敲门、端口敲门、黑洞模式、nftables DROP、SPAKE2、
  HMAC 控制台、Vue C2、PTY 8889、内存沙箱控制台。
  不是 host-c2-verify（那是授权机上验我们自己的 Sliver 落地）。
  支付假付、彩虹易 return_url 不并进本卡。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# C2 零信任控制台（大爱仙尊）

目标须在 `授权范围`。这是 **打别人家（已授权）C2 设施**，不是本机 implant 回连。  
授权内默认打到 **L2**：控制台 / 终端 / 库 三选一可验证。  
先问只剩：改原超管密、持久化清日志、耗余额。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | CF 前置 + 重点口黑洞/假 OPEN；JS 里有 knock/HMAC/wss/ICE 词 | 只扫 health；只写「主机不在线」 |
| L2 | JS 抽出敲门序列或 HMAC 钥，**或** 源站 Host/XFF 出控制台，**或** 未授权 JSON（keys/db/pty） | 65535 空转；TCP 全通但 HTTP 同码当真开 |
| L3 | 授权内进 Console / PTY / 库查询，证据打码 | 默认改超管密；把彩虹易 F-01 当本链洞 |

## 立刻跑

```bash
# 认面：CF / JS 敲门 / HMAC / 控制台路径；不默认喷 65535
python3 炼蛊房/c2_zt_probe.py drive --base https://授权站 --case <案>

# 已有候选源站 IP（先 origin_recon / cert-origin，IP 须进 scope）
python3 炼蛊房/c2_zt_probe.py drive --base https://授权站 --origin-ip <源IP> --case <案>

# JS 离线抽
python3 炼蛊房/c2_zt_probe.py extract --path bundle.js

# 铸时间窗 HMAC（抓到钥再打）
python3 炼蛊房/c2_zt_probe.py hmac --key <钥> --method GET --path /api/knock

# 只在抽出序列后才敲门，再回看重点口
python3 炼蛊房/c2_zt_probe.py knock --host <源IP> --seq 7000,8000,9000 --proto tcp
```

产物：`案卷/c2_zt/surface.json`。

溯源并行（本卡不替代）：

```bash
python3 炼蛊房/origin_recon.py --domain 授权域 --case <案>
python3 炼蛊房/js_secret_hunter.py hunt --base https://授权站 --case <案>
python3 炼蛊房/trusted_ip_header_probe.py --base https://授权站 --case <案>
```

## 六步（禁止停在「全端口无响应」）

```text
① CDN/证书找源 IP → Host / XFF 验是不是还黑洞
② 拉 Vue/Worker JS：knock 序列、HMAC 钥、wss PTY、STUN/TURN、backaddress
③ 有序列才 knock；无序列不要扫 1–65535
④ 铸 X-Auth 短窗重放；爆破不超过短字典，先找泄露
⑤ 控制台路径：/api/v1/keys/apply /pty/ /api/db/query /api/sandbox/exec
⑥ L2 填对象矩阵「自己×读」。改密/持久化先问。沙箱逃逸交接 linux-post-exploit / container-security-testing
```

## 交接

| 认到 | 走 |
|------|----|
| 只要源站 IP / 证书 SAN | `cdn-origin-tracing` · `origin_recon.py`，验完回本卡 `--origin-ip` |
| 只是 XFF 把 403 打成 200 | `trusted-ip-header`（加款仍走 hardcoded-token-cfip-fund） |
| PTY `wss://` 消息/CSWSH | `websocket-pentest` · `ws_probe.py` |
| 内存沙箱 / gvisor / runc | `linux-post-exploit` · `container-security-testing` · `瓮中逃.md` |
| 授权机验我们自己的 Sliver | `host-c2-verify` · `host_c2_verify.py` |
| 支付 notify / return_url | 假支付专卡，不并本链 |

## 强制

1. 点名敲门 / 黑洞 / Vue C2 **先开本卡**，不要并进 `host-c2-verify`。
2. 授权内出 HMAC 重放 / 源站 Host 旁路 / 未授权 JSON **直接做**，不要只交架构图。
3. TCP 全开且 HTTP 同码 = TUN 假 OPEN，禁止报 L2。
4. 彩虹易弱校验、默认改超管密、广谱 65535 不作为本卡结案。

## 真源

- 手法：`传承/行器·敲门.md`
- 探针：`炼蛊房/c2_zt_probe.py`
