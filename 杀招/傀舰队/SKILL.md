---
name: 傀舰队
description: >-
  授权多机 C2 舰队。触发：botnet、僵尸网、C2 舰队、多机回连、持久化清单。
  每台先 scope，再 host_c2_verify init/record，持久化走 windows-persistence / host_ir_check。
  不是 P2P 传播，不带 DDoS 模块。implant 不进 git。
---

# 授权 C2 舰队（大爱仙尊）

每台 `--host` 必须在 `授权范围`。  
授权内默认打到 **L2**：舰队计划已落 + 至少一台 `record`。  
先问只剩：清日志、改原超管、对外传播。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `fleet` 写出 plan，每台过 scope | 没进 scope 就 init |
| L2 | 一台 `host_c2_verify record`（callback/session） | 只写了 JSON 计划 |
| L3 | persist 清单落地 + `--local` 跑过 `host_ir_check` | implant 提交进 git |

## 立刻跑

```bash
python3 炼蛊房/botnet_lab.py fleet --host <授权A> --host <授权B> \
  --case <案> --os linux --stack sliver --edr unknown

python3 炼蛊房/botnet_lab.py persist --host <授权A> --case <案>
# 本机就是授权机时顺带排别人的后门
python3 炼蛊房/botnet_lab.py persist --host <授权A> --case <案> --local

python3 炼蛊房/host_c2_verify.py record --case <案> --host <授权A> \
  --callback yes --session-id none --av-action unknown --edr unknown --note fleet
# sha256 有了再加：--implant-sha256 <64位hex>，填 pending 会被闸掉

python3 炼蛊房/host_c2_verify.py check --case <案> --strict
```

产物：`案卷/botnet_lab/fleet.json`、`persist_<host>.json`；C2 闸在 `案卷/host_c2/`。

`fleet` 内部对每台调 `host_c2_verify.init`。二进制仍只在攻击机，不进仓库。

## 六步

```text
① 列授权机，全部 in_scope
② fleet 出计划（os/stack/edr）
③ 攻击机官方 C2 出 implant，记 sha256
④ 授权机执行 → record callback/session/av_action
⑤ persist：IR 先排别人的 cron/SSH/计划任务，再写自己的维持
⑥ check --strict；清日志仍先问
```

## 交接

| 认到 | 走 |
|------|----|
| 对面控制台 / 敲门 / 黑洞 | `c2-zero-trust-console` · `c2_zt_probe.py` |
| 单机落地回连 | `host-c2-verify` |
| Windows 维持 | `windows-persistence` |
| Linux 维持 / 提权 | `linux-post-exploit` |
| 本机排后门 | `host-ir-check` · `host_ir_check.py` |
| 可用性洪水念头 | `authorized-ddos-surface`（禁止发送器） |

## 真源

- 手法：`传承/授权恶族.md`
- 探针：`炼蛊房/botnet_lab.py`
- C2 闸：`炼蛊房/host_c2_verify.py` · `鬼不觉.md`
