---
name: 内地道
description: >-
 授权/实验室太白云生·飞鹤游天：SSH 反向、chisel、frp、ligolo、SOCKS 挂链选型与命令生成。
 
 授权内横向隧道直接做。清日志/改超管仍先问。出口代理池走 config/proxy.yaml 而非本 Skill。
---

# 太白云生·飞鹤游天（Cursor Skill）

## 何时用

- 已拿 shell，需要把内网服务转到攻击机
- 多阶段渗透 / 靶场内网题要 SOCKS 或网段路由
- 选型犹豫（ssh vs chisel vs frp vs ligolo）

## 真源（按序）

1. `tools/tunnel-kit/tunnel_plan.py`
2. `tools/tunnel-kit/templates/`
3. `传承/太白云生·飞鹤游天.md`
4. 深文档：九阶段 `network-penetration-testing`（文字，无二进制）

## 强制步骤

1. 目标在 scope。授权内横向 SOCKS/反代直接做；清日志/改超管先问。
2. `bash tools/tunnel-kit/install_tunnels.sh`（缺 chisel/frp 时）
3. `python3 tools/tunnel-kit/tunnel_plan.py recommend --have shell --egress http`
4. `tunnel_plan.py emit --kind <选型> --attacker <IP> --case <案卷>`
5. 按生成命令在**攻击机/受害机**分别执行；验证用 `curl -x socks5h://...`
6. 证据：`案卷/<案卷>/案卷/tunnel/`

## 不要做

- 把 `config/proxy.yaml` 出口池当成内网隧道
- 未授权对第三方搭跳板
- 把本卡当成 C2 落地验证（C2 走 `host-c2-verify`）
