---
name: 常山阴·狼栈
description: >-
 授权目标上 WolfStack CVE-2026-73519：硬编码集群密钥 X-WolfStack-Secret 绕过鉴权，
 枚举容器并 exec。与 Portainer/Docker 旁路同族；
 得壳后可读 .env 交接 fernet-session-decrypt / tg-cloud-panel。
---

> **常山阴**
> 狼王一啸北原开，阴云压阵万兽来。
> 常山不常阴更阴，死契密令血作牌。

# WolfStack 硬编码集群密钥（Cursor Skill）

## 何时用

- 主机暴露 WolfStack 管理口
- VPS/云控旁路扫到容器编排面板
- 用户点名 CVE-2026-73519

## 真源

1. `传承/狼栈·死契.md`
2. `炼蛊房/wolfstack_probe.py`
3. `tools/1day-kit/custom-templates/wolfstack-cve-2026-73519.yaml`
4. GHSA-r3mw-2wmq-j6jg（修 25.9.2+）

## 强制步骤

1. 目标在 scope。
2. ```bash
 python3 炼蛊房/wolfstack_probe.py -u http://IP:端口 --case <案卷>
 python3 炼蛊房/wolfstack_probe.py -u http://IP:端口 --case <案卷> --exec
 ```
3. 探针会对照**无密钥**请求：仅「有密钥放行、无密钥拒绝」才报 CVE-2026-73519；裸奔另记。
4. L2=`--exec` 见 `uid=`。
5. 容器内有 `.env`/session → 切 `fernet-session-decrypt` / `tg-cloud-panel`。
6. 双 401 → 记「已轮换密钥」，勿虚报。

## 不要做

- 未授权扫网 · 默认破坏性 exec · 只报 CVE 不验证

## 衔接

- 主机提权/隧道 → `linux-post-exploit` / `internal-tunnel`
- TG 物资 → `tg-cloud-panel`
