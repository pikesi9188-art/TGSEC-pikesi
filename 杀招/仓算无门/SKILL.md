---
name: 仓算无门
description: >-
 Apache Doris 三板斧：9030 MySQL 协议 root 空口令直连、8030 HTTP API 未授权翻库、
 SQL 注入顺藤摸瓜，有写权限再 SELECT INTO OUTFILE 甩马。
 
 默认 L2 翻库；OUTFILE/甩马授权内直接做。
---

# Apache Doris 未授权三板斧

Doris 三板斧：9030 MySQL 协议 root 空口令直连、8030 HTTP API 未授权翻库、SQL 注入顺藤摸瓜，有写权限再 SELECT INTO OUTFILE 甩马。

## 何时用

- 端口 **9030**（FE `query_port` / MySQL 协议）、**8030**（FE HTTP）或 **8040**（BE HTTP）
- 标题/体出现 Apache Doris、Palo、`/rest/v1/`、`default_cluster`
- 旁注/SSRF 打到内网 8030/9030；StarRocks 同口当兄弟栈
- `nday_route` hit `doris`；用户点名 CVE-2026-58319

## 真源

1. `传承/仓算无门.md`
2. `python3 炼蛊房/doris_probe.py --host <授权IP> --case <案卷>`
3. `tools/1day-kit/custom-templates/doris-unauth-surface.yaml`

## 强制步骤

1. 目标在 `授权范围`（SSRF 打到的内网 IP 先扩权）。
2. 默认跑满 L2（不要只扫端口就结案）：
 ```bash
 python3 炼蛊房/doris_probe.py --host <授权IP> --case <案卷>
 python3 炼蛊房/doris_probe.py --host <授权IP> --case <案卷> --deep
 python3 炼蛊房/doris_probe.py --host '[<IPv6>]:8030' --case <案卷>
 ```
3. 斧1：`9030` `root`/`admin` **空口令** → `SHOW DATABASES` / `SHOW FRONTENDS`。
4. 斧2：`8030` 无鉴权或 Basic `root:` → Doris `/api/query` **和** StarRocks `/api/v1/catalogs/.../sql`；顺带 `8040` BE 指纹。
5. 斧3：应用层 SQLi 或已拿到 SQL 执行面 → 顺 `information_schema` 摸业务表；**OUTFILE / 甩马授权内直接做**。
6. 证据：`案卷/doris/probe.json`。抽样打码，不拖全库。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | 9030 出 MySQL 握手或 8030 出 Doris/FE JSON |
| L2 | 空口令进（含仅系统库）或 HTTP `/api/query` 出 `result_set` |
| L3 | 授权内可验证写盘/OUTFILE（默认只写 marker） |

`< 3.1.0` 的 FE 管理 REST 对上 **CVE-2026-58319**。官方默认 `root` 空口。

## 不要做

- 未授权扫公网 8030/9030
- 默认 `SELECT INTO OUTFILE` 写 webshell / 清库 / `DROP`
- 只报「端口开着」结案

## 衔接

- 读到 JDBC/云钥 → 回灌业务站 / 假支付
- 同机 Web → 对象矩阵 + `linux-post-exploit`
- Redis/Mongo 伴生 → 对应中间件卡
- StarRocks 同口先当本卡打，路径差记 STATUS
