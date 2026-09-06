---
name: 锁库演
description: >-
  授权案卷内勒索演练。触发：ransomware、勒索构建、加密演练、ransom note、恢复演练。
  只加密 案卷/<案>/案卷/ransom_lab/inbox，钥落盘并带解密器。
  禁止动 / /etc 系统盘。不是对外发放的勒索构建器。
---

# 授权案卷勒索演练（大爱仙尊）

必须带 `--case`。加密范围锁死在案卷 `案卷/ransom_lab/inbox`。  
授权内默认打到 **L2**：加密可逆，钥和解密器同案。  
先问只剩：动系统盘、对外发加密器。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | `init` 出 inbox + `key.json` | 只口头说「可以加密」 |
| L2 | inbox 文件变成 `.seenc` 且 `decrypt` 还原原文 | 钥丢了还报演练成功 |
| L3 | 案卷 NOTE + `decrypt.sh` 能独立恢复 | 对 `/` `/etc` 动手 |

## 立刻跑

```bash
python3 炼蛊房/ransom_lab.py init --case <案>
# 把演练文件放进 案卷/<案>/案卷/ransom_lab/inbox/
python3 炼蛊房/ransom_lab.py encrypt --case <案>
python3 炼蛊房/ransom_lab.py decrypt --case <案>
```

算法：SHA256 计数器流 ⊕ 明文，钥 32 字节写 `key.json`。  
`encrypt` 会写 `NOTE.txt` 和 `decrypt.sh`。拒绝 uid=0 加密。

产物：`案卷/ransom_lab/{inbox,key.json,decrypt.sh,NOTE.txt}`。

## 六步

```text
① init 建 inbox / key.json
② 只往 inbox 放演练文件，不要软链到家目录
③ encrypt → 原文件消失，留下 .seenc
④ 确认 key.json 还在，再做任何展示
⑤ decrypt 还原；对一下哈希
⑥ 结案写 STATUS：可逆 + 路径，不写对外 payload
```

## 交接

| 认到 | 走 |
|------|----|
| 多机落地 / 回连 | `authorized-botnet-lab` · `host-c2-verify` |
| 启动项 / EFI | `authorized-bootkit-audit` |
| 可用性压测 | `authorized-ddos-surface` |
| 助手没身份 | 开源版不带助手注入 |

## 真源

- 手法：`传承/授权恶族.md`
- 探针：`炼蛊房/ransom_lab.py`
