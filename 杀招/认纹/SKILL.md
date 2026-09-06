---
name: 认纹
description: >-
  哈希族识别：bcrypt / crypt / JWT / MD5 / SHA / NTLM / argon2。
  触发：这是什么哈希、hash identifier、口令哈希识别。不是 GPU 爆破。
---

# 哈希识别（大爱仙尊）

授权样本或库转储里的哈希串。本卡 **只认族**，不开字典。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 命中 bcrypt / JWT / crypt / hex | 没跑识别就开 hashcat |
| L2 | 整文件分类进案卷 | 本卡跑完爆破 |
| L3 | 本卡不设 | GPU 穷举 |

规则：`$2a$/$2b$/$2y$` bcrypt、`eyJ` JWT、`$1$` `$5$` `$6$` crypt、`$argon2`、`$P$` phpass、32/40/64/128 hex。

## 立刻跑

```bash
python3 炼蛊房/hash_identify.py --hash '$2a$10$...............................................'
python3 炼蛊房/hash_identify.py --path hashes.txt --case <案>
```

产物：`案卷/hash_id/surface.json`。

## 六步

```text
① 先 identify，不要先猜 MD5
② JWT 交 jwt-bypass / jwt_persist
③ bcrypt/crypt 交 auth-brute（授权短字典）
④ NTLM hex 交域面，不要当网站口令
⑤ 没命中再看盐和轮数，仍不要本卡爆破
⑥ 结案写 kinds，不写撞出的明文（除非授权验证账号）
```

## 交接

| 认到 | 走 |
|------|----|
| JWT | `jwt-bypass-pentest` / `jwt-stateless-persist` |
| 网站口令哈希 | `auth-brute` |
| 域 NTLM | `ad-windows-router` |

## 真源

- 手法：`传承/专项探府.md`
- 探针：`炼蛊房/hash_identify.py`
