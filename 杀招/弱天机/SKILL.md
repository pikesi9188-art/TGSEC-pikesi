---
name: 弱天机
description: >-
  弱 PRNG / LCG 反推：glibc、MSVC、Java LCG。钱包助记词/卡密连续输出。
  触发：弱随机、LCG、prng、weak-rng、助记词连续。
  BIP39 正规派生仍走 wallet-core-reverse。禁止对无关链上地址碰撞。
---

# 弱随机 / LCG（大爱仙尊）

授权样本或自有钱包导出里的连续整数。  
授权内默认打到 **L2**：对上族并给出 next/prev。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | dump 里抠出 ≥2 个整数 | 单条随机数 |
| L2 | glibc / MSVC / Java / numerical 对上下一个 | 没对上还报可预测 |
| L3 | 用 next 推出下一张卡密/助记词并在授权样本验证 | 对无关链上地址穷举 |

内置族：`glibc (1103515245,12345,2^31)`、`msvc`、`numerical`、`java_lcg (2^48)`，shift 0/16。

## 立刻跑

```bash
python3 炼蛊房/weak_rng_probe.py lcg --out 12345 --out 1406932606
python3 炼蛊房/weak_rng_probe.py glibc --seed 1 --n 8
python3 炼蛊房/weak_rng_probe.py drive --path dump.txt --case <案>
```

`lcg` 直接吃观测值。`drive` 用正则 `\b\d{2,16}\b` 从文本抽。  
`glibc --seed` 正向展开，用来对照。

产物：`案卷/weak_rng/surface.json`。

## 六步

```text
① 从日志/样本取连续输出，不要跳着取
② lcg 先跑；ok=false 换 shift/族
③ 记下 family / state / next
④ 授权样本再取一个数验证 next
⑤ 正规 BIP39 / native 派生交 wallet-core-reverse
⑥ 禁止拿 next 去扫别人的链上地址
```

## 交接

| 认到 | 走 |
|------|----|
| BIP39 / HD / wallet-core | `wallet-core-reverse` |
| 卡密 / 网络验证 | `net-license-crack` |
| 钱包 App 业务面 | `wallet-app-pentest` |

## 真源

- 手法：`传承/专项探府.md`
- 探针：`炼蛊房/weak_rng_probe.py`
