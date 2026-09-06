---
name: 房睇长·分案
description: >-
  Banner / 产品版本映射 CVE：NVD 检索、CVSS 排序。只出假设，不算 L2。
  
  今天新 CVE 入库走 cve-daily-intel；站上复现走 nday_route / 1day-nuclei-kit。
---

> **房睇长**
> 智海观潮耳报先，一纸风闻动五域。
> 睇长不睇眼前利，先听劫云哪边偏。

# CVE 分诊（情报，L1 假设）

从 `Server:` / 页脚 / 包版本抽出「产品 + 版本」，先分诊再决定复现。禁止把本卡输出写成 STATUS 的 L2。

## 立刻跑

```bash
python3 炼蛊房/cve_triage.py --query 'Apache httpd 2.4.49' --case <案卷>
python3 炼蛊房/cve_triage.py --cve CVE-2021-41773 --case <案卷>
```

授权站要验证：

```bash
python3 炼蛊房/nday_route.py --url https://授权站 --case <案卷>
python3 炼蛊房/auto_campaign.py plan -d 授权站 --case <案卷>
```

## 分流

| 用户要的 | 走 |
|----------|-----|
| 这个版本可能有哪些洞 | **本卡 · L1 假设** |
| 今天/本周新 CVE 入库 | `cve-daily-intel` |
| 站上指纹复现 | `1day-nuclei-kit` · `nday_route.py` |
| HITCON ZeroDay | `hitcon-zeroday-intel`（不扩厂商） |
| 已知组件（Ollama / JetEngine / Doris / Actuator） | 对应专卡，不要停在 NVD |

## 强制

1. 关键字命中要先对版本回迁补丁。  
2. 第三方 PoC 当线索，不盲目对授权站执行。  
3. `/actuator` 命中走 Gateway 全链，禁止只扫 health。

## 失败

- NVD 超时 → 记 query，改日报或 `od_kit.py lookup`
- 只有产品名没有版本 → 先 `auto_campaign.py plan -d <域>`

## 真源

- 手法：`传承/使证闸.md`
- 工具：`python3 炼蛊房/cve_triage.py --help`
