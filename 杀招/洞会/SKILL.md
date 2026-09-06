---
name: 洞会
description: >-
  从 HITCON ZeroDay（zeroday.hitcon.org）公开列表学习漏洞手法并落本库 Skill：
  分类、对缺口写专卡、禁止把通报厂商扩进 scope。
  扫授权站复现走 hitcon_chain_probe（Ollama / 4577 / xmlrpc / 客户端状态 / 敏感目录 / 重置 token）。
---

# HITCON ZeroDay 情报 → 本库技能

## 何时用

- 用户丢 `https://zeroday.hitcon.org` 或说「去 ZeroDay 上学洞 / 写 skill」
- 要把公开通报转成可调用专卡，禁止只聊天结案
- 对照本库缺口（`harvest.py gap`）决定补哪张卡

## 真源（按序）

1. `传承/洞会·无日.md`
2. `炼蛊房/hitcon_zd_harvest.py`
3. `docs/intel/hitcon-zeroday/`（当日 JSON）
4. 组件专卡：`ollama-unauth` · `php-cgi-cve-2024-4577` · `wordpress-xmlrpc-surface` · `client-state-skip` · `sensitive-dir-dump` · `reset-token-surface` · `trusted-ip-header` · `open-redirect-chain`
5. 授权站一条龙：`炼蛊房/hitcon_chain_probe.py`

## 强制步骤

1. 拉公开列表并分类（站点若被 CF 拦，用 seed）：
```bash
python3 炼蛊房/hitcon_zd_harvest.py harvest --out docs/intel/hitcon-zeroday/$(date +%F).json
python3 炼蛊房/hitcon_zd_harvest.py gap --seed docs/intel/hitcon-zeroday/2026-08-27.json
# 授权站复测（未修族全跑）
python3 炼蛊房/hitcon_chain_probe.py --base https://授权站 --case <案卷>
```
2. **只学手法，不打通报厂商。** 禁止 `scope_expand --grant` HITCON 标题里的学校/医院/公司域。
3. 缺口族（Ollama / PHP-CGI 4577 / xmlrpc / 已落地马）切对应专卡；弱口/SQLi/IDOR/路径穿越走已有卡，不要重复造薄卡。
4. 新 P0 族按 `房睇长·耳报.md` 六件套落盘（Playbook + Skill + 探针 + nuclei 指纹 + nday_route + 词表）。
5. 向用户回报：**分类表 + 新 Skill 路径 + 授权站一条复测命令**。

## 成功口径

| 级 | 成立 |
|----|------|
| 情报 | 当日 JSON 有 ZD 编号、族、本库落点 |
| 完善 | `gap` 里 P0 族已有专卡，或明确「走已有卡」 |
| 复测 | 只对 `scope` 内目标跑专卡探针，不是打 HITCON 厂商 |

## 不要做

- 把通报 Vendor 扩进 `targets`
- 把详情页账密/内网 IP 写进可同步文档
- 只口头列 ZD 编号不落盘
- 监视器/CCTV 未授权当网站案主线

## 衔接

- 入库 CVE 编号 → `cve-daily-intel`
- 授权站指纹 → `nday_route.py` → 专卡
- 已落地 WP 马 → `坞壳落子猎.md`
