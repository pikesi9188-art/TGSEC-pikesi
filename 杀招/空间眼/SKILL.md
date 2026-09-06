---
name: 空间眼
description: "FOFA 查询/反查用: 子域、兄弟资产、指纹。密钥只读 config.yaml（Yanbai VIP）。"
version: 1.0.1
license: MIT
platforms: [linux]
metadata:
    tags: [fofa, recon, osint, asset-discovery]
    category: ctf-pentest
---
# FOFA 查询

## 密钥（强制）

- **只许**用仓库根目录 `config.yaml` → `fofa.email` / `fofa.key`（账号 **Yanbai VIP**）。
- **禁止**使用：fofoapi.com 内置免费 Key、账号 **Ynabai**、Skill 里历史硬编码、环境里的过期免费号。
- 不要把 Key 写进案卷正文或再写回本 Skill。

额度不足（`[820031] F点余额不足`）= 用错了免费号或 VIP 额度耗尽；先核对 `config.yaml` 是不是 Yanbai，再减 `size` / 分页。

## 入口（按序）

1. **引擎（推荐）** — 自动读 `config.yaml`：

```bash
python3 tools/space-search/bin/space_search.py search \
 --query 'domain="example.com"' --case <案卷> --engines fofa
```

2. **官方 API curl** — Key 从配置读，禁止手写免费号：

```bash
# 从 config.yaml 取 Yanbai key，打 fofa.info（不要打 fofoapi.com）
eval "$(python3 - <<'PY'
import yaml
from pathlib import Path
c=yaml.safe_load(Path("config.yaml").read_text())["fofa"]
print(f'FOFA_EMAIL={c["email"]!r}')
print(f'FOFA_KEY={c["key"]!r}')
PY
)"
qb=$(printf '%s' "QUERY" | base64 | tr -d '\n')
curl -sk "https://fofa.info/api/v1/search/all?email=$FOFA_EMAIL&key=$FOFA_KEY&qbase64=$qb&fields=host,title,ip,port,domain,protocol&size=100"
```

响应 = `{"error":false,"size":N,"results":[...]}`。

## 常用查询语法

- 子域: `domain="example.com"`
- IP 反查: `ip="1.2.3.4"`
- 指纹: `body="欢迎使用飞投后台管理框架"` / `title="钱包管理系统"`
- 端口/协议: `protocol="mysql"` / `port="3306"`
- 组合: `domain="x.com" && port="8888"` / `(protocol="http") && country!="CN"`
- 排除中国站: **必须 CN+HK+MO+TW 全排除**（用户明确要求, HK 结果不能当"非中国"交差）:
 `country!='CN' && country!='HK' && country!='MO' && country!='TW'`

## 批采流程（用户规范）

- 15-20 组查询 × 3-5 页, 每页 100 条; 排除 CN/HK/MO/TW
- 筛活 → 按框架/指纹分类 → delegate_task 下发（每组 10-20 目标）
- 每目标必测: admin/login/api/swagger/docs/install/robots.txt/.env + 框架 + 默认密码
- 发现高管/疑似后台再深度下发; 用户说"太少了" = 扩量

## Pitfalls

- base64 去掉换行（`tr -d '\n'`）
- 结果多页: 加 `&page=2`
- fields 用逗号分隔, 别加空格
- 大查询(size>500)可能被拒, 分页拉
- FOFA 语法里 `&&` 在 shell 中要引号包整个 query
- **不要**再走 `https://fofoapi.com/...` 免费代理

## 真源

- 手法：`传承/空间眼.md`
