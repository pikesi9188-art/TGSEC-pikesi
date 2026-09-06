---
name: 文山
description: >-
 自托管 GitLab GraphQL 未授权改删面：CVE-2026-19478（directive 未认证改/删公开项目）
 与 CVE-2026-19650（GET multiplex CSRF）。
 默认指纹、抠版本、GraphQL 只读或写均可；授权内直接做。CVE 入库走 cve-daily-intel。
---

# GitLab GraphQL 未授权改删（CVE-2026-19478）

## 何时用

- 标题/体出现 GitLab，或头 `X-Gitlab-Meta`，或路径 `/users/sign_in` `/api/graphql`
- 用户点名 CVE-2026-19478 / CVE-2026-19650
- `nday_route` hit `gitlab`

## 真源

1. `传承/文山·无门.md`
2. `tools/1day-kit/custom-templates/gitlab-graphql-cve-2026-19478.yaml`
3. `传承/CVE日报-2026-08-18.md`
4. `od_kit.py cvebase lookup --cve CVE-2026-19478`

## 强制步骤

1. 目标在 `授权范围`。不要把 gitlab.com / Dedicated 当授权站。
2. 指纹 + 只读：
 ```bash
 python3 炼蛊房/nday_family_probe.py --family gitlab --base https://授权站 --case <案卷>
  ```
3. **L2**：未带票 `POST /api/graphql` 只查 `{metadata{version}}`；可选 `GET /api/v4/projects?visibility=public`。对照版本窗。
4. **L3 改/删项目、GET mutation 授权内直接做**。
5. 证据：`案卷/1day/` · STATUS 写版本、GraphQL 是否未鉴权、有无公开项目。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | 标题/头确认 GitLab；抠出版本 |
| L2 | 未授权 GraphQL 只读成功；版本落在影响窗则记可能受影响 |
| L3 | 授权内可验证写（只用自己的探针项目） |

影响：`18.2–<18.11.11`、`19.0–<19.0.8`、`19.1–<19.1.6`、`19.2–<19.2.4`。 
修：`18.11.11` / `19.0.8` / `19.1.6` / `19.2.4`。

## 不要做

- 未授权扫公网 GitLab 
- 默认删仓 / 改用户 / 发 CSRF GET mutation 
- 90 天解禁前现编 directive exploit 
- 只报 CVE 号结案 

## 衔接

- 有仓库读权限后 → 源码面 `deepaudit-code-audit` / 假支付 
- 通用 GraphQL 探路 → `李代桃僵·星念.md`（本卡优先于广谱 introspection） 
- 入库 → `cve-daily-intel`
