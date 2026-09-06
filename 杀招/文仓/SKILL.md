---
name: 文仓
description: >-
  CVE-2026-60004 Gitea < 1.27.1 diffpatch API Git hook RCE。
  EPSS 82.4%（99.6 百分位），CISA KEV 2026-08-25，在野利用。
  仅做版本指纹 + API 探测；禁止实际写 Git hook。
  发现 Gitea 实例或
---

# Gitea diffpatch RCE — CVE-2026-60004

## 背景

Gitea < 1.27.1 的 `/api/v1/repos/{owner}/{repo}/diffpatch` 端点在处理 diff 时未过滤
恶意 Git hook，认证用户可通过构造 diff 触发服务端任意命令执行。  
已入 CISA KEV（2026-08-25），EPSS 82.4%，在野利用已确认。

## 授权检查

```bash
python3 炼蛊房/scope_expand.py --check <TARGET_DOMAIN>
```

目标不在 scope 禁止开打。

## 强制步骤

### Step 1 — 版本指纹（只读，无账号）

```bash
# Swagger 版本字段
curl -sk https://TARGET/api/swagger | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('info', {}).get('version', 'not found'))
"

# 或直接看版本 API
curl -sk https://TARGET/api/v1/version | python3 -m json.tool
# {"version":"1.XX.X"} — < 1.27.1 即阳性

# 登录后管理页面
curl -sk -b "gitea_session=YOUR_COOKIE" https://TARGET/-/admin/self-check \
  | grep -i 'gitea version'
```

### Step 2 — API 可达性探测（需低权账号）

```bash
# 生成 token（已有账号）
TOKEN="YOUR_GITEA_TOKEN"

# 列举仓库（验证 token 有效）
curl -sk -H "Authorization: token $TOKEN" \
  "https://TARGET/api/v1/repos/search?limit=3" | python3 -m json.tool

# 探测 diffpatch 端点响应码（不发恶意 payload）
curl -sk -o /dev/null -w "%{http_code}" \
  -X POST -H "Authorization: token $TOKEN" \
  -H "Content-Type: text/plain" \
  --data-raw "" \
  "https://TARGET/api/v1/repos/OWNER/REPO/diffpatch"
# 200/400 → 端点存在；403/404 → 无权或路径不同
```

### Step 3 — 本库族探针

```bash
python3 炼蛊房/nday_family_probe.py --family gitea --base https://TARGET --case <案卷>
```

nuclei 模板只作对照，不结案。

## 成功口径

| 条件 | 结论 |
|------|------|
| `version < 1.27.1` + `/api/v1` 可达 | **P0 确认，上报** |
| diffpatch 端点返回 200/400（非 404） | **端点暴露，待 PoC** |
| 版本 ≥ 1.27.1 | 已修补，阴性 |

## 禁止

- 实际 POST 含 hook 的恶意 diff payload
- 在未授权目标上执行任何步骤
- 把第三方 Gitea 实例扩进 scope

## 证据落盘

```bash
# 版本截图 / curl 输出 → exports/CASE/gitea/
mkdir -p exports/CASE/gitea/
curl -sk https://TARGET/api/v1/version > exports/CASE/gitea/version.json
```

## 参考

- CISA KEV：https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Gitea 1.27.1 Release Notes：https://gitea.io/
## 真源

- 手法：`传承/文仓·开天.md`
- 工具：`python3 炼蛊房/nday_family_probe.py --family gitea --base https://授权站 --case <案卷>`

- Playbook：`传承/文仓·开天.md`
- 日报：`传承/CVE日报-2026-08-28.md`
- JSON：`docs/intel/cve-daily/2026-08-28.json`
