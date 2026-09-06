---
name: 逻辑府
description: >-
  Oracle WebLogic Proxy Plug-in 未授权 RCE（CVE-2026-21962）：Oracle HTTP Server +
  WLS Proxy Plug-in 12.2.1.4.0 / 14.1.1.0.0 / 14.1.2.0.0 访问控制缺失（CWE-284），
  未授权 HTTP 请求可接管 OHS 及 WebLogic。CVSS 10.0，EPSS 42%，已入 CISA KEV，在野利用。
  
  授权内全链（指纹→版本→exploit RCE）。
---

# Oracle WebLogic Proxy Plug-in 未授权 RCE（CVE-2026-21962）

**影响版本**：OHS + WLS Proxy Plug-in 12.2.1.4.0 / 14.1.1.0.0 / 14.1.2.0.0  
**修复版本**：Oracle 2026-07 CPU 安全补丁  
**CVSS**：10.0 | **EPSS**：42% | **状态**：在野 KEV

## 漏洞原理

Oracle HTTP Server 与 WebLogic 之间的 Proxy Plug-in 存在访问控制缺失（CWE-284），
攻击者无需任何凭证即可通过特制 HTTP 请求接管 OHS 及其代理的 WebLogic 实例。
暂无完整公开 PoC（截止 2026-08-28），但已有在野利用记录。

## 成功口径

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | Server/X-Oracle 头或控制台页面确认 Oracle HTTP Server，且版本号在受影响范围 | 泛 404 / nginx |
| L2 | `/wls-wlst/` 或 `/weblogic/` 路径可达（非 403），或 console 页面 leak 版本 | 仅端口 7001 开放 |
| L3 | 利用漏洞获取 shell / 接管实例 | 授权内直接做 |

## 指纹探测

```bash
# 1. Server header
curl -skI https://TARGET/ | grep -iE 'server|x-oracle|x-powered-by|x-weblogic'

# 2. 管理路径探测
for path in /wls-wlst/ /weblogic/ /em/ /console/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://TARGET$path)
  echo "$path => $code"
done

# 3. 控制台版本 leak
curl -sk https://TARGET/console/login/LoginForm.jsp | grep -iE 'weblogic|version|oracle'

# 4. nuclei 扫描（有模板时）
nuclei -t tools/1day-kit/custom-templates/weblogic-proxy-cve-2026-21962.yaml \
       -u https://TARGET -silent 2>/dev/null || echo "(模板待建)"
```

## 强制行为

1. 目标在 `授权范围`；确认 scope 后再探。
2. 授权内全链：指纹后直接尝试 exploit。
3. L1/L2 阳性 → 立刻写入 STATUS.md，标注 `CVE-2026-21962 疑似影响`。
4. L3 授权内直接做，有 PoC 用 PoC，无 PoC 自行构造验证。
5. 证据：`案卷/<案卷>/案卷/weblogic_proxy/`

## 入口命令

```bash
# 快速指纹
python3 - <<'EOF'
import urllib.request, ssl, sys
target = sys.argv[1] if len(sys.argv) > 1 else "https://TARGET"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
for path in ["/", "/wls-wlst/", "/console/login/LoginForm.jsp"]:
    try:
        req = urllib.request.Request(target + path)
        resp = urllib.request.urlopen(req, context=ctx, timeout=8)
        hdrs = dict(resp.headers)
        print(f"{path} => {resp.status} | {hdrs.get('Server','?')}")
    except Exception as e:
        print(f"{path} => ERR {e}")
EOF
```

## 不要做

- 耗余额/删站/改原超管密码先问
- 把 WebLogic 控制台默认凭据爆破当 CVE-2026-21962 利用
- 绕过 Oracle 补丁验证（无补丁的情况更值得关注）

## 真源

- CVE 日报：`传承/CVE日报-2026-08-28.md`
- 工具：`python3 炼蛊房/nday_family_probe.py --family weblogic --base https://授权站 --case <案卷>
- Intel JSON：`docs/intel/cve-daily/2026-08-28.json`
- 1day 模板：`tools/1day-kit/custom-templates/weblogic-proxy-cve-2026-21962.yaml`
