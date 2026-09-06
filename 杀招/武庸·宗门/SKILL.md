---
name: 武庸·宗门
description: >-
  Windows/AD 域渗透与后渗透场景分流路由。已拿到域内 shell 或发现 AD 环境时，
  根据具体场景分流到对应专用 Skill。
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# Windows / AD 域渗透分流

**适用时机**：已在授权域内机器上有 shell，或发现 Active Directory 环境。

## 场景 → Skill 速查表

| 场景 | 触发特征 | 走哪张卡 |
|------|----------|----------|
| **域信息枚举** | 首次拿到域内机器 shell | `ad_surface_check.py` + `windows-ad-pentest` |
| **AD 域渗透完整链** | BloodHound / ACL / 域控 | `windows-ad-pentest` |
| **AD CS 证书滥用** | ESC1-13、`certify`、ADCS、证书模板 | `adcs-pentest` |
| **混合身份 / Entra** | AAD、ADFS、云身份、PRT | `windows-ad-pentest`（混合段）+ `identity-federation` |
| **Kerberos 攻击** | Kerberoasting、AS-REP Roasting、Silver/Golden Ticket | `kerberos-attack` |
| **SMB 横向移动** | Pass-the-Hash、WMI、impacket、psexec | `smb-lateral-movement` |
| **Windows 持久化** | 计划任务、服务注册、注册表 Run、DLL 劫持 | `windows-persistence` |
| **内网隧道建立** | 出网受限、需要代理链、SOCKS | `internal-tunnel` |
| **内网扫描** | 横向扫端口/服务 | `internal_scan.py`（`ad_surface_check.py` 附带） |
| **Linux 提权** | 低权 shell → root，SUID/sudo/cron | `linux_lpe_checker.py`（本卡 AD 场景优先） |
| **Windows 提权** | 低权 → SYSTEM，UAC/SeImpersonatePrivilege | `windows_lpe_checker.py` |
| **容器逃逸 → K8s** | 容器内 ServiceAccount / privileged | Playbook `瓮中逃.md` + 群瓮·特权 |
| **主机应急响应** | 已入侵后门排查、IR | `host_ir_check.py` |
| **C2 落地验证** | Sliver / 授权主机回连 | `host-c2-verify` |

## 五阶段（无 shell 也能开）

| 阶段 | 做什么 | 命令 / 卡 |
|------|--------|-----------|
| 1 侦察 | DC 端口 88/389/445/5985、空会话、LDAP 匿名、kerbrute | `ad_surface_check.py` |
| 2 凭据 | AS-REP / Kerberoast / 喷洒（先看锁定策略）/ netexec 横扫 | `kerberos-attack` |
| 3 域接管 | DCSync、krbtgt、金/银票 | `windows-ad-pentest` |
| 4 高级 | 委派/RBCD、ADCS ESC1-13、ACL 链、混合 AAD | `adcs-pentest` |
| 5 横向 | PTH/PTT、evil-winrm、chisel/SSH 隧道 | `smb-lateral-movement` · `internal-tunnel` |

版本命中 CVE（如 PetitPotam 类）必须证明协议可达，不能只报版本。

## 决策流程

```
已拿 shell
   │
   ├─ Linux？→ linux_lpe_checker.py 并行 host_ir_check.py
   ├─ Windows？
   │   ├─ 看域加入状态 → ad_surface_check.py
   │   ├─ 域内机器 → windows-ad-pentest → BloodHound → ACL
   │   ├─ 发现 ADCS → adcs-pentest（ESC 系列）
   │   ├─ Kerberos 服务账号 → kerberos-attack
   │   ├─ 想横向 → smb-lateral-movement
   │   └─ 想持久 → windows-persistence
   ├─ 容器？→ 瓮中逃.md → K8s ServiceAccount
   └─ 需要内网代理 → internal-tunnel
```

## 前置工具

```bash
# 初始化 AD 环境侦察
python3 炼蛊房/ad_surface_check.py --host 目标IP --case <案卷>
# 自动化 LPE 检查
python3 炼蛊房/linux_lpe_checker.py --case <案卷>          # Linux
python3 炼蛊房/windows_lpe_checker.py --case <案卷>       # Windows
```

## 禁止

- 拿到域控权限后立刻改 KRBTGT 密码（先问）
- 在不出网的靶机上用需要 Internet 的工具
- 未授权内网 IP 随意横向（先确认 scope 涵盖内网段）

## 真源

- Playbook：`传承/宗门·认族.md` · `纵横天下.md` · `太白云生·飞鹤游天.md` · `反客为主-窗府.md` · `反客为主.md`
- Skill 详细命令见各子卡
