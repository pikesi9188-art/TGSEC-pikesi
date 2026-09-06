---
name: 飞书
description: >-
  邮件安全路由卡。触发：钓鱼邮件、SPF、DKIM、DMARC、BEC、邮件头分析。
  社工投递仍走 tg-account-library / autonomous-social-engagement。
  不在仓库搭建钓鱼基础设施。
---

# 邮件安全（路由卡）

## 本仓探针

```bash
python3 炼蛊房/email_sec_probe.py eml --path <信.eml> --case <案>
```

L2=信头或 SPF/DMARC 弱。证据进案卷 `测绘/`。

## 何时用

- 评估授权域的邮件安全配置（SPF/DKIM/DMARC）
- 邮件头取证分析（钓鱼溯源）
- BEC / 钓鱼攻击可行性评估
- 用户点名邮件安全审计

本卡只指路 + 配置审计，不搭建发信基础设施。网站案默认不走本卡。

## 真源

- 钓鱼模拟知识：CSS 23 → `python3 炼蛊房/css_query.py get --id 23-001`
- 邮件取证：CSS 30-005 → `python3 炼蛊房/css_query.py get --id 30-005`
- 分流：`传承/凤金煌·分音.md` §3

## 核心步骤

1. **SPF 记录审计**：检查发件人策略框架。
   ```bash
   dig TXT 目标域名 +short | grep spf
   # 检查 SPF 是否为 ~all（软失败，可伪造）还是 -all（硬失败）
   # ~all 或 ?all → 伪造风险；-all → 严格
   ```

2. **DKIM 检查**：验证域名签名配置。
   ```bash
   # 常见 selector：default, google, k1, selector1
   dig TXT default._domainkey.目标域名 +short
   dig TXT google._domainkey.目标域名 +short
   dig TXT selector1._domainkey.目标域名 +short
   ```

3. **DMARC 策略评估**：
   ```bash
   dig TXT _dmarc.目标域名 +short
   # p=none → 无策略（最弱）  p=quarantine → 隔离  p=reject → 拒收
   # 无 DMARC 或 p=none + SPF ~all = 高伪造风险
   ```

4. **邮件头分析**（取证场景）：
   ```bash
   # 关键字段
   # Received: → 跳板链路溯源
   # Authentication-Results: → SPF/DKIM/DMARC 验证结果
   # Return-Path: → 实际发件人
   # X-Originating-IP: → 发件源 IP
   ```

5. **MX 记录与邮件网关识别**：
   ```bash
   dig MX 目标域名 +short
   # 识别邮件网关厂商（Google Workspace / Microsoft 365 / 自建）
   ```

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | 完成 SPF/DKIM/DMARC 配置枚举，识别邮件网关 |
| L2 | 发现可利用的配置缺陷（~all + p=none，可伪造发件人） |
| L3 | 在授权测试中成功投递伪造邮件到目标邮箱 |

## 分流

| 场景 | 去向 |
|------|------|
| 社工投递 / TG 投递 | `autonomous-social-engagement` |
| TG 号库管理 | `tg-account-library` |
| 钓鱼页面制作 | CSS 23（知识参考） |
| 邮件服务器漏洞 | 对应 CVE 专卡 / `nday_route.py` |
| Zimbra 漏洞 | `zimbra-snmp-rce` |
| Exchange / OWA | `nday_route.py` → 对应 CVE |

## 不要做

- 搭建钓鱼发信基础设施
- 向非授权目标发送伪造邮件
- 网站案中当主链使用
