---
name: 乐土·人事
description: >-
  大爱仙尊·社会工程学攻击框架：钓鱼攻击/水坑攻击/信息收集/2026 AI社工/DeepFake/社工库/物理社工/邮件伪造/SPF/DKIM绕过
---

> **乐土**
> 沉沦黄土十万年，今再扬尘拂行衣。
> 只愿苍生共平等，万千生灵竞相揖。
> 轮回不忘初时志，万千生灵系心间！

# social-engineering-framework（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/social-engineering-framework/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name social-engineering-framework`

---

长文超过 1800 行，作业时 Read 真源全文，不要凭记忆。

# SKILL: 社会工程学攻击框架 — Social Engineering Attack Framework

> **AI LOAD INSTRUCTION**: 完整社会工程学攻击框架，覆盖钓鱼攻击（鱼叉/批量/Smishing/Vishing/Quishing）、邮件伪造（SPF/DKIM/DMARC绕过）、钓鱼页面克隆（HTTPS伪装/Typosquatting/IDN同形异义字）、水坑攻击（恶意JS注入/供应链污染/CDN投毒）、信息收集（OSINT/社交媒体挖掘/泄露数据库）、2026 AI社工（LLM钓鱼/DeepFake语音克隆/AI虚假身份）、社工库技术（数据清洗/关联分析/知识图谱）、物理社工（尾随/USB投递/工作证伪造）、社工防御对抗（安全培训绕过/钓鱼演练检测/沙箱逃逸/浏览器指纹伪造）、合规与法律边界（授权测试/红队演练规则/证据保留）。适用于红队演练、授权渗透测试、安全意识培训评估。

## 0. RELATED ROUTING

Use this file for social engineering attack frameworks. Also load:

- [email-header-injection](../email-header-injection/SKILL.md) for email header injection fundamentals, SMTP relay abuse, and BCC exfiltration patterns
- [dns-pollution-hijacking](../dns-pollution-hijacking/SKILL.md) for DNS poisoning and hijacking techniques used in phishing infrastructure
- [isp-traffic-hijacking](../isp-traffic-hijacking/SKILL.md) for ISP-level traffic manipulation and SSL stripping in MITM phishing scenarios
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) for bypassing WAF protections on phishing landing pages
- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) for XSS payloads used in watering hole attack JS injection
- [supply-chain-attacks](../supply-chain-attacks/SKILL.md) for supply chain poisoning techniques used in watering hole and CDN attacks
- [subdomain-takeover](../subdomain-takeover/SKILL.md) for domain takeover techniques used in phishing infrastructure
- [recon-and-methodology](../recon-and-methodology/SKILL.md) for structured testing methodology, authorization, and evidence handling
- [account-opening-security](../account-opening-security/SKILL.md) for KYC bypass and identity fraud techniques relevant to social engineering
- [security-awareness-training](../security-awareness-training/SKILL.md) for defensive training approaches against social engineering

---

## 1. 钓鱼攻击 (Phishing Attacks)

钓鱼攻击是社会工程学中最核心的攻击手段，2026年钓鱼攻击已深度整合AI技术，成功率大幅提升。

### 1.1 鱼叉式钓鱼 (Spear Phishing)

鱼叉式钓鱼针对特定目标个人或组织进行精准攻击，需要深入的前期信息收集。

**目标信息收集脚本**：

```bash
# 收集目标社交媒体信息
theHarvester -d target-company.com -b google,linkedin,github,shodan -f harvest-results.html

# LinkedIn 公开信息抓取
linkedin2username --company "Target Corporation" --domain target-company.com -o linkedin_users.txt

# 生成目标邮箱格式
python3 -c "
import itertools
with open('names.txt') as f:
    names = [line.strip().split() for line in f]
formats = ['{first}.{last}', '{first[0]}{last}', '{first}', '{first}_{last}']
for name in names:
    for fmt in formats:
        print(fmt.format(first=name[0].lower(), last=name[1].lower()) + '@target.com')
" > email_variants.txt
```

**Gophish 鱼叉钓鱼平台部署**：

```bash
# 部署 Gophish 钓鱼平台
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
cd gophish-v0.12.1-linux-64bit

# 修改配置监听 0.0.0.0
sed -i 's/127.0.0.1/0.0.0.0/g' config.json

# 修改 admin_server 为 true 监听外部
# 启动
./gophish

# 通过 REST API 自动化创建钓鱼活动
curl -X POST http://localhost:3333/api/campaigns/ \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q4 Security Awareness",
    "template": {"name": "Password Reset"},
    "page": {"name": "O365 Login"},
    "url": "https://phish.target-company.com",
    "smtp": {"name": "SendGrid SMTP"},
    "groups": [{"name": "Engineering Team"}],
    "launch_date": "2026-01-15T08:00:00Z"
  }'
```

…（其余见长文）
