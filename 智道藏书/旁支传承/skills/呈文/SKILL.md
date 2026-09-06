---
name: 呈文
description: "生成渗透测试安全报告 — 统一 JSON 数据模型 → Markdown/HTML/Word 三种格式自动出报告。使用场景: 渗透/CTF/红队收尾出报告、SRC 漏洞报告、复测报告。"
version: 1.0.0
created_by: agent
---

# Security Report Templates — 安全报告生成器

渗透测试 / 红队 / CTF 收尾时,把发现整理成 JSON,一键生成专业格式安全报告。

## 触发场景

- 用户说「出报告」「写报告」「生成报告」「交付文档」
- 渗透测试结束后需要正式交付物(MD/HTML/Word/PDF)
- 复测报告、漏洞汇总、SRC 提交

## 快速使用

```bash
# 1. 生成示例报告(三格式全出),看数据模型长啥样
python3 <跨库工具不可用，跳过>/skills/security-report-templates/scripts/security_report_generator.py --sample -o /tmp/report_demo

# 2. 把测试发现整理成 report.json(字段见下方数据模型)
# 3. 一键生成全部格式
python3 <跨库工具不可用，跳过>/skills/security-report-templates/scripts/security_report_generator.py /path/to/report.json -o /path/to/output

# 只出某一种格式
python3 .../security_report_generator.py report.json --md -o out/      # 仅 Markdown
python3 .../security_report_generator.py report.json --html -o out/    # 仅 HTML
python3 .../security_report_generator.py report.json --docx -o out/    # 仅 Word
```

依赖: python-docx(仅 Word 需要, venv 里已装)。HTML 用 Chart.js CDN,需联网渲染。

## 数据模型(JSON)

```json
{
  "report_meta": { "report_id": "REP-2026-001", "client_name": "目标", "tester": "测试人员",
                   "test_start": "2026-08-01", "test_end": "2026-08-02", "classification": "机密" },
  "executive_summary": { "overview": "本次测试共发现 N 个漏洞…", "risk_level": "高危" },
  "scope": {
    "targets": [ {"url": "https://app.example.com", "type": "Web应用", "methodology": "黑盒"} ],
    "out_of_scope": [ {"url": "https://x.example.com", "reason": "第三方"} ]
  },
  "methodology": {
    "standards": ["PTES", "OWASP Testing Guide v4.2", "NIST SP 800-115"],
    "tools": [ {"name": "Nuclei", "version": "3.x", "purpose": "漏洞扫描"} ]
  },
  "systems": [ {"name": "主站", "critical": 1, "high": 2, "medium": 0, "low": 1} ],
  "findings": [
    {
      "id": "VULN-001",
      "title": "SQL注入 - 登录接口",
      "severity": "Critical",                    // 可选,不填则按 cvss_score 自动推断
      "cvss_score": 9.8,
      "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss_version": "3.1",
      "cve_id": "", "cwe_id": "CWE-89",
      "owasp_category": "A03:2021 - Injection",
      "affected_component": "/api/v1/login",
      "vuln_type": "SQL Injection",
      "description": "漏洞描述…",
      "reproduction_steps": ["步骤1", "步骤2"],
      "poc": { "type": "http_request", "content": "POST /api/v1/login HTTP/1.1\n…" },
      "impact": "影响说明",
      "remediation": { "short_term": "临时修复", "long_term": "长期修复",
                       "priority": "P0", "deadline": "24小时内" },
      "references": ["https://…"],
      "retest": { "first_round": {"date": "2026-08-10", "status": "已修复", "note": ""} }
    }
  ]
}
```

**severity 支持**: Critical/High/Medium/Low/Info(或中文 严重/高危/中危/低危/信息)。不填 severity 时按 CVSS 阈值自动映射: 9.0+/7.0+/4.0+/0.1+/0。

## 输出格式说明

| 格式 | 特点 | 适用 |
|---|---|---|
| **Markdown** | 完整章节: 文档控制→执行摘要→范围→漏洞详情→修复汇总→附录; 含风险统计表 | 快速交付 / Typora |
| **HTML** | 侧边栏导航 + 统计卡片 + Chart.js 柱状/饼图 + 漏洞卡片 | 客户演示(浏览器打开) |
| **Word** | python-docx 生成, 封面+表格+颜色标注, 可直接转 PDF | 正式交付 |

Word 转 PDF: `libreoffice --headless --convert-to pdf report.docx`

## 报告写作要点(AI Agent 注意)

1. **漏洞按严重性降序排列**(生成器已自动排序)
2. 每条 finding 必须包含: 描述、复现步骤、影响、修复建议(带优先级 P0-P3 和期限)
3. 复测记录保留,体现闭环
4. 附录自动带免责声明
5. 从渗透现场拿到的数据(URL、payload、响应)直接填入 reproduction_steps / poc.content,不要二次编造

## 参考文件

- `scripts/security_report_generator.py` — 主生成器(JSON→MD/HTML/DOCX, 自包含)
- `scripts/word_report_generator.py` — 原仓库完整版 Word 生成器(样式更丰富, 可替换使用)
- `references/markdown_report_template.md` — 完整 Markdown 模板(含 Mermaid 图表示例)
- `references/html_report_template.html` — 原仓库完整版 HTML 模板(43000 字符, 功能更全)

报告撰写模块（39 模块 09 提取整合）。
