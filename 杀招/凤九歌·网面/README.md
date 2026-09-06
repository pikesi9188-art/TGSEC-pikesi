# web-pentest

版本：**1.2**

这是一个参考 `wechat-miniapp-pentest` 扩展出来的 Web 渗透测试 skill，面向**已授权**的 Web / H5 / SPA 站点测试。

## 核心能力

✅ 前端静态审计（curl 抓页面 / JS / 静态资源）  
✅ JS 文件名称提取与大模型筛选（优先锁定业务功能类 JS）  
✅ 业务功能类 JS 自动下载归档（方便后续 Grep / 审计）  
✅ 接口说明整理  
✅ 最小探测验证（低影响、非破坏性）  
✅ 流量分析与验证  
✅ 敏感信息检测（身份证 / 手机号 / 邮箱 / API / Key）  
✅ 多 Agent 协作  
✅ 父 Agent 复核降误报  

## 输出物

- `网站目录结构.md`
- `接口说明.md`
- `渗透测试-静态分析验证文档.md`
- `渗透测试-流量分析报告.md`
- `敏感信息检测报告.md`

这些输出物现在都有对应模板，能直接套。

## 目录结构

```text
web-pentest/
├── SKILL.md
├── README.md
├── changelog.md
├── agents/
│   ├── coordinator.md
│   ├── frontend-static-auditor.md
│   ├── sensitive-data-detector.md
│   ├── sqli-tester.md
│   ├── auth-logic-tester.md
│   ├── injection-tester.md
│   ├── sensitive-data-validator.md
│   └── traffic-analyzer.md
├── references/
│   ├── API_EXTRACTION.md
│   ├── BUSINESS_LOGIC_HINTS.md
│   ├── FALSE_POSITIVE.md
│   ├── FRONTEND_ENCRYPTION.md
│   ├── MINIMAL_PROBING_RULES.md
│   ├── SENSITIVE_PATTERNS.md
│   ├── TEST_MATRIX.md
│   ├── TRAFFIC_ANALYSIS_GUIDE.md
│   ├── PAYLOAD_LIBRARY.md
│   ├── CURL_EXAMPLES.md
│   ├── SENSITIVE_SAMPLE_CASES.md
│   ├── RISK_RATING.md
│   ├── FINDING_STATUS.md
│   ├── REDACTION_RULES.md
│   ├── REQUEST_RESPONSE_QUOTING.md
│   └── SECRET_PATTERNS.md
├── templates/
│   ├── report_template.md
│   ├── site_structure_template.md
│   ├── api_catalog_template.md
│   ├── static_validation_template.md
│   ├── traffic_report_template.md
│   ├── sensitive_report_template.md
│   └── js_classification_prompt.md
└── tools/
    ├── extract_page_js.py
    └── archive_business_js.py
```

## 执行门禁

开始前必须先确认两件事：
1. 是否已授权
2. 只做代码静态分析、只做流量分析，还是两者都做

如果没有明确确认：
- 不主动发探测请求
- 不做漏洞利用
- 只停留在非侵入性梳理建议

## 父子 Agent 结构

### 父 Agent
`coordinator`
- 负责授权确认、模式确认、任务编排、结果复核、输出汇总

### 子 Agent
- `frontend-static-auditor`：前端静态审计（含 API / Key / Token 线索自动提取）
- `sensitive-data-detector`：敏感信息识别（身份证 / 手机号 / 邮箱 / API / Key）
- `sqli-tester`：SQL 注入最小探测
- `auth-logic-tester`：未授权 / 越权 / 逻辑缺陷探测
- `injection-tester`：命令执行 / SSRF / 文件读取探测
- `sensitive-data-validator`：敏感信息结论复核（含 API / Key 泄漏）
- `traffic-analyzer`：流量分析与验证建议

## 审计与验证流程

1. 先让父 Agent 确认授权和测试模式
2. 静态分析阶段：
   - `frontend-static-auditor`
   - `sensitive-data-detector`
3. 在 `frontend-static-auditor` 内部先完成：
   - `python3 tools/extract_page_js.py <目标页面> -o js_inventory.json`
   - 用 `templates/js_classification_prompt.md` 把 `js_files` 分类为 `business_js` / `vendor_js` / `review_js`
   - `python3 tools/archive_business_js.py js_inventory_classified.json -o audit_js`
4. 父 Agent 复核后，整理：
   - `网站目录结构.md`
   - `接口说明.md`
   - 敏感信息初步线索
5. 最小探测阶段：
   - `sqli-tester`
   - `auth-logic-tester`
   - `injection-tester`
   - `sensitive-data-validator`
6. 父 Agent 再做统一复核，输出：
   - `渗透测试-静态分析验证文档.md`
   - `敏感信息检测报告.md`
7. 如果用户要求流量分析，再交给 `traffic-analyzer`
8. 父 Agent 汇总输出 `渗透测试-流量分析报告.md`

## 设计原则

- 最小探测
- 低频验证
- 低影响
- 非破坏性
- 结论必须有证据
- 父 Agent 必须复核子 Agent 结论，避免直接把子 Agent 输出当最终结论

## 新增补充

### 样例库
- `references/PAYLOAD_LIBRARY.md`
- `references/CURL_EXAMPLES.md`
- `references/SENSITIVE_SAMPLE_CASES.md`

### 正式输出规范
- `references/RISK_RATING.md`
- `references/FINDING_STATUS.md`
- `references/REDACTION_RULES.md`
- `references/REQUEST_RESPONSE_QUOTING.md`
- `references/SECRET_PATTERNS.md`

这些文件主要用来统一：
- 风险等级
- 结论状态
- 敏感信息脱敏方式
- 请求响应摘录方式
- 最小探测样例

### 密钥特征识别
- `references/SECRET_PATTERNS.md`

这个文件专门用来辅助识别：
- JWT
- Bearer Token
- API Key / Secret
- 云服务密钥
- 私钥 / 证书线索
- 占位符与真实疑似密钥的区别
