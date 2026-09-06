# 测试矩阵

| 模块 | 检测项 | 优先级 | 子 Agent | 输出位置 |
|------|--------|--------|----------|----------|
| 静态审计 | 接口提取 | P0 | frontend-static-auditor | 接口说明.md |
| 静态审计 | 前端加密识别 | P1 | frontend-static-auditor | 接口说明.md / 静态验证文档 |
| 敏感信息 | 身份证识别 | P0 | sensitive-data-detector | 敏感信息检测报告.md |
| 敏感信息 | 手机号识别 | P0 | sensitive-data-detector | 敏感信息检测报告.md |
| 敏感信息 | 邮箱识别 | P0 | sensitive-data-detector | 敏感信息检测报告.md |
| 验证 | SQL 注入 | P0 | sqli-tester | 静态验证文档 |
| 验证 | 未授权/越权 | P0 | auth-logic-tester | 静态验证文档 |
| 验证 | 命令执行 | P1 | injection-tester | 静态验证文档 |
| 验证 | SSRF | P1 | injection-tester | 静态验证文档 |
| 验证 | 任意文件读取 | P1 | injection-tester | 静态验证文档 |
| 验证 | 逻辑缺陷 | P1 | auth-logic-tester | 静态验证文档 |
| 流量分析 | 鉴权机制 | P0 | traffic-analyzer | 流量分析报告 |
| 流量分析 | 资源归属映射 | P0 | traffic-analyzer | 流量分析报告 |
| 流量分析 | 敏感字段流动 | P0 | traffic-analyzer | 流量分析报告 / 敏感信息报告 |
