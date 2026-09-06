# 敏感信息识别规则

## 1. 身份证

可识别：
- 18 位身份证
- 15 位老身份证（低优先级）

识别注意：
- 结合上下文判断是否为演示数据
- 如可行，检查出生日期片段和校验位合理性

## 2. 手机号

优先识别中国大陆手机号：
- 1[3-9]XXXXXXXXX

识别注意：
- 避免把订单号、流水号误判为手机号
- 观察上下文字段名：mobile、phone、tel、contact

## 3. 邮箱

识别常规邮箱格式：
- name@example.com

识别注意：
- 区分演示邮箱、测试邮箱、公司真实邮箱
- 结合字段名与使用场景判断风险

## 4. API 泄漏

重点识别：
- /api/
- /admin/
- /internal/
- /debug/
- /test/
- /export/
- /upload/
- /callback/

识别注意：
- 不要把注释中的废弃路径直接当成真实接口
- 优先确认是否被代码调用、拼接或配置引用
- 优先关注后台、调试、内部接口、回调接口

## 5. Key / Secret 泄漏

重点关键词：
- apiKey
- appKey
- appSecret
- accessKey
- secretKey
- clientSecret
- token
- bearer
- jwt
- x-api-key
- privateKey
- authorization

识别注意：
- 不要把占位符、demoKey、testKey 直接当生产密钥
- 结合初始化代码、请求头构造、第三方 SDK 调用一起判断
- 正式报告中默认脱敏展示
- 若位于请求头拼接逻辑中，风险通常高于普通注释残留
