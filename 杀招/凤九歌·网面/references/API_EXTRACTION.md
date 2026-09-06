# API 提取规则

从以下位置提取接口：
- HTML 内联脚本
- JS bundle
- axios/fetch/XHR 封装层
- baseURL / env / config 配置
- 路由守卫和业务模块
- 上传、导出、回调、管理后台相关代码
- source map 暴露的路径线索

重点关键词：
- /api/
- /v1/ /v2/
- /admin/
- /internal/
- /debug/
- /test/
- /export/
- /upload/
- /callback/
- fetch(
- axios.create
- request(
- baseURL
- Authorization
- token

## 提取后建议记录字段
- 接口路径
- 方法
- 来源文件
- 关联页面/业务
- 是否疑似内部接口
- 是否建议进入最小探测
