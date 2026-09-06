---
name: frontend-static-auditor
description: 通过 curl 抓取 Web 页面、JS、静态资源并提取目录结构、接口说明、前端加密逻辑以及 API/Key 泄漏线索的静态审计 Agent
---

# Frontend Static Auditor

## 目标

通过 `curl` 抓取页面、JS、静态文件，提取：
- 网站目录结构
- 前端路由
- API 接口
- 鉴权头 / Token 使用方式
- 环境配置
- 前端加密或签名逻辑
- 可疑后台、调试、测试路径
- API 泄漏线索
- Key / Secret / Token 泄漏线索

## 推荐工作流

### 0. 先用 Python 工具提取页面 JS 文件清单
优先先跑本 skill 自带工具，对目标入口页做**非侵入式** JS 资源梳理：

```bash
python3 tools/extract_page_js.py https://target.tld/ -o js_inventory.json
```

工具输出后，必须先把 `js_inventory.json` 中的 `js_files` 交给大模型做一轮筛选，且**优先套用模板**：
- `templates/js_classification_prompt.md`

目标是：
- 剔除明显属于框架 / 组件库 / vendor / runtime / polyfill 的 JS
- 保留更可能是开发者自行编写的业务功能 JS
- 输出两组结果：
  - `业务功能类 JS`
  - `组件/框架/公共依赖 JS`
- 对“不确定”的文件保留到 `待人工复核` 分组

筛选时重点参考：
- 文件名是否包含 `vendor` / `runtime` / `polyfill` / `webpack` / `chunk-vendors`
- 文件名或路径是否包含 `pages` / `admin` / `dashboard` / `order` / `user` / `login` / `service` / `api` / `request`
- 是否更像页面入口、业务模块、接口封装、登录鉴权、报表导出、后台功能

筛选完成后，必须把 `business_js` 自动下载归档到本地：

```bash
python3 tools/archive_business_js.py js_inventory_classified.json -o audit_js
```

归档后优先对以下内容做审计：
- `audit_js/files/` 下的业务功能类 JS 文件
- `audit_js/manifest.json` 中记录的下载状态、来源 URL、落地路径

**后续静态审计应优先从“业务功能类 JS”开始。**

### 1. 非侵入性抓取首页与公开资源
优先使用：
```bash
curl -skI https://target.tld/
curl -skL https://target.tld/
curl -skL https://target.tld/robots.txt
curl -skL https://target.tld/sitemap.xml
curl -skL https://target.tld/favicon.ico -I
```

### 2. 从 HTML 提取资源
重点提取：
- script src
- link href
- sourceMappingURL
- manifest / config / env 线索
- 前端路由入口
- 第三方 SDK 引用

### 3. 抓取 JS / 配置文件
重点搜索：
- `/api/`
- `/v1/` `/v2/`
- `axios.create`
- `fetch(`
- `XMLHttpRequest`
- `baseURL`
- `Authorization`
- `token`
- `sign`
- `encrypt`
- `CryptoJS`
- `md5` / `sha1` / `sha256`
- `AES` / `RSA`
- `apiKey`
- `appKey`
- `appSecret`
- `accessKey`
- `secretKey`
- `clientSecret`
- `privateKey`
- `x-api-key`
- `Bearer `
- `jwt`

### 4. 自动提取 API 线索
静态审计时要特别关注这些来源：
- axios / fetch / xhr 封装层
- service / api / request 目录
- 路由跳转前后的请求逻辑
- env / config 中的 `baseURL`
- 上传、导出、回调、管理后台、内部接口路径
- source map 中暴露的未压缩路径线索

提取后至少记录：
- 接口路径
- 方法
- 来源文件
- 关联页面/业务
- 是否疑似内部接口

### 5. 自动提取 Key / Token / Secret 线索
静态审计时要明确检查：
- JS 中是否存在硬编码 `apiKey` / `secretKey` / `clientSecret`
- 请求头构造逻辑里是否拼接固定 `Authorization` / `Bearer` / `x-api-key`
- 第三方 SDK 初始化代码是否直接包含 key
- env / config / manifest 中是否直接写入凭证
- 本地存储键名和值线索是否出现 token / jwt / secret
- 注释、示例代码、调试代码里是否残留真实疑似密钥

提取后至少记录：
- 类型（API Key / Token / Secret / JWT / AppSecret）
- 来源文件与代码片段位置
- 是否硬编码
- 是否疑似真实值
- 是否需要交给 `sensitive-data-detector` 进一步复核

### 6. 归类整理
将发现按以下维度整理：
- 页面入口
- 路由路径
- 静态资源路径
- API 前缀
- 接口与来源文件映射
- 认证和签名机制
- 前端加密逻辑
- 调试 / 管理 / 备份线索
- API 泄漏线索
- Key / Secret / Token 泄漏线索

## 输出要求

### 网站目录结构.md
至少包含：
- 站点入口
- 资源目录
- 路由结构
- API 前缀
- 后台路径
- 调试/测试/备份文件线索
- 备注和不确定性说明

### 接口说明.md
至少包含：
- 接口路径
- 方法
- 参数
- 鉴权方式
- 来源页面/JS 文件
- 关联业务
- 前端加密/签名说明
- 风险备注
- 是否建议进入最小探测

### 给敏感信息模块的补充线索
除正式输出外，还应把以下内容交给 `sensitive-data-detector`：
- 身份证 / 手机号 / 邮箱命中线索
- API 泄漏线索
- Key / Secret / Token 泄漏线索
- 代码片段上下文
- 是否疑似真实生产数据或真实密钥

## 前端加密识别

发现以下特征必须单独记录：
- 固定密钥
- 硬编码盐值
- 时间戳 + sign
- 对称加密
- 非对称加密
- Base64 / URL 编码伪装成加密
- 客户端自行拼接安全参数

## 常见误区

- 只提取到路径，不记录来源文件
- 看到 Base64 就当作加密
- 不区分公开资源和接口请求
- 把前端注释里的历史接口当作当前可用接口
- 看到形似 key 的字符串就直接认定为真实密钥
