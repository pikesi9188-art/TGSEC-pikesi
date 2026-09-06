# Secret / Key 特征识别规则

> 用于辅助识别“像密钥的字符串”和“真实疑似密钥”。
> 这里只做识别与归类，不做越界利用。

## 一、通用判断思路

判断一个字符串是否像真实密钥，优先看：
1. 是否出现在初始化代码、请求头构造、SDK 配置中
2. 是否与 `apiKey` / `secret` / `token` / `authorization` 等字段名绑定
3. 是否长度、字符集、前缀特征稳定
4. 是否与第三方服务调用一起出现
5. 是否只是占位符、测试值、demo 值

## 二、常见高关注命名

- apiKey
- appKey
- appSecret
- secretKey
- accessKey
- accessToken
- refreshToken
- clientSecret
- privateKey
- publicKey
- jwt
- bearer
- authorization
- x-api-key
- ak / sk

## 三、常见格式线索

### 1. JWT
典型格式：
- `xxxxx.yyyyy.zzzzz`

判断要点：
- 通常由 3 段 Base64URL 风格字符串组成
- 常与 `Bearer` 一起出现
- 常出现在 `Authorization` 头或本地存储中

### 2. Bearer Token
典型格式：
- `Bearer <长字符串>`

判断要点：
- 常见于请求头构造逻辑
- 如果前端硬编码固定 bearer 值，风险较高

### 3. Base64 / Hex 长串
判断要点：
- 单独出现的长字符串不一定是密钥
- 必须结合变量名、上下文、调用逻辑一起判断
- 仅因为“很长”不能直接下结论

## 四、云服务 / 第三方服务常见线索

### 1. AWS 风格线索
- `AKIA...`
- `aws_access_key_id`
- `aws_secret_access_key`

### 2. 腾讯云 / 阿里云 / 其他云厂商
常见命名：
- `secretId`
- `secretKey`
- `accessKeyId`
- `accessKeySecret`
- `cos` / `oss` / `sts`

### 3. 地图 / 短信 / 推送 / AI / 支付服务
常见命名：
- `mapKey`
- `smsKey`
- `smsSecret`
- `openaiApiKey`
- `paymentKey`
- `merchantKey`
- `clientSecret`

## 五、私钥 / 证书线索

重点关注：
- `-----BEGIN PRIVATE KEY-----`
- `-----BEGIN RSA PRIVATE KEY-----`
- `-----BEGIN EC PRIVATE KEY-----`
- `-----BEGIN CERTIFICATE-----`

判断要点：
- 私钥落在前端通常高风险
- 证书本身不一定敏感，但和私钥同时出现要重点关注

## 六、容易误判的情况

以下内容不要直接判定为真实密钥：
- `demoKey`
- `testKey`
- `your_api_key_here`
- `xxxxxxxx`
- `123456`
- 文档示例中的演示 token
- mock 数据中的假凭证

## 七、报告建议

正式报告里建议记录：
- 位置
- 变量名
- 上下文用途
- 是否硬编码
- 是否疑似真实密钥
- 是否需要服务端迁移
- 脱敏展示值
