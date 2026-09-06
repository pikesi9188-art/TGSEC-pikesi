# 发卡平台 AES-CBC + MD5 签名 API 逆向（guanhai.one 实战）

目标：guanhai.one 观海号铺（多租户 SaaS 发卡平台 v5.0.34，商户1207），后端 Swoole + nginx，支付走鲨鱼支付。

## 前端加密逆向（从 util.js）
- **Secret 生成**：`MD5(当前毫秒时间戳)`，作为请求头 `Secret`，且是 AES key/iv 来源
- **AES-128-CBC 加密**：key = iv = Secret 前16字符（Utf8.parse），加密 JSON body 后 base64
- **Signature 签名**：`MD5(ksort参数拼成 k=v&k=v 去尾& + "&key=" + Secret)`，作为请求头 `Signature`
- 请求头三件套：`Content-Type: text/plain` + `Secret` + `Signature`
- 响应也用响应头 `Secret` 前16字符做 AES key 解密 body

## Python 客户端核心
```python
secret = md5(str(int(time.time()*1000)))           # 每次请求新 Secret
payload = encrypt(json.dumps(data), secret[:16])   # AES-CBC
sign = md5(ksort_string(data) + "&key=" + secret)  # 签名
# POST 明文 payload + Secret + Signature 头
# 响应: decrypt(r.text, r.headers['Secret'][:16])
```

## 利用链（注册→订单→支付页→回调）
1. **注册**：`POST /register` {username,password,password_re} → 返回 token（JWT）
2. **登录**：`POST /login` → token，用于后续请求 Authorization: Bearer
3. **创建订单**：`POST /user/recharge/trade` {amount:"0"} → 返回 trade_no
   - amount 支持字符串格式，`"0"` 能过校验（0元订单）
   - 但支付页把 0 元提到最低 0.01 元（服务端有下限保护）
4. **拿支付 URL**：`POST /pay` {trade_no, method:"11"(支付方式ID), balance:0} → pay_url
   - 支付方式 ID 从 /user/trade/order 页面 data-payId 提取（11/12/41 等）
5. **支付页**：GET /pay.{trade_no}（需登录 session）→ 返回提交到 pay.shayu.my 的 form
   - 泄露：pid=1000、notify_url=http://64.118.129.183:8912/pay/async.{trade_no}、sign
6. **回调伪造**：POST 到 notify_url 返回 `{"code":0,"msg":"回调参数错误!"}` = 验签严格，需要商户 KEY

## 关键坑
- 支付页 /pay.{trade_no} 需要登录态，匿名访问返回"服务器出现错误"（Swoole 错误页）
- /user/personal/info 泄露当前用户 password(SHA1)+salt+app_key，JWT 签名密钥 = 用户密码哈希
- 用户枚举：登录接口 "密码错误"=用户存在，"用户不存在"=无此用户，且无速率限制
- 支付方式 ID 必须匹配订单（method=12 报"订单状态异常"= 该订单已用 method=11 生成过支付页）
