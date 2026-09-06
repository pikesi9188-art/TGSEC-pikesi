# curl 最小探测样例

> 所有请求都应保持低频、低影响、非破坏性。

## 1. 首页与静态资源抓取

```bash
curl -skI https://target.tld/
curl -skL https://target.tld/
curl -skL https://target.tld/robots.txt
curl -skL https://target.tld/sitemap.xml
```

## 2. JS 资源抓取

```bash
curl -skL https://target.tld/static/app.js
curl -skL https://target.tld/assets/index-xxxx.js
```

## 3. 未授权最小探测

```bash
curl -sk 'https://target.tld/api/user/profile'
```

```bash
curl -sk 'https://target.tld/api/user/profile' \
  -H 'Authorization:'
```

## 4. SQL 注入轻量探测

```bash
curl -sk 'https://target.tld/api/search?q=test%27'
```

```bash
curl -sk 'https://target.tld/api/search?q=test%20and%201=1'
```

```bash
curl -sk 'https://target.tld/api/search?q=test%20and%201=2'
```

## 5. 越权 / IDOR 最小探测

```bash
curl -sk 'https://target.tld/api/order/detail?id=1001' \
  -H 'Authorization: Bearer <token>'
```

只替换一个资源 ID 做对比。

## 6. 命令执行过滤探测

```bash
curl -sk 'https://target.tld/api/ping?host=test;'
```

```bash
curl -sk 'https://target.tld/api/ping?host=test%7C'
```

## 7. SSRF 接受性探测

```bash
curl -sk 'https://target.tld/api/fetch?url=https://example.com'
```

```bash
curl -sk 'https://target.tld/api/fetch?url=not-a-url'
```

## 8. 文件读取路径差异探测

```bash
curl -sk 'https://target.tld/api/file?path=../test.txt'
```
