---
name: 单页·内府
description: "SPA+API: fallback discrimination, bundle mining, BOLA."
version: 1.0.0
author: curator
license: MIT
platforms: [linux]
metadata:
    tags: [pentest, spa, angular, bola, idor, api]
    category: daaixianzun
---
# SPA + Backend API 渗透方法论（同源壳判别 / 端点挖掘 / BOLA 验证）

适用于：Angular/React/Vue SPA 与后端 API 同域或同 CDN（Cloudflare→CloudFront→S3 / WP 等），常见于交易平台、白标 SaaS、fintech。会话案例见 `references/tradesai-case.md`（⚠️本包未含此案例文件，跳过）（⚠️本包未含此案例文件，跳过）。

## 1. 同源 SPA 壳判别（找真实 API 路由）

SPA 有 catch-all 路由时，**未路由到后端的路径全部返回 index.html**（200、几十 KB、含 `<!DOCTYPE html>` / `<base href="/">` / `data-critters-container`）。判别法：

- 批量探测路径，按响应体含 `<!DOCTYPE` 或 `<html` 过滤 → 剩下的（空 401 / JSON 400 校验 / JSON 200 / 503）才是真实后端端点
- `/api/health` 返回 **503** 而其余全 200 HTML = 后端存在（路由打到但节点异常）→ 证明 API 在同域后面
- `Accept: application/json` 头不足以绕过壳，按响应体判别才是正解
- 前端 bundle 里出现的 `apiUrl`（如 `https://studio.trades.ai/api/v1`）是 API base 的第一手证据

## 2. Angular main.js 端点挖掘（grep 模板）

下载 `main-*.js` / `scripts-*.js` 后：

```bash
grep -oE '\$\{Zt\.apiUrl\}/[a-zA-Z0-9_/\-\.\$\{]*' main.js | sort -u        # 全部 API 路径（template literal）
grep -oE 'this\.[a-zA-Z]+Url=`\$\{Zt\.apiUrl\}/[^`]*`' main.js | sort -u    # URL 常量赋值
grep -oE '(get|post|put|delete)\(`?\$\{this\.(baseUrl|apiUrl)\}[^`)]{0,80}' main.js | sort -u
grep -oE '"[a-zA-Z0-9_/]{2,40}"' main.js | sort -u | grep -iE 'hub|wallet|auth|bot|trade|admin|connection'
```

顺序：先找 `{production:!0,apiUrl:"..."}` 配置对象拿 base → 挖子路径（`/Bots/${t}`、`/UserConnections/${t}` 等）→ 对每个端点带 JWT 探测状态码。前端还暴露**路由级敏感面**：`/admin/users`、`/admin/system-stats`、`/admin/financial-report` 等即后台功能清单。

## 3. 客户端 AES "ID 加密" = 纯混淆（别被骗）

JS 里硬编码 key/salt（如 `PBKDF2("TRADESAIHASH_KEY","salt1234",1000,SHA256)` + AES-CBC）对 ID 做"加密"：

- **关键验证：API 是否接受明文 ID**。接受 → 混淆零安全价值（报 Info/Low），顺序 ID 照常枚举
- 不用花时间"破解"它；直接测原始 ID 即可
- 报告里明确：硬编码密钥混淆不是防护，是观感工程

## 4. mail.tm 注册 .NET API 确认邮箱坑

- 确认邮件链接是 fragment：`https://host/confirm_email#token=<b64>&email=<b64>`
- 调 `confirmemail` 时 **`email` 参数传 base64 编码邮箱**（不是解码地址！解码版 500，base64 版 200 返回 accessToken+refreshToken）
- token 含 `+`/`/`，用 requests `params=` 自动编码
- 多封 Confirm Email（同 subject "Confirm Email"）→ 按 `to` 收件地址匹配，别只看 subject

## 5. 双账号 BOLA/IDOR 验证方法论

1. 注册 User A + User B（mail.tm 邮箱，走完确认）
2. 用 A 建测试数据（portfolio/bot/connection），B 的 token 跨账号读 → 干净的水平越权 PoC
3. 无归属校验判定：`GET /UserConnections/{id}` 任意 id 返回 200+凭据 = BOLA 实锤
4. **结构确认法**：枚举时只记录字段名/连接类型/accountName，值脱敏——证明影响范围但不批量落真实数据
5. 顺序 ID 枚举面：JWT `nameid`（用户）、portfolio id、connection id、bot id 全顺序 → 枚举起点即攻击面

## 6. 公开 vs 私有对象判别（防误报）

- `isPublished:true` 的资源对任意登录用户可见 = **市场公开（by design），不是 IDOR**——先对比 `/Marketplace` 类公开端点确认
- 私有对象对非属主返回 500/403 = 该端点有归属校验
- **真正放大器**：公开对象响应泄露内部 ID（bot 详情含 `userConnection.id` + `accountName`）→ 用该 ID 打私有凭据端点。公开→私有 ID 桥接是这类平台最常见的 BOLA 放大链

## 常见防御已验（别重复打）

- `/Portfolios/{id}` 有归属校验（跨账号 404/壳）
- 未发布 bot 500 保护
- JWT alg=none 拒绝 / 弱密钥爆破失败（HS256 正常签名）
- Swagger/OpenAPI 被 SPA 壳吞掉（89KB HTML）→ 不可达即无泄露
- 连接创建时对交易所 API key 做外部校验（假 key → 500）→ 无法用假数据建 Bybit/Binance 连接，改用无需外部校验的类型（TradeLocker/Telegram）或直接测读端点

## 交付

- findings 落地 evidence/；报告 MD（MEDIA 交付）；红队式输出：漏洞 + PoC 步骤 + CVSS + 修复建议
- 敏感数据边界：PoC 用自建账号 + 最小样本，结构确认不批量收割真实用户数据

## 参考

- `references/tradesai-case.md`（⚠️本包未含此案例文件，跳过）（⚠️本包未含此案例文件，跳过） — TradesAI 完整案例（端点表、IDOR 链、AES 混淆细节）
