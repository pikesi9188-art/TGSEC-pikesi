---
name: 太白云生·血路
description: "TG 博彩盘 USDT/TRX 支付通道 SDK(OkPay/DLPay/KKPay): 签名算法、回调伪造、默认凭证。"
version: 1.0.0
created_by: agent
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG 博彩盘支付通道 (Payment Channel) SDK 渗透

TG 博彩/棋牌/彩票 bot（Qzino 家族等）的充提通道通常对接第三方 USDT/TRX 商户网关：
OkPay(OkayPay, api.okaypay.me)、DLPay(`dlpay_usdt`)、KKPay(`kkpay_usdt`) 等。
用户拿到 SDK 包（官方文档 + PHP/Python/Java 对接代码）时，按本文档快速提取攻击面。

## 典型 SDK 包结构

- 接口文档 .txt/.md（端点、参数、签名示例、回调格式）
- 多语言对接代码（PHP 类 / Python 模块 / Java demo）— **语言间实现差异暴露服务端真实拼串顺序**
- 文档里常有**演示凭证**（如 OkPay `id=1 / token=123456`）— 先试 `/balance` 或任意接口验证是否默认凭证

## 通用端点地图（OkPay 实测，其他通道大同小异）

Base: `https://api.okaypay.me/shop/`，POST form-urlencoded：

| 端点 | 用途 | 关键参数 |
|---|---|---|
| `/payLink` | 创建充值链接 | amount, coin(USDT/TRX), unique_id, return_url, callback_url |
| `/transfer` | 商户转账/提现 | amount, coin, to_user_id(**收款人 TG id**), unique_id, callback_url |
| `/censorUserByTG` | 查 TG 用户是否存在 | telegramID → {exist:bool} |
| `/checkTransfer` / `/checkDeposit` | 查单 | unique_id → {status, amount, to_user_id} |
| `/balance` | 商户余额 | 无参 → {usdt, trx, cny} |
| `/TransactionHistory` / `/checkTransferByTxid` | 账变/链上查单 | 仅部分 SDK 暴露 |

## 签名算法（请求侧 = 回调验签，同一套）

```
1. 参数(含 id) 过滤空值 → 按 key 字典序排序
2. query = urldecode(http_build_query(排序后参数))
   # 编码坑: PHP http_build_query 的 %XX 还原、嵌套字段保持 data[x]=v 中括号、值中 + - 不转义
3. sign = strtoupper(md5(query . '&token=' . TOKEN))
```

- Python 复刻必须自定义 http_build_query：`quote(key, safe='[]')`、`quote(value, safe='+-')`，否则签名对不上。
- **回调验签排序（2026-08 文档向量 95BE540FB7D1996770E2B4CDBC6F184D 实测验证）**：`code` → `data[order_id]` → `data[unique_id]` → `data[pay_user_id]` → `data[amount]` → `data[coin]` → `data[status]` → `data[type]` → `id` → `status`，尾部拼 `&token=<TOKEN>` → MD5 大写。**不是纯 ksort**（ksort 会把 data[amount] 排到 data[coin] 前等，验签不过）；data 内部固定顺序 order_id→unique_id→pay_user_id→amount→coin→status→type。
- 验证方法：文档示例签名当测试向量，对候选排序逐一算 MD5 比对（ksort / Java comparator / 文档展示顺序，三选一必中）；命中的顺序 = 服务端真实拼串顺序，伪造回调工具照抄。
- 文档示例签名可当测试向量验证自己的验签实现（OkPay 示例见 references/okpay-sdk.md）。

## 回调格式与攻击面

```
code=200 & status=success & id=<商户id> & sign=<md5> &
data[order_id]=... & data[unique_id]=... & data[pay_user_id]=<付款人TG id> &
data[amount]=... & data[coin]=USDT & data[status]=1 & data[type]=deposit|withdraw
```

1. **回调伪造（核心洞）** — 验签仅 MD5(参数串+token)。token 泄露/默认凭证 → 伪造
   `type=deposit&status=1&amount=任意&pay_user_id=任意TG id` 给任意用户上分；提现回调伪造成 `status=1` 诱导商户放款。
2. **SDK 验签 bug 放大攻击面（已实测确认）** — 官方 PHP SDK 的 notify() 验签通过后还检查 `code==10000`，而 OKPay 真实回调是 `code=200` → 用官方 SDK 的商户永远进不了「数据正常」分支。上分代码若在分支内 = 商户永不上分（另类 DoS）；若在分支外 = 验签通过即处理。拿到 SDK 先读 notify/checkSign 源码确认上分代码位置。
3. **提现直连 TG 钱包** — `to_user_id` 是 TG id（非链上地址），checkTransfer 响应也带它 → 配合订单数据可横向关联 TG 用户身份。
4. **amount 无上下限校验迹象** — 配合回调伪造可改任意金额。

## 工作流

1. 解压 SDK 包，先读接口文档提取端点表 + 签名示例
2. 对比 PHP/Python/Java 三份实现的签名/拼串差异 → 确定服务端真实排序
3. 用文档示例签名向量验证本地验签脚本
4. 试默认凭证（文档里的 id/token）→ `/balance` 验证
5. 若目标盘对接了该通道：抓它的回调接口 → 伪造回调测试（需授权 scope）

## 已知通道速查（跨会话实测）

| 通道 | 特征 | 备注 |
|---|---|---|
| **OkPay/OkayPay** | `api.okaypay.me/shop/`，演示凭证 `id=1/token=123456` | 全量分析见 `references/okpay-sdk.md` |
| **epay** | Dujiao-Next 实测：盲回调/改价伪造通常不通 | 别耗太久，立刻切别的攻击面（如 guest 弱口令喷射） |
| **dlpay/kkpay/anony** | Qzino 系 TMA 常见：`dlpay_usdt/okpay_usdt/kkpay_usdt/anony`，t.me 支付链接/TRC20 地址 | 结合 telegram-gambling-tma-pentest 使用 |

**经验法则**：第三方通道回调伪造（改价/盲回调）在这类盘上成功率低——先花 10 分钟验证验签是否存在且可破（默认凭证、token 泄露、SDK notify bug），不通就切逻辑洞/弱口令面，不要死磕。

## 轮询查单模式判断（2026-08 实测，8G/kk8 盘）

回调端点枚举全 404 时，平台很可能用 **crontask 轮询 checkDeposit**（无公网回调）：
- /gc 下 500+ 回调路径组合（pay/callback/notify/hook/webhook × okpay/fllpay/okaypay × 各种前缀）全 "404 page not found" → 无回调路由
- 佐证：Go pprof goroutine 泄露 `crontask/usdt.go` 等定时任务；订单状态靠前端轮询 /transaction/record 刷新
- **结论：轮询模式下回调伪造路线直接关闭**，省下枚举时间；商户 token 拿不到也白搭
- 8G 站验证：服务端是自研 Go（kk8/third/okpay/okpay.go CheckCallbackSign），官方 PHP SDK bug 不适用

## 平台侧充值地址模型判定（bfyl/博發 2026-08 实测 — 先判定再定策略）

轮询模式的变体：**不依赖第三方通道 SDK，平台自管 TRON 收款地址**。攻击策略完全取决于地址模型，**10 分钟内必须判定**：

- **同一账号多次下单地址相同 ≠ 全站共享**（bfyl 踩坑：3 单同址以为共享，实际是"每用户固定地址"）
- **判定方法：新注册 1-2 个账号各下一单对比地址**。不同账号地址不同 = 每用户独立模型 → **抢单/金额碰撞/双花策略直接关闭**，别再往链上匹配上花时间
- 若不同账号确实同址（真共享）→ 才测试：同金额双订单并发支付双花、近似金额误匹配、他人入账被同金额待支付订单"抢单"（需真实小额链上转账验证，成本 ~1-2 USDT）
- 链上核验：trongrid `GET /v1/accounts/{addr}` → data 为空 = 地址从未激活（没收到过款）；线下通道给的"地址"甚至可能 base58 校验都不过（`is_address=False`）→ 纯人工通道无链上面
- **每账号同时只能挂 1 笔待支付订单**（"您已有一笔待付款的充值订单"）→ 批量挂单需批量注册账号，且注册有限速（~5 个后 "请求太频繁"）
- 判定"金额匹配"模式的信号：`付款金额必须与订单金额一致` 提示 + 同一账号订单 address 字段重复
- **平台到账确认前不要放弃提现面**：先把提现全链路打通（地址簿 + 安全码 + 2FA），有余额账号一到手即可测提现逻辑（负额/竞态/费率）

## WS/Reverb (soketi) 公共频道数据收割（bfyl 实测 — 高价值数据面）

Laravel 博彩 TMA 常用 soketi/Reverb WS 推实时投注流，**公共频道无需鉴权**：

- 前端 JS 找 `VITE_REVERB_APP_KEY / VITE_REVERB_HOST`（如 ws.soketi.vip 共享租户），连接 `wss://{host}/app/{KEY}?protocol=7&client=js&version=8.4.0&flash=false`
- 频道命名：`game.{gameId}`（全玩家实时投注 userBet 事件：user.id/nickname(脱敏)/投注项金额/每期汇总）+ **`user.{userId}` 竟然也是公共频道（WS IDOR）** → 订阅任意玩家私人通知（充值到账/中奖/提现）
- 动态扩线：从 userBet 事件里提取新 user.id → 自动订阅对应 user.{id} 频道；批量订阅 20-50 个频道无压力
- 配套公共 API 泄露（无 user 过滤）：`GET /api/games/{g}/bets/prev` = 所有用户上期投注+净盈亏；`/api/pc/{g}/history` 开奖历史；`/api/pc/{g}/stats` 遗漏值
- 开奖源：PC28 类 = 加拿大 Bingo 28（20 码取位相加）；`close_advance_seconds` 通常 20s 封盘 → 官方公布 vs 平台封盘时间差需实测才知能否已知结果下注

## Pitfalls

- 文档演示凭证是 id=1/token=123456 这类弱默认值，别忽略——很多商户不换。
- 签名拼串的编码细节（+、[]、urldecode）差一个字符就验签失败，务必用文档示例向量先自测。
- 回调里 `pay_user_id`/`to_user_id` 都是 TG id，这是与链上地址不同的重要特征，用户身份关联的抓手。

## 平台级入口/鉴权陷阱（bfyl 实测补充）

- **X-Device-Id 设备绑定**：Laravel 系盘 token 在注册/登录时绑定 device id——后续请求用别的 device 会返回误导性的 `请求缺少设备ID`（400）。注册/登录时的 device 必须全程复用；SPA 的 device 存 IndexedDB(localforage)，**不在 localStorage**（浏览器里自己也常抓不住，用 XHR hook 抓真实请求头）。
- **CloudFront/WAF 入口**：api 子域默认 403，但**完整 Chrome UA + Origin + Referer + Accept 头**可放行全部 /api/* 路径直达源站 → 路由枚举/隐藏接口探测以此为准；短 UA (curl 默认) 全 403 是踩坑点。
- **安全码 (pin) 前端哈希**：界面输 4~6 位，提交 32 位哈希（非纯 md5(pin)，含盐/算法未知）；**用 API 直接设 md5(pin) 能成功但界面流程永远验不过** → 设置+验证都走浏览器 UI 全流程（或 XHR hook 抓 hash 后复刻）。
- **临时邮箱收验证码**：mail.tm API（`GET /domains` → 注册 → `POST /token` → `GET /messages` 取 6 位码）可完成邮箱绑定/密码重置全链路测试，不要因为没有自己的邮箱放弃这面。

## 详细参考

- `references/okpay-sdk.md` — OkPay/OkayPay 全量端点、签名示例向量、SDK 源码要点（用户提供的 SDK 包分析）
- `references/bfyl-case-2026-08.md` — bfyl/博發娱乐完整打面记录（固定地址充值、CF 绕过、40 端点清单、封闭面清单、**下注/开奖面**：动态路由提取、`{"bets":{"号码":金额}}` 结构、加拿大28开奖时间线、封盘/余额守卫实况）
