---
name: 马鸿运·影交易
description: "量化/跟单平台渗透: admin=user同表、XFF绕限速、webhook策略枚举。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, quant, copy-trading, nodejs, express]
    category: daaixianzun
---

> **马鸿运**
> 鸿运加身命难收，杀机扑面运来救。
> 北原少年福如海，气运比刀更温柔。

# 量化跟单平台渗透 (Copy-Trading / Quant Platform)

## 触发条件
- 目标为「量化跟单平台」(果仁量化/EasyQuant类): 用户绑交易所 API Key+Secret 跟单策略
- 指纹特征: Vue3 SPA + Express API (`X-Powered-By: Express`)、`/v1/quant/*` 路由、JWT cookie (`quant_user_token`)、admin 后台 `/GrenLh...` 自定义前缀
- 用户目标词汇: 「用户公钥私钥/API Key Secret/跟单/策略订阅/VIP」→ 目标数据 = 全站用户绑定的**交易所 API Key + Secret** (存 DB api_keys 表, 常规接口只返回 masked)

## 核心认知(本类平台通用)
1. **admin 与 user 同表**: `/api/admin/login` 校验的就是 users 表的 username+password, 只是多检查 `isAdmin` 字段。用自己注册的账号密码调 admin login 返回 `"Forbidden: User is not an admin"`(密码已通过), 不存在的用户/错密码返回 `"Invalid credentials"` → **admin 凭证=user 表密码, 无独立账号体系**。
2. **目标数据只在 admin 或 DB**: 用户侧 `GET /api/v1/quant/api-keys` 永远返回 `apiKeyMasked`(`PROB***_123`), 完整 secret 只在 admin users 详情或 PostgreSQL 里。
3. **注册提权字段全部失效**: `isAdmin/role/userType/roles` 等注册参数会被剥掉(部分触发 500)——不要浪费时间。
4. **mock/real 双实例常见**: 一个端口自称 `mock-api`(不真发邮件、可能不禁限速), 另一个端口 8080 等是真实实例。FOFA 抓到过 API 但 curl 不通 = 防火墙按源 IP 过滤, 时机性重试。

## 侦察与枚举(已实战验证)
1. **API 根即宝藏**: `curl <ip>:<port>/` → JSON 常直接暴露 `service`, `adminConsole` URL, `healthz` 路径。admin 入口 `https://site/GrenLhadmin/login` 就从这里来。
2. **Express 三态路由指纹**: 404=`Cannot GET /...`(无此路由), 401=`Unauthorized: No token provided`(有路由+需鉴权), 403=`Forbidden: admin required`(鉴权过了但非 admin)。**用 404/401/403 三分法区分路由存在性**。
3. **未授权用户枚举**: `GET /api/register/invite-preview?inviteCode=X` 无鉴权返回 inviter 的 `userId/username/inviteCode`; 注册接口 `username already exists` 可枚举已存在账号。系统 seed 账号常为: admin/root/administrator/guoren/operator/manager/superadmin/system/品牌名。
4. **webhook 枚举 oracle**: `POST /api/webhook/trade` 无鉴权。`strategy_id="17 "`(**带尾空格**)通过类型转换 → 「策略 ID 无效」vs「Webhook 密钥校验失败」二分策略存在性; `strategy_id=shortCode`(大小写不敏感)也被接受。但 **secret 不可从公开字段(shortCode/uuid/internalName/日期 hash)推导**。
5. **webhookTradeId = shortCode(5位大写字母数字)**: 策略列表字段 `webhookTradeId` 与 `shortCode` 相同值(如 `1MVS3`), webhook 端点直接接受 `trade_id=shortCode` 定位策略(无需 strategy_id) → 完整 TradingView 格式: `{"trade_id":shortCode,"type":"order","strategy_secret":"x","ticker":"BTCUSDT.P"或"BTC.P","action":"buy","market_position":"long","custom_message":"open_long|止损:64000|止盈:66000"}`。**secret 字段名可配置**: 实测 `strategy_secret`/`secret`/`token`/`webhook_secret` 均被读取(报「校验失败」), `key`/`auth` 不识别(报「缺少字段」) → 用字段名差异确认配置。
6. **XFF 绕限速**: 登录接口 429 带 `retryAfterSeconds`, 加 `X-Forwarded-For: <随机IP>` + `X-Real-IP` 可绕过(按真实 IP 计数)。**⚠️ 只用于少量逻辑验证, 用户喊「别爆破」立即停全部枚举**。
7. **邮箱枚举不可行**: forgot-password 对任意 email 返回统一「已发送」; mock 实例不真发邮件(mail.tm 收不到), 重置 token 不可拿。
8. **CORS 严格**: 任意 Origin 不回显, 凭据模式无用, 不靠 CORS 偷 admin token。
9. **FOFA 兄弟证书发现**: `cert="<domain>"` 查询可发现同证书的其他 IP(实测找到 `134.122.140.179`, 与 jieshouxinhao 一样是 Windows RDP 3389, 响应指纹 `030000130ed0...` 一致 = 同模板管理)。此类 RDP 主机 protocol=2(CredSSP/NLA), 不能离线抓 hash; 仅作兄弟资产记录, 不当活攻击面。

## 攻击面清单(按优先级)
- **免认证交易全量泄露(必测)**: `GET /api/v1/quant/masters/{id}/trade-dashboard` 与 `/strategies/{id}/trade-dashboard` **无需任何 token**, 且支持 `?page=&pageSize=` 分页拖全量交易记录(单个 master 可 9337+ 条, 4MB+)。字段: symbol/side/entry/exit/quantity/positionValue/netPnl/traceId/动态杠杆/`source:"live_webhook"` 真实信号单。**userId 常被清洗为 null/0, apiKeyId 同样, 密钥不带出** — 高价值信息泄露 + 策略/信号行为分析, 但≠ get secret。证据落盘 JSON 即可交差。
- admin 端点全 `403 admin required` → 门 = admin 密码(user 表密码)/DB。
- 提现/佣金: `POST /api/v1/quant/referral/withdrawals` 有余额校验(金额>0, 余额≥0), 竞态/负值/精度均被挡, 但**风控参数泄露**(minWithdrawalUsdt、maxDailyRequests、白名单)有参考价值。
- VIP/订阅: `POST /api/v1/quant/vip/purchase` 创建订单需人工审查, `selfServicePaid` 不会自动激活。
- webhook 无鉴权注入交易: 拿到任意策略 secret = 可伪造信号, 但 secret 只能 admin 生成。
- **testApiKey = 服务端真实外呼交易所**: `POST /api/v1/quant/api-keys/{id}/test` 响应用真实明文 secret 请求 OKX(`"OKX 请求失败: HTTP 401"` 证明), 响应含 `viaRelay` 字段 → 为改 key 前 SSRF/中继探测保留现场。
- 策略/大师详情、simulator 回测接口均只返回公开数据, 无用户 PII。

## Pitfalls
- 用户喊「先发数据」= 立即停攻击扩展, 优先打包已提取数据交付(JSON/CSV/tar.gz + 统计摘要), 再继续深挖。
- **交付格式(用户反馈「乱码」)**: 聊天正文用纯文本 bullet, 少用大表格; MD/数据文件用 MEDIA 发干净文件; **严禁把 read_file 带行号输出直接贴聊天**(用户看到"1|# ..."即乱码)。数据交付物: 全量 JSON + 精简 CSV(关键字段) + 打包 tar.gz + 统计摘要。
- 用户喊「别爆破」= 立即 kill 全部爆破进程(pkill -f admin_brute), 之后禁止任何密码枚举, 哪怕只猜 10 个品牌密码。只打逻辑洞: IDOR/参数越权/路径绕过(大小写、`.`、`//`、尾斜杠)/方法覆盖(`X-HTTP-Method-Override`)/注册提权。若全部硬墙, 诚实交底: 需要用户点头才继续 admin 密码路。
- 不要浪费时间: JWT alg=none/空密钥/公钥混淆(签名验证严格)、注册字段注入、CORS、NoSQL 注入。
- 8080 这类被防火墙过滤的端口要结合 FOFA 历史证据, 标注「曾出现但不能再访问」, 不当活攻击面。

## References
- `references/grlh-quant-case.md` — 果仁量化(guorenlianghua.com)实战细节: API全端点图、枚举确认的系统用户、请求响应样例、绑定 api-key 字段、admin 端点矩阵。