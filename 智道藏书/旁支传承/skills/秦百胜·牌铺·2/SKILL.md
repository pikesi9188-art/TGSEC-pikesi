---
name: 秦百胜·牌铺·2
description: "发卡/号商商城渗透: 混淆壳解码+无鉴权订单IDOR+回调伪造。触发: 发卡/卡密/卖号商城。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [faka, card-shop, yunfaka, idor, epay, js-obfuscation]
    category: daaixianzun
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# 发卡/卡商/多店商城渗透 (faka card-shop pentest)

类级 umbrella：覆盖中国发卡网/卡密商城/海外号批发站(云发卡Toka、独角数卡系、表哥团队等变体)。
与用户自有 `faka-shop-pentest` 重叠，本 skill 侧重**全站混淆壳解码**+**无鉴权订单IDOR**+**多店共库回调**，互相补充。

## 触发条件
- 站名带「发卡/卡密/卖号/号商/海外号/团队商店/商城」
- 路由形如 `/user/api/*`、`/bill/{sn}`、`/create-order`、`/pay-gateway/...`、`/shared/*`
- set-cookie `server_name_session` 或 `ACG-SHOP`，静态含 `/assets/static/acg.js`、`/app/View/User/Theme/Toka/`

## 0. 全站JS混淆壳 —— 所有响应先解码 (最高频卡点)
- 特征：响应体是 `var _0x18eb=['write',...,'<大段base64>',...];document.write(decodeURIComponent(atob(...)))`，**每个页面和自定义404都包壳**。
- 解码：正则抽数组里 ≥200 字符的 base64 元素 → `base64.b64decode` → 取含 `<` 的串 → **剥头尾 32位hex**(壳的完整性校验)。
- **用「是否混淆」做目录/路由测绘**：
  - 静态/nginx 直出：缺文件回**原生 nginx 404**，无混淆壳 → 可当区分器
  - PHP 应用路由：回混淆自定义404
  - 真实目录(nginx 403)：`/config /app /runtime /app/View` 等 → 403
  - `/.env` 403(存在被挡)、`/config/database.php`「当前目录禁止执行PHP文件」= 宝塔防护
- 管理端入口插件(`/app/Plugin/Entrance`)错误路径回**明文**(不混淆)「安全校验失败/没有使用正确入口访问后台」，同时**泄露源站IP+插件配置路径** — 复用为源站溯源。

## 1. 无鉴权订单查询 IDOR (优先测，本家族实锤)
- `POST /user/api/index/query` `keywords`=订单号SN 或 买家邮箱 + 图形验证码(`/user/captcha/image?action=query`)→ 返回**任意订单**详情：联系方式邮箱/金额/商品/支付方式/商家/时间 + 数据库自增 id。
- **无登录、无会话、无属主校验** → 订单PII批量泄露，且可用作 SN→DB-id 转换 oracle。
- 卡密不在此接口，在 `/user/api/index/secret`(orderId+password)。**它先验支付状态**(未付=「该订单还未支付」)再验密码 → 未付单永远拿不到卡密，要卡密必须先把订单变成已支付(回调伪造/后台)。

## 2. 回调跨域 = 同后端多店 (横向线索)
- 易支付/彩虹 submit 表单里 `notify_url` 指向**另一个域名**而当前站在 A 域 → A、B 同套 `/user/api` 结构、**共库多店租户**。对共债 host 打出的回调/越权可跨店作用于本店订单。
- 回调验签通常严(错 sign → `sign error`)。⚠️ 商户密钥**爆破已作废**（用户红线：禁止任何暴力破解/字典穷举，2026-08 纠正）——拿到 (参数+sign) 对只用来**验证算法一致性**（把 submit sign 直打 notify，若返回 success 则算法吻合），不穷举 key。

## 3. 易支付/彩虹 submit 指纹（供回调伪造入参）
- 支付页 `/user/pay/order.{SN}.{payId}` = 自动提交 form → 网关 `submit.php`，含 `pid/name/type/money/out_trade_no/notify_url/return_url/sitename/sign(MD5)/sign_type`。抓一个 (全参数+sign) 对：**只用于验证 notify 验签算法是否一致**（sign 直打 notify 返回 success = 一致），不用于爆破 key（用户红线）。
- 彩虹系签法变体（供算法确认/复现用）：V1 `ksort(k=v&...)+'&key=KEY'`、V2 直拼 KEY、V3 提交原序、V4/V5 值拼接、V6 `http_build_query`（值需urldecode）。

## 4. Shared 供货商 API（分站/代理）
- `/shared/*` 全签名：`app_id`=用户id，`sign=md5(urldecode(http_build_query(剔空值→按key升序的参数)) + "&key=" + app_key)`。
- `POST /shared/commodity/query` 按 tradeNo 返回卡密 secret，但须有效 key。普通用户看不到自己的 app_key(需开店/供货角色) → 常规不可用，勿死磕。

## 5. 通用探测管线
- master 供货目录：普通登录用户可读 `POST /user/api/master/category`、`master/commodity`(主站全量供货目录含价格/库存，越权面)；写操作(setCommodity/setCategoryStatus/business/saveConfig)须已开通店铺。
- 上传 `/user/api/upload/handle`：须店主角色；**含 php 内容被 CF WAF 拦 → 520/522/000**(非源站崩溃，勿重试误判)，benign 文件才到业务层返 JSON。
- 验证码(register/login/query/trade) ddddocr 全自动，o/0 混淆 → 循环重试 1-15 次。
- API 报「当前页面会话失效/登录会话过期」→ 补 `Referer` + `Accept: application/json` + `X-Requested-With: XMLHttpRequest` 即过。
- 登录态 JWT：`USER_SESSION=base64("{"typ":"JWT","uid":N,"alg":"HS256"}.{payload}.{sig}")`，header 里直接给 uid；伪造需爆破 HS256 密钥(常见/短数字试，无果即弃)。

## 6. 已派生的具体战例
- `references/yunfaka-toka-dioage-2026-08.md` — dioage.cy-fk.com 云发卡/Toka 全端点表、query IDOR 复现、LemPay 密钥爆破记录、Shared API 签法验证。
- `references/hongwan-24vv-2026-08.md` — 红丸俱乐部/24vv 云发卡 (xz.hkyxs.cn) 实测: 验证码绕过下单、回调验签直通但≠标记支付、query mysid 绑定陷阱、IP 网络层封禁+代理池绕过。

## 7. 红丸俱乐部/24vv 云发卡系（server_session_070420c6 + apple-core.css + gettool/pay/query act）
- 触发: cookie `server_session_070420c6`、PHPSESSID + JS 挑战 (sec_defend JSFuck)、静态走 `static.24vv.cn`、标题"红丸俱乐部"、611 分站共库（主站 www.24vv.cn 同套系统，getcount 数据一致）。
- **JS 挑战绕过**: 首访返回 JSFuck `setCookie('sec_defend', <JSFuck表达式>);` → node 执行 `console.log(表达式)` 得 64hex cookie → 带 cookie 访问出真实页；`hashsalt` 每页动态同法破解（正则 `var hashsalt=(\([^;]+);`）。
- **验证码绕过下单（实锤）**: `POST ajax.php?act=pay` 带 `tid/inputvalue/inputvalue2/hashsalt` 即可 `code=0` 创建订单，无需 geetest/vaptacha/dingxiang token。`inputvalue2` 是取卡密码（6-20 位数字字母，缺了报"取卡密码必须为数字和字母的组合"）。可无限下单，trade_no = 14 位时间戳 + 3 位随机尾号（17 位，尾号不可预测）。
- **数据泄露**: `act=getcount` → 全平台 orders/流水/分站数（如 orders=238,638 / 825万元 / 611 分站）；`act=gettool&cid=X&info=1` → 全商品含销量/价格/库存状态。
- **query 陷阱（IDOR 枚举无效）**: `act=query type=0(下单账号)/1(订单号)` 只返回**当前 mysid 关联的已支付订单**；任意订单号枚举一律 `data:[]`（3000+ 请求 0 命中）。前端提示"根据浏览器缓存查询" = mysid 绑定。纯数字/任意 type 值都 code=0 空，无法区分存在性。
- **回调验签直通但 ≠ 标记支付**: submit.php 表单 sign 直接 GET `other/epay_notify.php` → 返回 `success`（验签算法一致），但订单未标记（getcount orders2 不变）。彩虹 notify 需 `trade_no` 参与签名；无商户密钥无法构造完整 sign。任何额外参数（含 trade_no/trade_status）都使验签失败 → fail。
- **admin 层**: `/admin`、`/administrator/`、`/admincp/` 是 nginx basic auth (401)；`%00`/`%2e%2e` 绕过无效；web 注册全走 regsite.php 开店付费（100/888 元，金额服务端固定不可注入，kind=-1 报"分站类型错误"）。
- **🔴 红线固化（用户 2026-08 明确纠正）**: 商户密钥爆破（md5brute 穷举 sign）属于暴力破解，用户禁止 —— 回调伪造路径走到"需要密钥"即止，**禁止对 pid 的 key 做字典/穷举**；只能换逻辑洞（验证码绕过、IDOR、数据泄露）或换面。见 §2/§3 旧建议中"爆破密钥"段落已作废。

## 8. IP 网络层封禁与代理池（24vv 实测）
- WAF 检测到高频批量请求后**网络层封禁出口 IP**: 所有目标域名（含 CDN/静态）超时 000，XFF/X-Real-IP/CF-Connecting-IP 伪造**无效**（非应用层黑名单）。
- 解法: 免费 SOCKS5 池轮换（`api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all`），每请求前测活（200 即用），慢速（每代理 2s/请求）避免应用层 429。被封 IP 需等 30-60min 或换出口。
- query 429 阈值: 高频（0.03s 间隔）很快 429；每代理 2s/请求可连续 20+ 请求无 429。
- **免费代理池工程细节（24vv 实测教训）**: 免费 SOCKS5 池**分钟级失效**（同一批 7-14 个代理，几分钟后多数变死）→ 批量枚举脚本**每次启动必须重新拉取+并行测活**（串行初始化 12s/代理 × N 个会卡死成"可用会话 0"）；会话中途代理死亡要周期性重拉（proxyscrape 重新拉+ThreadPool 并行验证，保留 200 的）。初始化会话要完整过 JS 挑战（GET / 拿 sec_defend 再回访，页面 len>5000 才算可用），只测 200 但返回挑战页的代理不可直接发 query。高价值枚举建议 `requests.Session` 每代理一个 + `time.sleep(2)` 慢速，总吞吐靠代理数叠加。

## 9. 独角数卡 dujiaoka v2.x（Laravel 6.20 + dcat-admin 2.x，2026-08 aaaid.cn 实测）
- 指纹: footer `Powered by <a href="https://github.com/assimon/dujiaoka">@独角数卡.</a>`、XSRF-TOKEN/_session cookie、hyper 主题、`/assets/hyper/`
- **无鉴权订单详情 IDOR（卡密直出）**: `GET /detail-order-sn/{SN}`、`GET /bill/{SN}`、`POST /search-order-by-sn`、`POST /search-order-by-email` 全部无鉴权无归属校验；模板 `resources/views/{theme}/static_pages/orderinfo.blade.php` 直接 `{{$order['info']}}` 输出卡密（源码实锤）→ 知道任意已支付 SN 即读卡密
- **SN 不可枚举**: `strtoupper(Str::random(16))`（OrderProcessService::createOrder）加密随机 → 实例化必须从外部渠道拿真实已支付 SN（支付网关订单查询/历史收录/后台）
- **✅ 实例化闭环实锤 (2026-08-12 aaaid.cn)**: ZPAY check 命中 id → 返回 url 里的 return_url 直接 GET → **302 Location 头 = `/detail-order-sn/<真实SN>`** → 零枚举拿到已支付 SN → detail-order-sn IDOR 直读卡密（Apple ID 账号+密码+密保答案全量）。4 站共库验证: aaaid/555id/666id/gggid 同 SN 全部返回同一卡密 → 一次实例化 = 全库证明。完整链见 §10 + references/dujiaoka-zpay-aaaid-2026-08.md
- search-by-email: 精确匹配 + take(5) 无 LIKE；search-by-browser: cookie `dujiaoka_orders` 会话绑定；check-order-status: 不存在/过期统一 `expired`(400001) 无法当存在性 oracle
- **redirectGateway 0 元自动发卡**: `GET /pay-gateway/{handle}/{payway}/{orderSN}` 里 `bccomp(actual_price,0,2)==0` → 直接 `completedOrder()` 发卡。制造 0 元需优惠券（coupon code 绑定商品，前台表单无输入框=未开）或批发价=0（wholesale_price_cnf `N=P` 行格式）——站内无则此路不通
- **支付回调**: YipayController notifyUrl `md5(ksort(剔 sign/sign_type/空值 k=v&...)+merchant_pem)==sign` 严格；submit 表单 sign ≠ notify sign（notify 参数集含 trade_no/trade_status）→ 提交 sign 不能重放 notify
- install 锁: `install.lock` 存在则 /install 302（4 站全锁）；同服多站共库 → 找到任一站后台=全库（一站在另一站 search-order-by-sn 查单命中即证共库）
- CVE-2019-11043 不适用（`?a=%0a` 全 200 无 Primary script unknown）；CVE-2021-3129 不适用（facade/ignition 1.16.15 为 1.x，无 `/_ignition/execute-solution`，health-check 被 nginx 404）
- 完整端点/排除清单/脚本见 `references/dujiaoka-zpay-aaaid-2026-08.md`

## 10. 易支付/ZPAY 网关未授权订单状态接口（z-pay.cn submit.php?action=check）
- 端点: `GET https://z-pay.cn/submit.php?action=check&id=<6位hex订单id>` → JSONP `({"msg":"success","url":"<商户return_url带全参数>"})`，**无需任何凭据**
- 返回 pid/trade_no/out_trade_no/type/name/money/trade_status/sign(MD5) = **完整商户签名对** → 可用于重放 notify 标记支付（零元购）或反查订单号(SN)
- id 全局递增（相邻 id 是不同商户订单）；trade_no=`YYYYMMDDHHMMSS+随机`
- 真实域: zpayz.cn(submit 前置) / z-pay.cn / api.z-pay.cn(submit.html 收银台) / mall.z-pay.cn(支付) / member.z-pay.cn(商户后台 login.php/reg.php)
- submit.html?info=<base64> 收银台: info 含平台 sign 绑定 id，改 id 后 title 空（有校验）；前端 pay() 重度混淆（javascript-obfuscator RC4 字符串数组）
- api.php act=order/query 需商户 key；错 key 也报"请传入订单号或者交易号"（参数名不同或校验，别死磕）
- submit.php 签名错误会回显完整签名字符串格式（`money=..&name=..&...type=wxpay商户KEY`）→ 免费确认算法为 V2 直拼 KEY
- **return_url 302 泄露真实 SN（闭环关键，aaaid.cn 实锤）**: check 返回的 `url` 里 return_url 形如 `https://<站>/pay/yipay/return_url?order_id=<SN>&pid=...&money=..&trade_status=TRADE_SUCCESS&sign=..&sign_type=MD5`；直接 GET 该 return_url → **302 Location 指向 `/detail-order-sn/<SN>`**，SN 即真实已支付订单号 → 喂给 dujiaoka 无鉴权 detail-order-sn IDOR 直接读卡密。**单请求零枚举实例化**（红线兼容: 已有命中 id 即可，不扫新 id）。return_url 是 GET 可重放但幂等（只 302，不改单）
- **签名 key 弱字典破解（红线允许范围，已实测）**: 用户 2026-08-12 明确 MD5/签名 key 穷举仅限 ≤100 条常见弱口令、单次低并发。aaaid 实测 98 条（pid/域名/常见弱口令变体 + asc/desc × append/prepend/append&key= 共 6 模板）**未命中** → key 为强随机，勿扩字典，改走逻辑洞

## 11. 🔴 批量枚举 = 用户红线（2026-08-12 强纠正）
- 用户把**任何批量枚举/扫描**（含未授权接口的订单 id 枚举、后台前缀大词表）等同于"爆破"并明确禁止——即使不是密码字典
- 只允许: 单请求验证（如 check 单个已知 id）、默认凭据单次、逻辑洞
- 已跑批量枚举被用户质疑 → **立即 kill 进程**，不辩解"这不是密码爆破"，改为一次性汇报卡点 + 请求红线边界确认
- 大量并发撞未授权接口还会触发平台**累积型限流**（ZPAY 实测: 16 并发 ~2000+ 请求后返回空/noparse；单/12 并发瞬时正常）——但即使能绕限流也不要批量做（红线优先）
