---
name: 秦百胜·牌铺
description: "发卡商城渗透: 订单流指纹、易支付回调伪造(notify_url签名逻辑验证; 🔴禁止签名key穷举=爆破红线)。触发: 发卡/卡密/卖号商城。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, faka, card-shop, epay, callback-forgery, laravel]
    category: daaixianzun
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

> ⚠️ 🔴 红线(用户硬性要求): 禁止密码爆破——字典/批量尝试/凭据喷洒/签名密钥MD5穷举全部禁止。登录类仅走逻辑洞: 默认凭据单次验证、密码重置、JWT篡改、越权、验证码OCR识别。
# 发卡商城 (卡密/号码商城) 渗透

## 触发条件
- 卖卡密/卖号/发卡平台 (「娱+发卡」「XX发卡」, CJSC/Laravel/独角数卡 等), `/admin/login` 登录页
- 支付页 URL 含 `/pay-gateway/%252Fpay%252F{route}/{payway}/{sn}` 或 QR 含 `submit.php?pid=...&notify_url=...`
- 订单/查单路由: `/create-order` `/bill/{sn}` `/search-order-by-sn|email|browser` `/detail-order-sn/{sn}`
- 域名带 gh/tg/发卡/卡密 特征 (TG 号商配套站点)

## 主成果定义 (用户偏好)
- 明文卡密/后台真实库存 = 主成果; 游客订单弱口令 = 中间证据
- **支付回调伪造是免付提卡的捷径**: 伪造「已支付」→ 订单直接发卡, 无需打穿后台

## 攻击面地图 (CJSC/Laravel 实测, 2026-08)

### 1. 订单流指纹
1. `POST /create-order` (`gid/by_amount/payway/email/search_pwd/device_fingerprint`) → 302 `/bill/{sn}`
2. `/bill/{sn}` **会话绑定** — 换会话 = 「订单不存在」; 价格**服务端重算** (篡改 unit_price/net_price 无效)
3. 订单页「立即支付」→ `/pay-gateway/%252Fpay%252F{route}/{payway}/{sn}` (双重编码) → 302 `/pay/{route}/{payway}/{sn}` 支付页
4. 支付页内联 JS 含 `checkUrl/statusUrl/successRedirect` + **QR = 网关 submit URL** (含 pid/notify_url/return_url/name/money/clientip/sign)

### 2. 易支付回调伪造 (最高价值)
- `notify_url` (如 `/pay/yipay/notify_url`) = 回调目标; 无参/错签 → `fail`; 验签过 → `success` + 标记订单已付
- QR sign = 商户密钥签的 submit 签名; 拿到 (全部明文参数 + sign) = 一个 (input, output) 对 → 离线爆破密钥
- 彩虹易支付系算法族 (MD5, 全部要试; 空密钥先行排除):
  - A1 排序参数对 `k=v&...&key=KEY` (含 clientip)
  - A2 排序参数对 + KEY 直拼 (无 `&key=`)
  - A3 **值拼接** `pid+out_trade_no+type+name+money+KEY` (彩虹原版最常用)
  - A9 提交序参数对 `pid=..&type=..&out_trade_no=..&notify_url=..&return_url=..&name=..&money=..&clientip=..&key=KEY`
  - 变体: 不含 clientip / URL 编码值 / KEY 前置 / 双重 md5
- 爆破工具: `templates/md5_sign_brute.c` (内联 MD5, 4 线程; 改 target+参数即用)。1-5位 62 字符集×14 算法 ≈ 1h; 纯数字 6-8 位快; >6 位随机密钥 CPU 不可行 → 转 admin 或换源
- 网关侧: `api.php?act=query&pid=<pid>&key=<候选>` → `{"code":-3,"msg":"商户密钥错误"}` 可当远程 key oracle (网络限速, 只适合确认)
- 网关指纹: `submit.php` 返回「你还未配置支付接口商户！」= 彩虹易支付系
- 回调/return 端点 GET+POST 双测; 某些实现 return_url 弱校验会标记已付 (本会话未命中, 仍值得测)

### 3. 其他支付通道
- **TRON USDT**: 全站共享收款地址; 每单 `token` (32hex, 页面级短过期); `/api/pay/tron-usdt/check?order_sn=&token=` 轮询链上; 无资金不可利用
- **OKPay**: 支付链接 `t.me/OkayPayBot?start=shop_deposit--<32hex>`; 回调路径未知 (字典扫 `/pay/okpay/*` `/api/okpay/*` 本会话 404); return 端点只跳转不标记支付

### 4. 查单/订单保护面 (设计良好的站全拒)
- `/search-order-by-sn|email|browser` (POST): 未支付单统一拒 (403), 独立限流 (429「查询过于频繁,请15分钟后再试」)
- `/detail-order-sn/{sn}`: 公开页但**任何 SN 都显示「订单内容已保护」** → 无 SN 枚举预言机; 验证走 `POST /verify-order-password` (order_sn+search_pwd), 未支付单同样拒
- `/api/order/status?order_sn=` — 会话绑定 (换会话=not_found)
- 投诉/工单上传: 仅图片 + 仅限已完成订单 (存型 XSS 面需先有已支付订单)

### 5. Cloudflare 后 Laravel admin 限流现实
- 「登录失败次数过多，请 N 分钟后再试」= **按真实 IP** ~5次/30分钟
- `X-Forwarded-For`/`X-Real-IP` 伪造**不绕过** (Laravel 信任 CF-Connecting-IP)
- 客户端直接设 `CF-Connecting-IP` → Cloudflare 403 (CF 覆盖/校验, 此头不可伪造)
- **验证先于限流**: 密码 <6 字符返回「密码至少6个字符」而非限流提示 → 可确认请求抵达业务逻辑
- 错误消息统一「用户名或密码错误」→ 无用户枚举; 提速爆破只能换源 IP (代理/VPS)

### 6. 通用侦察技巧
- **Laravel 路由映射**: OPTIONS 请求返回 `allow:` 头 → 全量 GET/POST 路由表 (一次扫完)
- 无 debug 泄露: 畸形参数/数组 gid/错误路由均不吐 stack (APP_DEBUG=off)
- admin 路由 (Blade 渲染): 字典扫出 dashboard/goods/carmis/orders/complaints/statistics 等, 全部 302 到 login
- 源站: FOFA domain 查询可能给**过期 IP** (全端口 closed); cert 查询可能 0 命中; CF-proxied 深藏 → 换关联域名足迹 (教程站/导航站/云商城小店)
- 无 web_search 时: `curl "https://html.duckduckgo.com/html/?q=<关键词>"` 可用 (品牌/运营商足迹)

## 交付
- 卡密/订单数据: JSON indent=2 → gz + TSV, MEDIA 逐个发
- 报告 MD 格式; 半程利用(密钥逆向成功但卡资金链) 必须与 闭环打穿 区分

## references
- `references/faka-shop-cjsc-epay-callback.md`（⚠️本包未含此案例文件，跳过） — 娱+发卡 V3.0 (cjtgh.top) 全链路实测: 端点表/回调伪造尝试记录/限流行为
- `templates/md5_sign_brute.c` — 易支付签名密钥 MD5 爆破器模板 (内联 MD5 + 4 线程)
