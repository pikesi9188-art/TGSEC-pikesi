---
name: 商心慈·一指
description: "1Z.com 白标博彩家族(xyx776/s09.cc)：qpuserapi 域名指纹、MD5 签名伪造、SVG 点选验证码自破、批量注册 Referer 绕过、充值/提现链、后台弱速率枚举。"
version: 1.0.0
license: MIT
metadata:
    tags: [gambling, 1z, white-label, api, captcha, pentest]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# 1Z.com 白标博彩家族渗透

## 触发指纹
- 目标含 1Z.com / 幸运星娱乐 / xyx776.cc / s09.cc / *-1z.com 白标
- uni-app/Vite SPA + webman(PHP) 后端 + qpuserapi 域名模式
- 点选验证码 (SVG click-captcha)

## 情报概览
- 品牌: 1Z.com N.V. (库拉索 GLH-OCCHKTW0666862027), 前端域随机 (xyx776.cc 等)
- API 域模式: qpuserapi.s09.cc (CNAME → qpgame.syyclv.com → 新加坡)
- 后台: qpadmin.s09.cc (vue3-element-admin, /adminapi/api/v1/), 超管 ht.s09.cc (kangle 3311)
- 支付网关: *.nowtd.com/*.nowkf.com (APISIX + IP白名单), 商户 No.co
- 客服: kxp.dot03cy.xyz (visitor API 未授权)
- 游戏商: B23 平台 (a7mvk21u.com 启动器, mzqyyk.com 游戏源)

## 签名伪造 (关键)
- SECRET: `234fasdkUH%5748` (前端 bundle vS() 函数)
- 算法: 参数排除 sign → 按键排序 → 只拼接值 `v1&v2&...&` → +SECRET → MD5 → 大写
- 固定参数: env=release, chl=zw, plt=web, v=2.3.33, lang=cn, pkg=web, time(秒)
- 密码: 双重MD5 md5(md5(pwd))
- 敏感接口(/api/pay/order等) 加密可选, 明文请求服务端也接受

## 验证码自动破解
1. POST /api/captcha/click {scene: login|register} → token + sequence[{key,text}] + image(SVG)
2. 解析 SVG: `<g><circle cx cy/><text>符号</text></g>` → 图标坐标
3. 按 sequence 顺序收集 points [{x,y}]
4. POST /api/captcha/click_check {token, scene, points} → verify_token
5. 用 verify_token 提交注册/登录 (captcha_verify_token 字段)

## 批量注册 (Referer 绕过)
- 必须带 `Referer: https://xyx776.cc/` + `Origin: https://xyx776.cc` 否则 "当前域名未配置注册入口"
- 参数: {account, pwd(双MD5), nation:86, register_type:0, promo_code, from, sys:web, did, captcha_verify_token}
- 限频: 同IP 3-4个后 "当前网络注册过于频繁" (等窗口)
- 推广绑定: 注册传 promo_code=主账号推广码 → PCode 自动绑定

## 充值下单 (API 明文)
POST /api/pay/order {source:2, payId:68, channelId:wallet_h5, buyType:1, price, gold, recharge_percent_activity_id:0}
- 最低 100元人民币 / 50 USDT (id=103 usdt_pay)
- 返回 url: https://*.nowtd.com/scanPay?params=<订单号>
- 金额校验: price 服务端校验, gold 篡改无效, 不同金额不同订单

## 提现链
1. init_bank_passwd {uid, lgtm, pwd(6位), login_pwd(双MD5)} → pay_pwd_set=1
2. transfer/add_account {type:3, account(USDT地址), account_name, bank, open_bank}
3. bank/coin 提现 → 风控: 首次需累计充值10元
4. 提现通道: USDT TRC20 (费率2%, 500-50000)

## 其他接口
- /api/pay/channel → 29通道配置 (费率/限额)
- /api/pay/recharge-percent-options → 优惠活动 (首存100%, 可提588, 审核2x)
- /api/game/game_index_v2 → 游戏列表 (未授权)
- /api/game/entergame → 游戏URL+ot令牌 (B23平台)
- /api/exchangeCode/use_code → 兑换码 (无限流, 需TG频道获取)
- /api/captcha/click 验证码响应含 sequence → 可全自动
- 客服: /api/chat/visitor/chatStart 无认证创建会话, channelInfo 泄露 tenantId

## 后台 (qpadmin.s09.cc)
- 正确前缀 /adminapi/api/v1/ (POST /api/v1/ 会 405 nginx)
- 登录: FormData {username, password, google_code, verifyCodeKey, verifyCode} (multipart/form-data)
- 返回: {tokenType, accessToken} (Bearer)
- 用户枚举: superadmin 存在 ("用户名或密码错误" vs "不存在")
- 限流: 2次/窗口 (IP维度, XFF无效), 需慢速爆破 3min/个
- 无验证码接口 (verifyCode 前端模板残留)

## Pitfalls
- 前端域随机 (xyx776.cc 只是当前入口), FOFA 用 cert="1z.com" 找全族
- qpadmin 后台 POST /adminapi/api/v1/ 前缀, 其他路径 405/404
- ht.s09.cc HTTPS 握手成功但不响应 (IP白名单静默丢弃), kangle 3311 同理
- 支付网关 IP白名单用真实socket IP, XFF/Client-IP 无效
- nkrl.viky.u9pic-1z.com 是独立平台(U9彩票) 需RSA+AES签名, 不同代码
- 兑换码规则: 888彩金/封顶102/需充值100激活, 平台禁止自动化(风控红线)
- 批量注册限频: 同IP 3-4个/窗口

## 变现路径 (已验证)
批量注册(自动验证码) → promo_code挂主账号 → 充值100(+2%+首存100%) → 提现密码+USDT绑定 → 提现

## 真源

- 手法：`传承/凤九歌·认族.md`
- 工具：`python3 炼蛊房/gambling_family_probe.py --family 1z --base https://授权站 --case <案卷>`
