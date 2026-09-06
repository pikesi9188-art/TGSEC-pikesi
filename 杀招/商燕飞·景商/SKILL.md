---
name: 商燕飞·景商
description: >-
  大爱仙尊·鲸商城PRO（jingsoft）发卡平台渗透手册。应对云月/秋月系自动发卡平台，商家后台/支付/邀请码注册/未授权接口。
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# jingsoft-merchant-platform（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/jingsoft-merchant-platform/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name jingsoft-merchant-platform`

---

# 鲸商城PRO（jingsoft）发卡平台渗透手册

> 遇到"云月商城/自动发卡平台"类目标（前端 console 泄露 `Design with by 鲸商城PRO【全新版】 https://www.jingsoft.com`）时按此手册打。这是商业发卡源码，前端 SPA + 商家后台分离，有大量可枚举 API。

## 目标判定（指纹）

```js
// merchant 后台 JS 的 console.log 泄露：
"Design with by 鲸商城PRO【全新版】 https://www.jingsoft.com"
// 技术栈：ThinkPHP + Vue3 SPA (Arco Design) + Cloudflare
// 前端资源路径：/package/shop/assets/*.js（店铺端）、/package/merchant/assets/*.js（商家端）
// 支付：对接彩虹易支付（epay.*.cn），getUserChannel 返回 Yipay/USDT/TRX/OKPAY
```

## 资产结构

| 入口 | 路径 | 说明 |
|------|------|------|
| 店铺端 SPA | `/shop/<token>` | 买家看商品/下单，token 公开（如 WMWY） |
| 商家后台 SPA | `/merchant/login` | 商家登录，JS: `/package/merchant/assets/index.*.js` |
| 商家 API | `/merchantApi/<Controller>/<action>` | 154+ 接口，大多需登录（401） |
| 店铺 API | `/shopApi/<Controller>/<action>` | 部分公开（商品列表/价格/下单） |
| 支付回调 | `/payApi/Yipay/notify`、`/payApi/Yipay/callback` | 彩虹易支付回调 |
| 插件文件 | `/zmkj-utils/params-wrapper.php` | 前端插件配置（一般无敏感信息） |

## 关键 API 清单

### 商家端（merchantApi）— 需登录
- `POST /merchantApi/user/login` — 登录，body: `{username, password}`，token 存 `merchant_token`（localStorage 365天）
- `POST /merchantApi/user/register` — 注册，需 `{username, password, repeat_password, mobile, mobile_code, email, email_code, invite_code, invite_token}`
- `POST /merchantApi/User/checkUserInviteCode` — 校验邀请码（可枚举）
- `POST /merchantApi/User/checkUserInviteToken` — 校验邀请人（返回"邀请人不存在"）
- `POST /merchantApi/user/forget` — 找回密码（用户名枚举："用户名不存在"）
- `POST /merchantApi/user/findUsername` — 找用户名（需邮箱/手机号+验证码）
- `POST /merchantApi/email/send`、`/merchantApi/sms/send` — 发验证码（需 ticket=极验 token）
- 业务：Goods/list、GoodsCardStorage/list（卡密存储）、order/list、order/exportCards（导出卡密）、payment/info（支付配置含KEY）、wallet/applyCash（提现）、Upload/file（文件上传）

### 店铺端（shopApi）— 公开
- `POST /shopApi/Shop/info` — 店铺信息（token 公开）
- `POST /shopApi/Shop/goodsList` — 商品列表 `{token, goods_type, current, pageSize}`
- `POST /shopApi/Shop/getGoodsPrice` — 价格 `{goods_key, quantity, coupon_code, channel_id}`
- `POST /shopApi/Shop/getUserChannel` — 支付通道
- `POST /shopApi/Pay/order` — 下单 `{goods_key, quantity, contact(≥6位), channel_id, ...}` → 返回 trade_no + payurl
- `POST /shopApi/Pay/query` — 查单 `{trade_no}`
- `POST /shopApi/Shop/goodsInfo` — 商品详情

### 未授权接口（重点）
- `POST /merchantApi/Upload/file` — 文件上传（multipart, 字段名 file），**不要求登录**，但源站可能 520
- `POST /merchantApi/system/config` — 系统配置（含 register.invite_code_get_url、kefu 联系方式）
- `POST /merchantApi/Common/captchaStart` — 极验初始化
- `POST /merchantApi/user/checkSafeMode` — 安全模式状态

## 注册链路（付费邀请码模式）

```bash
# 1. system/config 泄露注册配置
POST /merchantApi/system/config → register: {invite_code_get_url, is_need_invite_code:1, register_type:email, is_need_sms_verify:1}

# 2. 邀请码是付费商品！invite_code_get_url 指向的店铺卖"邀请码"卡密（如 ¥3）
#    想免费注册 → 需绕过支付拿邀请码卡密（见 rainbow-pay-submit-replay 手册）

# 3. 短信/邮箱验证码需极验 ticket，硬门槛
POST /merchantApi/sms/send {event:register, mobile, ticket} → 人机验证失败！
```

## 攻击顺序建议

1. 先拉 `merchantApi/system/config`（公开）拿注册配置/客服信息/邀请码获取地址
2. 枚举商家 API 未授权接口（Upload/file、checkSafeMode、forget 用户名枚举）
3. 免费/低价拿邀请码卡密（走支付绕过，见 rainbow-pay-submit-replay）
4. 注册商家账号 → 登录 → payment/info 拿支付密钥 → 伪造回调免付 → 批量提卡
5. 如果登录限速/锁定：等 10 分钟或换 IP

## 陷阱

- **520 全站限速**：接口探测太密会触发源站 WAF 封 IP（连 GET 都 520），停 3-5 分钟再试
- **登录频率限制**：连续错密码 → "操作频繁请10分钟后重试"，再错 → login.lock 锁定
- **人机验证**：短信/邮箱/注册都过极验（geetest），ticket 拿不到就发不了码
- **CF 前置**：域名常套 Cloudflare，zip 备份/源码路径全 403
- **商家 API 大多 401**：先批量测未授权（`{"code":1}` 或非 401 的就是金矿），别逐个手测
- **批量测接口会触发限速**：控制节奏，一次别刷太多接口

## 参考
- 支付绕过细节见 `rainbow-pay-submit-replay`（彩虹易支付回放）
- 发卡族通用支付绕过见 `faka-family-pay-bypass`
