---
name: 秦百胜·白包
description: >-
  大爱仙尊·免费领取接口未校验价格领付费礼包。博彩/游戏/充值类站。前端拦price!=0但服务端不验→未付到账。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# free-package-claim-bypass（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/free-package-claim-bypass/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name free-package-claim-bypass`

---

# 免费领取接口 · 未付领付费礼包手册

> 应对博彩/游戏/应用商店类站点有"免费礼包"功能。核心：**前端拦 price!=0，服务端不校验价格/支付状态 → 直接把付费 packageId 塞进 free-claim 接口，未付到账**。

## 目标判定
- 站点有免费领取/每日礼包/滚动活动类接口，URL 含 `claim-free`、`free-package`、`rolling-offers` 等。
- 前端 JS 里有 `price !== 0` 拦截逻辑（说明服务端路径还在，只是按钮被藏）。

## 关键原理
前端 bundle 逻辑：
```js
if (!s || s.price !== 0) { return; }  // 不发请求
// 仅 price===0 才调 claim-free-package
```
服务端 `claim-free-package` 未校验 package 价格与支付状态 → 绕过前端直打即可。

## 利用步骤
1. 注册账号完成邮箱/手机验证，拿有效 Bearer Token。
2. `POST /v2/event-trigger/events`（或同族活动列表接口）→ 取含 packages 的 activeEvent，**注意 packages 同时含 price=0 和 price>0 的包**。
3. 把付费 packageId（如 585206，price=23.99）填进 free-claim 接口 body，activeEvent 用 events 返回的**原对象**（不要手改价格字段）。
4. `GET .../get-wallet` 验证余额增加，且无对应支付订单。

## 接口怎么找（不是爆破）
1. 登录后 DevTools→Network，先走一遍**真免费包**（price=0），录下 claim 请求。
2. 下载前端 bundle，搜 `claim-free-package`、`rolling-offers`、`price !== 0`。
3. 把周边 REST path 列全（get-wallet、events 等），用 Token 直打。
4. 搜不到支付预下单/capture 与领取绑定 → 判定服务端没校验付款。

## 实测参考
- packageId 585206，标价 $23.99 / 65 SC + 130 万 GC，未付成功到账。
- 同活动 15.99 档领完大额后通常失效，不能连领。
- 可多账号批量利用（每号该活动约 1 次）。
- 提现可能仍受手机验证/KYC 限制，不影响"未付款到账"成立。

## 诚实纪律
- 必须验证钱包/余额实际增加才算 ✅；仅 200 但余额没动 = ⚠️。
- 不经过任何支付接口是判定关键。
- 以服务端活动配置为准校验 packageId 与用户资格，勿信任客户端提交的 activeEvent 内价格字段。
