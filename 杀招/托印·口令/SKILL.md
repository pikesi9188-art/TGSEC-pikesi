---
name: 托印·口令
description: "FastAPI OAuth2 password grant 登录链渗透：账号枚举、密码重置 oracle、邮箱变更 IDOR、token 刷新竞态。触发：FastAPI/OAuth2/password grant/access_token+refresh_token。"
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [auth, oauth2, fastapi, login, user-enum, account-takeover, pentest]
    category: daaixianzun
---
# OAuth2 Password-Grant 登录面测试 (跨目标通用)

触发: FastAPI SaaS 的 `POST /auth/token` (OAuth2 password grant), 或要审登录/重置密码/改邮箱流程。源自 origami.tech 实战, 方法通用。

## 1. ★★★ 登录必用 application/x-www-form-urlencoded (不是 JSON)
- 很多 FastAPI 的 `/auth/token` 是 `formData` + `mediaType: "application/x-www-form-urlencoded"` (OAuth2 password grant 的默认)
- **发 JSON body 永远回 `Incorrect username or password` 即使密码正确** — 曾浪费整个爆破/登录轮次, 最贵的坑
- 前端确认 (不用猜): 找 bundle 里 `postAuthToken` 的 `mediaType: "application/x-www-form-urlencoded"` / `formData` 字段
- 正确请求:
 ```
 POST /api/auth/token
 Content-Type: application/x-www-form-urlencoded
 grant_type=password&username=<email>&password=<pw>
 ```
- 排查信号: 新注册账号密码确定正确却登录失败 → 先怀疑 content-type, 不是密码
- 影响: 所有登录/爆破/密码喷射脚本必须用 form; 用 JSON 的自动化会全假阴性

## 2. Password-recovery 用户枚举 (代理免限流 oracle)
`POST /auth/password_recovery/change?email=<X>&code=999999&password=...` 响应区分:
- `{"detail":"User does not exists"}` = 邮箱未注册
- `{"detail":"Incorrect code entered"}` = 邮箱**已注册**
- **该端点常不在登录的限流桶**: 能过 CF crl 的代理池访问无 429 → 批量枚举任意邮箱是否注册 (staff/内部账号定位)
- 对照: send_mail / confirm 常被限流, 但 change (改密动作端) 是枚举入口
- 配合: 枚举域名变体 (help@/info@/admin@/pr@/bd@ + 内部域) 找真实 staff 账号再定向爆破

## 3. 账号生命周期接管链 (全部实测可行)
- **重置密码链**: `send_mail?email` → 收验证码 (mail.tm) → `change?email&code&password` → `"Password has been changed"` → form 登录新密码
- **改邮箱链** 🔴: `email_change/send_mail?new_email=<我们控的邮箱>` → 收码 → `change?new_email&code` → `"Email has been changed"` → **旧 token 立即失效** = 账号邮箱转移
 - 攻击链: 获任意目标会话 → 改邮箱到自己临时邮箱 → 密码恢复 → 完全接管 (若 target 会话可拿到)
 - 验证账号是否激活: 注册后收 `"Success Sign-up"` 邮件即真激活
- 密码、改邮箱都要邮箱 code, code 是 6 位真随机 (与时间戳无关)

## 4. 验证码 (code) 爆破可行性判据
- 测法: 单代理连续对 confirm/change 打错误 code, 数几次后出现 429
- origami 实测: **每代理 2 次即 429** → 6 位=100 万不可爆破 (真随机且非时序)
- 硬墙是限流窗口而非密码数; 除非 4 位 code 或未限流, 否则别投时间
- 有代理池也救不了: 18 代理 × 2 = 36 次/窗口 × 冷却 ≈ 每 90s 25 个, 6 位要 N 万分钟

## 5. 快速自检
- [ ] /auth/token 确认用了 form-urlencoded (查前端 mediaType)?
- [ ] 登录失败先查 content-type 再疑密码?
- [ ] 收集过未注册/已注册枚举差异?
- [ ] 记下 reset/email-change 用的 code 位数 + 限流次数?

## 关联
- 邮箱收码细节 (mail.tm hydra Collection / token 落盘) → `saas-signup-multitenant-testing`
- 拿到会话后做账号邮箱转移接管 → 本技能 §3

## 真源

- 手法：`传承/黑楼兰·硬撼.md`
- 工具：`python3 炼蛊房/auth_brute_probe.py --help`
