---
name: 暂飞书
description: >-
  大爱仙尊·用 API 拿一次性临时邮箱收验证码（注册目标平台账户）。触发词：临时邮箱、接验证码、注册账户收码、temp mail。
---

# temp-email-verification-codes（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/recon-and-methodology/temp-email-verification-codes/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name temp-email-verification-codes`

---

# 临时邮箱 API · 注册账户接验证码

去目标平台（490.ai 等）注册账户需要能收验证码的一次性邮箱时用。优先用可脚本回调的 API，
别指望开浏览器（沙箱里 Chrome 常起不来）。

## 首选：temp-mail.io 内部 API（实测可用，域名不被拒）

temp-mail.io 的公开内网 API 免登录就能创建+收信，生成的邮箱域名动态轮换（`ruutukf.com` 等），
对临时邮箱屏蔽较宽松的平台能收到码。

创建邮箱（返回 email + token）：
```bash
curl -s -X POST "https://api.internal.temp-mail.io/api/v3/email/new" \
  -H "Content-Type: application/json" \
  -d '{"min_name_length":8,"max_name_length":15}'
# -> {"email":"3te4svf1@ruutukf.com","token":"pBwk0qQMc8123CMz5RzX"}
```

收信（Bearer token 轮询，空 `[]` = 还没信）：
```bash
EMAIL="<上面拿到的email>"; TOKEN="<上面拿到的token>"
curl -s -X GET "https://api.internal.temp-mail.io/api/v3/email/$EMAIL/messages" \
  -H "Authorization: Bearer $TOKEN"
# -> [{"from":"Router <noreply@...>","subject":"注册验证码","body_text":"您的注册验证码是 157791..."}]
```

- 轮询间隔 3-5 秒，验证码类邮件通常几秒到几十秒到。
- 从 `body_text` 里正则抽验证码数字。

## 免费额度关键坑：邮箱只有约 10 分钟寿命

- **免费版邮箱 10 分钟后过期删除**（temp-mail 官方标 "10 minute mail"）。
- Premium 才 30 天。
- 所以：注册流程要一口气走完；若目标还要二次验证码，10 分钟后就收不到了，
  需新建邮箱或换长期邮箱。

## 其它服务的坑（实测）

- **mail.tm**：`POST api.mail.tm/accounts` 能建，但域名被目标屏蔽率更高；
  且可用域名是固定的（如 `emalupe.com`），不接受自定义。
- **1secmail**：`api/1secmail.com` 返回 403 Forbidden（服务器拒绝）。
- **Guerrilla Mail / LMArena 等 API**：部分返回空或 JS 渲染，不适合脚本回调。

## 用法流程

1. 调 temp-mail `/email/new` 拿地址+token。
2. 把邮箱地址给用户，让用户去目标平台填（注册/身份信息由用户自己定，别代填）。
3. 用户说"发送了"后轮询 `/email/{email}/messages`，读到验证码发回。
