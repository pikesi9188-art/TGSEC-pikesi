---
name: 夺舍
description: >-
 授权目标上认证强绑定、API key/secret 绑用户 token、IDOR 直读失败时的账号接管链：
 OAuth redirect/DCR、密码重置、JWT 混淆、Host 头污染重置链接。
 
 盘口重置优先看扩展包 gambling-password-reset-ato；GVA 走 ginvue-admin-stealth-takeover。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# 账号接管链

IDOR 全阴不是结案，是换认证生命周期。只打自己的号。

## 四刀（按序，阴性才换）

1. **重置面** — 短 token / 任意 code / Host 污染重置链  
   `python3 炼蛊房/ato_reset_withdraw_probe.py dummy-reset --base https://授权站 --case <案>`  
   盘口：`gambling-password-reset-ato`
2. **OAuth/OIDC** — `redirect_uri` / 缺 `state` / 隐式流  
   `python3 炼蛊房/oauth_oidc_surface_probe.py --base https://授权站 --case <案>`
3. **JWT** — `alg:none` / 弱 HS256 / kid  
   `python3 炼蛊房/jwt_forge_probe.py --help` · Skill `李代桃僵`
4. **会话** — 改密后旧票仍活；Session Fixation。重置 token 外泄走 `reset-token-surface`

## 不要做

- 未授权对第三方用户发钓鱼 / 定向重置别人
- 把「能注册」当成接管
- GVA `authorityId=888` → `ginvue-admin-stealth-takeover`
- 工具不是 `case_report.py`

真源：`智道藏书/旁支传承/skills/account-takeover-chain/SKILL.md` · `传承/托印·越权.md`
