---
name: oauth-oidc-flow
description: >-
  OAuth2 / OIDC 授权码流与 redirect_uri。触发：openid-configuration、
  authorization_code、redirect_uri 劫持、/oauth/authorize、SSO 越权、
  implicit flow、#access_token。grant_type=password 立刻切
  oauth2-password-grant-login-testing。
---

# OAuth / OIDC 授权码流

目标须在 `授权范围`。不换他人 code。

## 真源

- 手法：`传承/托印·越权.md`
- 工具：`python3 炼蛊房/oauth_oidc_surface_probe.py --base https://授权站 --case <案>`
- 路由：`identity-federation`（SAML / Passkey 仍走那边）

```bash
python3 炼蛊房/oauth_oidc_surface_probe.py --base https://授权站 --case <案>
python3 炼蛊房/oauth_oidc_surface_probe.py --base https://授权站 --case <案> --client-id <id>
```

## 何时用

登录跳到 `/oauth/authorize`、`response_type=code`、`.well-known/openid-configuration`。  
FastAPI `grant_type=password` 表单登录不是本卡。

## 失败

只有 discovery JSON 是 L1，不算劫持。`redirect_uri` 必须跳出到 `example.com` 才报 L2。
