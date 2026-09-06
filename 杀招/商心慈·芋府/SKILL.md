---
name: 商心慈·芋府
description: >-
 授权目标上芋道/ruoyi-vue-pro 的 TMA 或 Web：/runtime/app-config.js、
 /app-api、AES+RSA+X-Ca-Token、sk_encrypt.json 密钥泄露、租户 PLATFORM_ID。
 Qzino /api.html 走 telegram-tma-gambling。
 旧名 `yudao-tma-pentest` / `yudao-web-appapi-pentest` / `tma-encrypted-api-reversal` 已并入本卡。
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# 芋道 TMA / Web 加密 API（Cursor Skill）

## 何时用

- 前端有 `/runtime/app-config.js`（`PLATFORM_ID` + `API_LIST`）
- API 前缀 `/app-api/`，或 `/app-api/encrypt` 返回 base64
- 能读到 `sk_encrypt.json`

## 真源

1. `传承/芋府·微域.md`
2. `智道藏书/旁支传承/skills/yudao-tma-pentest/SKILL.md`
3. `智道藏书/旁支传承/skills/yudao-web-appapi-pentest/SKILL.md`
4. `炼蛊房/yudao_appapi_probe.py`

## 强制步骤

1. 目标在 scope。
2. ```bash
 python3 炼蛊房/yudao_appapi_probe.py -u https://授权前端 --case <案卷>
 ```
3. 命中 `sk_encrypt` → 抽密钥，明文 `/app-api` 探活，再解加密通道。
4. 命中 TMA 配置 → 抽 salt/RSA，先打未授权 tenant/游戏配置；有 initData **当轮 autoLogin**。
5. 充提链按手册做；凭证上传 ≠ 入账。回调交 `payment-callback-forgery`。
6. 证据：`案卷/yudao_appapi/` + STATUS（变体/租户/是否拿到 token）。

## 不要做

- 把 Qzino `method` 信封套过来
- 在 app 域死磕 `/admin-api`
- 过期 initData 连打登录后结案「加密失败」
