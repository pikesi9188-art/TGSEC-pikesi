---
name: 万我
description: >-
 对象矩阵闸（不是又一张专卡）：开案/开始/深挖/接管且已有任意身份时，
 先填自己vs他人的读/写/加款/配置，专卡阴性必须回表。
 禁止超管截图结案、禁止 info 当只读自己、禁止给自己加款失败就停。
 
---

> **东方长凡**
> 万我出手千身同，一念分身遍北原。
> 智海无边身作舟，长凡不凡我即天。

# 对象矩阵（身份错位）

## 真源

`传承/万我.md`

## 强制行为

1. **有会话先填矩阵**（自己 / 他人 × 读 info / 加款 / 配置文件 / 桶），再决定回哪张专卡。 
2. `/api/user/info`、`userId`、`refreshUserInfo` → 当 IDOR 测；奖品可以是 **bcrypt / 资金密码 hash**，不只有 PII。 
3. 给自己加款失败 → **立刻打他人 uid**；入账以 **B 自己的 token 查余额** 为准（提现记录 balance 常是快照）。 
4. 进了 `super_admin` → 下一刀是 **配置/文件/COS·OSS 钥**，不是只找 RCE 或改原超管密。 
5. OAuth2 password grant 必须 `application/x-www-form-urlencoded`（细节见 `oauth2-password-grant-login-testing`）。

## 最短动作

```bash
python3 炼蛊房/object_matrix.py init --case <案卷>
python3 炼蛊房/object_matrix.py next --case <案卷>
python3 炼蛊房/object_matrix.py check --case <案卷> --strict
python3 main.py authz-probe -u https://授权站 --scope 授权范围
python3 炼蛊房/js_secret_hunter.py hunt --base https://授权站 --case <案卷>
```

加款验证：注册 B → A 的票给 B 加最小额 → B 的票查余额差。大额先问。全表拖库先问。

## 交接

- 开放注册 + IDOR 拖用户 → `register-bypass-idor` 
- 硬编码 Token + CF-IP 加款 → `hardcoded-token-cfip-fund` 
- 云钥落盘 → `云府·临钥.md` · `bucket_probe.py` 
- Cognito `IdentityPoolId` / Unauth 角色 → `cognito-unauth-s3-chain`（他人读 List/Get；写只用 marker） 
- TG session 目录 → `tg-cloud-panel` / `tg-account-library` 
- FastAdmin 代付 `part/multi` money / `makemoney` 流水 → 回矩阵打 **真结算格**，不要当已加款 
- FastAdmin Shop `shop_id` EQ 阴性 → 回矩阵打 **他人读**（GT/IN），禁止写「隔离正确」 
- 假支付 / Actuator / 芋道专卡照打，阴性后回到矩阵换对象，不要换同类锤子
- 低权票 + 管理 API / 角色字段 / Method-Override → `rbac-bypass-authz`（垂直面，不替代他人格）
- `wallet_id` / 双路径资金 API / 展示层地址 / 消息回单号 / 玩家票 init·turnWater → `fund-edge-ops`（uid 阴必须换键，禁止写无越权）
