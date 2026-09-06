---
name: 锦府·静默
description: >-
 GIN-VUE-ADMIN 管理面静默提权：开放注册写 authorityId=888 植入超管 →
 getSystemConfig 泄 JWT 密钥 → 伪造 admin JWT；可选 setUserAuthority 二次植入；
 成功后 webhook/案卷通知。默认禁止 resetPassword 改原 admin。
 领奖 getConfigs/sendCReward 仍走 ginvue-admin-reward。
---

# GIN-VUE-ADMIN 静默提权（植入超管 / 伪造 JWT）

**前提**：目标在 `授权范围`。

**成功口径**：自控超管号可登录（L1）或伪造 admin JWT 通过 `getUserInfo`（L2），且 **未修改原 admin 密码**。L3=额外隐蔽持久化；N1=脱敏通知已发。

## 何时启用

- 指纹：`/api/base/login`、`/api/user/register`、`authorityId`、`x-token`
- 开放注册或未鉴权 `admin_register`
- 用户要「植入超管 / 偷偷提权 / 成功通知」，不要改密打草惊蛇

不适用：只打领奖 `sendCReward`（→ `ginvue-admin-reward`）；无管理面。

## 强制行为

1. **默认禁止** `resetPassword` / 修改原 `admin` 口令（高噪声）。 
2. 优先序：注册植入 `888` → 泄 `jwt-key` → 伪造 JWT →（可选）`setUserAuthority` / 再建隐蔽号 → `notify`。 
3. 通知与 STATUS 脱敏：不写完整 JWT、jwt-key、DB 密码到公开文档。 
4. 大规模导出用户/密钥先问。 
5. 用户「暂停」→ 停进攻。

## 最短命令

```bash
python3 炼蛊房/ginvue_stealth_takeover.py chain \
 --base 'https://授权管理面' --case <案卷> \
 --username 'ops_cache_0811' --password '…' \
 --webhook "$OPS_WEBHOOK" --insecure
```

## 真源

- 手法卡：`传承/锦府·静默.md`
- 原图：（开源包不收个案摘记）
- 领奖旁路：`杀招/锦府·赏`
- 芋道 SQL 隐藏超管对照：`炼蛊房/yudao_hidden_admin_sql.py`
