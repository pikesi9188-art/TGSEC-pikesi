---
name: 死票还活
description: >-
  改密后旧 JWT 仍活（无状态持久化）。触发：JWT 无状态、改密码票还在、旧票仍 200。
  不改原超管密。none/弱密钥仍走 jwt-bypass-pentest。
---

# JWT 无状态持久（大爱仙尊）

目标须在 scope。用 **改密前留下的自己的票** 打 `/me` 一类接口。  
授权内默认打到 **L2**：200 且体像用户。  
先问只剩：改原超管密。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 解出 alg/iat/exp | 只看到 Bearer |
| L2 | 旧票 200 且 JSON 含 user/role | 401 当洞 |
| L3 | 本卡不默认改密做对照 | none/弱 HS256（交伪造卡） |

## 立刻跑

```bash
python3 炼蛊房/jwt_persist_probe.py drive \
  --url https://授权站/api/me --token '<旧票>' --case <案>
python3 炼蛊房/jwt_forge_probe.py --help
```

探针：`Authorization: Bearer <token>` GET；`split_jwt` 记 alg/iat/exp。  
`alive` = 200 且正文含 user/role/`{`。

产物：`案卷/jwt_persist/surface.json`。

## 六步

```text
① 用自己的旧票，不要拿别人的
② drive 打 /api/me 或等价
③ 200 → 填对象矩阵「自己×读」仍活
④ 401 → 服务端有黑名单，本卡阴性
⑤ none / 弱密钥另走开 jwt_forge
⑥ 不要为了对照去改超管密
```

## 交接

| 认到 | 走 |
|------|----|
| alg none / 弱 HS256 / kid | `jwt-bypass-pentest` · `jwt_forge_probe.py` |
| 低权票打管理 API | `rbac-bypass-authz` |
| 重置 token 外泄 | `reset-token-surface` |

## 真源

- 手法：`传承/李代桃僵.md` · `专项探府.md`
- 探针：`炼蛊房/jwt_persist_probe.py`
