# ACG-FAKA `USER_SESSION` 结构

异次元发卡站会员 Cookie，值为 JWT（HS256）。

## 形态

```text
USER_SESSION = base64url(header).base64url(payload).base64url(sig)
```

必须 **恰好两个** ASCII `.`。表格/TSV 粘贴常丢掉点号 → `session_import` / `session_pipeline` 会 FAIL。

## Header（常见）

```json
{"typ":"JWT","uid":522,"alg":"HS256"}
```

- `uid`：会员用户 ID  
- 算法固定 HS256，伪造需服务端 secret（白盒 / 配置泄露）

## Payload（常见）

```json
{"expire":1788446883,"login":true}
```

- `expire`：Unix 秒；与 Cookie 过期大致对齐  
- 其它字段视版本可能含 `username` 等

## 配套 Cookie

| Name | 作用 |
|------|------|
| `ACG-SHOP` | 店铺/会话附属 |
| `cf_clearance` | Cloudflare；过期后需 `cf_session.py capture` 重过 |
| `USER_SESSION` | 会员鉴权真身 |

## 作业流程

1. 有头：`cf_session.py capture` 完成 Turnstile/登录  
2. 校验：`session_import` / `session_pipeline`  
3. 无头：`cf_session.py consume` 或 Playwright `storage_state`  
4. 勿手修损坏 JWT；浏览器重新导出  
