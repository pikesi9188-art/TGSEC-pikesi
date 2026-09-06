---
name: 商燕飞·南域
description: "巴西/葡系博彩 SPA 渗透：base64 配置解码提取 API 密钥、tRPC 端点枚举与越权、代理/代币操控。触发：tRPC/BR gambling/PT casino/b64 config。"
version: 1.5.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, brazil, trpc, spa, ff567, h57]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# BR/PT 博彩 SPA (tRPC 白标) 渗透

巴西/葡语博彩 H5 白标（例: FF567 / 188world.com / h57vip.com）。前端 SPA + Cloudflare + `/api/frontend/trpc`。

## 触发信号

- `window.__APP_CONFIG__` 超长 `domainInfo`/`channelInfo`
- `apiUrl` `https://api5.a-b-c-8.com` / `api*.a-b-c-*.com`
- `/main/inicio`、`/api/frontend/trpc`、Turnstile+阿里云验证码
- 葡语+BRL/PIX；`regionName=巴西`
- HTML `DESENVOLVIDO POR DAANROX` 或 `/rox/api/*`

**主体**：巴西/BRL/非.cn → 可继续；中国主体停手。

## 执行纪律

- 授权/`继续` 后**禁止**问是否继续；边打边报 3-5 行并同回合继续 tool
- `405 region` → 立刻换同源站/出口，勿空转 header
- 用户要「后台用户数据」= admin 用户表导出；前端未授权手机号只算中间成果

## 配置解密

```text
blob → reverse() → b64decode → unquote → json.loads
```

## 会话门槛（打穿关键）

| 只带 | 效果 |
|---|---|
| Bearer alone | 半会话：写/详情常失败 |
| `Cookie: token_user=<token>` | **真会话** |
| + X-Tag / X-Auth-Tag / x-token-data | 完整客户端态 |

登录后必须回带 `Set-Cookie: token_user`。

```text
POST /api/frontend/trpc/auth.login
{"json":{"username":"<phone>","password":"...","lastLoginDevice":"<uuid>","loginDeviceModel":"Android Chrome"}}

POST /api/frontend/trpc/auth.registe
{"json":{"password":"...","phone":"119xxxxxxxx","cpf":"<11>",
 "registerDevice":"<uuid>","registerType":"Phone","channelId":0}}
# 用 phone 不是 phoneNumber（以报错为准：Telefone é obrigatório）
```

## 金额

- cents：`awardAmount:3` → `balance:300`
- 提现 `minAmount:1000`；礼包 300 会卡出金
- `withdraw.createOrder` 先试 `password`=登录密

## 未授权高价值

| 过程 | 泄露 |
|---|---|
| `activity.sharePhone` | BR 手机号 `allPhones` |
| `activity.assistanceCashAwards` | `[{userId,amount}]` |
| `rank.userRank` | top100 userId+rankValue |

改 userId header **不能**读他人 details。

## ROX / daanrox

| 路径 | 行为 |
|---|---|
| `/rox/api/check-user.php`+token_user | OK+user_id |
| `/rox/api/set_ip.php?ip=` | 未授权写 IP |
| FOFA `body="/rox/api/check-user.php"` | 扩面 |

## PHP 后台 form-acessar

- `POST {base}/ajax/form-acessar.php`：`email`+`senha`+`_csrf`
- `base` 常是 `/admin` 或 **`/dashboard`** — h57vip 真面板在 `/dashboard/login`，`/admin/login` 可能是 SPA 壳
- 公开源码 `daanrox/candy-crush-pay`：`admlogin` 明文；SQL 默认 `contato@daanrox.com`/`Candy123456`（现网常改，全站试过无效别死磕）
- 会话 `$_SESSION['emailadm']`；路径 `rox_admin/`（现网常被 SPA catch-all 吞掉）

### 错误语义（勿误判）

| 响应 | 含义 | 动作 |
|---|---|---|
| `Seus dados não foram encontrados` | 邮箱不存在/未命中 | 换邮箱枚举 |
| `Revise os dados inseridos` | **不一定是账号存在** | agent86t 上 `admin@admin.com` 对任意密码都返回此句=特殊校验/黑名单，**禁止 10k 爆破** |
| `Dados incompletos no formulário` | 缺 csrf/字段 | 先拉 login 页拿 `_csrf` |
| `Insira um e-mail válido` | 非邮箱格式 | 跳过 |

### SPA 假路径

`/phpmyadmin` `/adminer` `/rox_admin` `/helderadmin` 常 **HTTP 200 + 主站 SPA**（`__APP_CONFIG__` 或 `DESENVOLVIDO POR DAANROX`）。判定真面板：有 `name="senha"` + `form-acessar` 且 **不是** 整页 SPA。

打穿后抓：`usuarios/clientes/jogadores/saques` 导出用户表。

## 攻击优先级

1. 解密配置+过程表
2. 未授权 sharePhone/awards/rank
3. 过 region（同源 h57 族 / BR 出口）
4. 注册→Cookie 真会话
5. 羊毛/pay/withdraw
6. ROX
7. PHP 后台用户表（主交付）

## 坑点

- Bearer 半会话 ≠ 打穿；没 `token_user` Cookie 就别报「已登录」
- 注册字段以报错为准
- 礼包 300 < withdraw min 1000 → 半程
- `admin@admin.com` + “Revise” ≠ 可爆破账号（agent86t）
- `/phpmyadmin` 200 先查 SPA 壳
- JP 卡 region：优先同源站

## 参考

- 个案附件未入库（原 references/ff567-h57-session-notes.md）

## 真源

- 手法：`传承/商燕飞·盘口.md`
- 工具：`python3 炼蛊房/gambling_family_probe.py --family br-trpc --base https://授权站 --case <案卷>`
