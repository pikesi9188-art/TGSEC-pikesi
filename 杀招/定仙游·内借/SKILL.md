---
name: 定仙游·内借
description: "echo SSRF内网扫描/服务发现/K8s svc/云metadata枚举/端口状态码判定(500≠closed→DB开放)。含状态码判定法：500=DB/Redis/SSH、400+HTTPS=kubelet、429=限流。"
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [ssrf, pentest, internal-network, kubernetes, metadata]
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

> 旧名 `ssrf-internal-pivot`、`echo-ssrf-internal-scanning` 已重定向到本卡，勿再展开旧正文。

# SSRF 内网横向与侦查 (echo/POST-only SSRF)

触发: 拿到回显式 SSRF (任意 URL 请求且响应体回显), 需要打内网/找服务/读 metadata/K8s 服务发现时。

## 0. 先确认 SSRF 的能力边界 (5 分钟)
1. **回显语义**: webhook.site 或自控端点验证请求真的发出 (看 user-agent/headers/body)
2. **请求特征**: 方法 (GET/POST)、Content-Type、body — 决定能打什么服务:
 - 无 Content-Type + 空 body 的 POST → **grpc-gateway 类服务全 415** (ArgoCD/大多数 Go gRPC 网关)
 - 有 CT + JSON body → 可打 REST API
3. **协议支持**: 通常只有 http/https; file/gopher/ftp/dict 报错 (httpx/requests 限制)
4. **回显区分**: 目标真实响应原样回显 (200/400/401/404); **框架 500 (如 "Internal Server Error") = 目标连接失败/超时**; curl 000 = TCP 通但非 HTTP (Redis/SSH/gRPC)

## 1. UA 陷阱 (高价值教训 — 防假阳性)
- **批量扫描客户端 (python-urllib 默认 UA) 常被 CF WAF 拦 → 403 error code: 1010** — 所有请求假阳性!
- 症状: 整个网段"全 1010"、"全开放"或"全 500" — 先换 UA 验证
- 修复: 所有批量请求带 `User-Agent: curl/8.5.0` 或浏览器 UA
- 诊断法: 同一 URL 用 curl vs urllib 各打一次对比响应

## 2. 限流管理 (慢扫是唯一答案)
- 全局限流通常是**滑动窗口** (实测 ~60 req/min): 单发 @1s 连续 20 次 OK, 批量 0.9s 间隔仍 429
- 安全速率: 间隔 ≥1s, 429 后冷却 30-60s 再续
- **手动测试与后台扫描共享限流预算 — 绝不并行** (互相踩 429)
- 长扫描脚本必须内置: 429 冷却 + token 自动刷新 (过期后密码重登, 重登过快会被 CF 403 — 需手动重登)

## 3. K8s 服务发现: svc.cluster.local DNS 枚举 (王牌技巧)
IP 段扫描往往失败 (pod 漂移/网络隔离), **DNS 服务名直连是更稳的路**:
- 目标格式: `http://<service>.<namespace>.svc.cluster.local:80/`
- 枚举组合: 常见 ns (default, argocd, kube-system, ingress-nginx, gitops, cicd, monitoring...) × 常见服务名 (api, backend, argocd-server, postgres, redis, minio, grafana, prometheus, nginx...)
- 判读: `500/连接失败` = 服务不存在; `200/404/400` = **服务存在** (404 也是命中!)
- 命中后补测组件的默认端口: argocd-server 8080/8443, repo-server 8081, dex 5556/5557, redis 6379, applicationset-controller 7000 (webhook, 400=缺事件头)
- gRPC/非 HTTP 服务 TCP 可达时表现为 curl 000 或读超时 — 标记但无法用 HTTP 交互

## 4. 云 metadata 枚举 (169.254.169.254)
- **OpenStack/OVH**: `/openstack/latest/meta_data.json` → ovh-token/node_ip/apiserver_url/SSH 公钥; `network_data.json` → 网段/网关; `vendor_data.json`
- **AWS 兼容**: `/latest/meta-data/` → instance-id/hostname/local-ipv4; `/latest/meta-data/iam/security-credentials/` (有 role 才有)
- GCP: `/computeMetadata/v1/...` 需要 Metadata-Flavor 头 (SSRF 无头控制时常 404/403)
- **负载均衡多节点**: 每次 SSRF 可能命中不同节点 → 反复读 metadata 收集每节点不同 token/拓扑
- 多节点对比还能确认 API 后端规模

## 5. K8s pod IP 漂移 (扫描时效)
- 负载均衡的 API 集群 pod IP **分钟级漂移** — 扫描发现的 IP 立即用, 别复用
- 更稳: DNS 服务名 / 已知 node IP 的固定端口 (kubelet 10250, nodePort 30000+)

## 6. 服务指纹 (错误页识别)
- Squid 400 页 (8080-8089 常为代理池) — `<title>ERROR: The requested URL could not be retrieved`
- FastAPI: JSON `{"detail": "..."}` (401/404/405/422 泄露 schema)
- nginx: 403/404/308 (308 = http→https 强制, 服务在后面)
- CF: `error code: 1010/1000/526` (WAF/回源失败)
- ArgoCD grpc-gateway: `415 Invalid content type` (需要 CT 的请求才通)

## 支撑文件
- `references/origami-case-study.md` — 实战案例: 全链路 (extended SSRF → metadata → ArgoCD 内网 → API pod 群)
- `python3 炼蛊房/ssrf_probe.py` — 本库探针（头像/URL 预览 SSRF）；内网慢扫按本卡限流纪律手写，勿找已删除的外门 `scripts/ssrf_scan.py`

## ★ 端口状态码判定法（回显式 SSRF 关键陷阱）

> 来源：`ssrf-internal-pivoting`（已并入）

最常见错误：把 `500 Internal Server Error` 当失败过滤 → 数据库端口全部漏判。

| SSRF 回显 | 判定 | 示例 |
|---|---|---|
| HTTP 200 / 4xx（非 CF 1010）| **HTTP 服务存活** | FastAPI、Squid 400、CoreDNS 404 |
| **HTTP 500 "Internal Server Error"** | **端口 OPEN = 非 HTTP 协议** | Postgres 5432、Redis 6379、MySQL 3306 |
| **HTTP 400 "Client sent an HTTP request to an HTTPS server"** | **端口 OPEN = HTTPS 服务** | kubelet 10250、k8s apiserver 443 |
| HTTP 429 crl/rate_limit | 触发全局限流，冷却 45–60s | 应用层全局 crl |
| HTTP 403 + "error code: 1010"（CF 页）| 虚拟段/CF Tunnel，非真实服务 | 10.4.0.0/24 等 |
| 5s+ 超时 / 连接拒绝 | 关闭或防火墙 drop（无法区分） | — |

**根本原因**：`500` 是 httpx 对非 HTTP 端口**连接成功后**解析失败，由上游框架包成 500。绝大多数脚本写 `if '500' in code: skip` → 把数据库端口当关闭。**DB/Redis 开放的信号恰恰是这个 500。**

### 落地脚本要点

```python
try:
 r = requests.get(f"{SSRF_BASE}?url=http://{ip}:{port}/", timeout=4)
 body = r.text
 if r.status_code == 500:
 print(f"OPEN-NONHTTP {ip}:{port}") # DB/Redis/SSH
 elif r.status_code == 400 and "HTTPS" in body:
 print(f"OPEN-HTTPS {ip}:{port}") # kubelet/apiserver
 elif r.status_code in (200, 400, 401, 403, 404):
 print(f"HTTP {ip}:{port}")
 elif r.status_code == 429:
 time.sleep(50); ... # 限流，重试
except requests.exceptions.ConnectionError as e:
 if "refused" in str(e): pass # 关闭
 elif "EOF" in str(e) or "Bad status" in str(e):
 print(f"OPEN-NONHTTP {ip}:{port}") # 也是 DB！
```

### 校准步骤（先跑再扫）

1. 已知 HTTP：打 Squid 8089 → 应得 400 Squid 页（对照"HTTP 存活"）
2. 已知关闭：打 `:59999` → 记超时/refused 形态
3. 已知 HTTPS：打 kubelet 10250 → 期待 "Client sent HTTP to HTTPS" 400

### 实战案例（origami.tech）

- 早先脚本排除所有 `500` → 10.4.2.96 的 5432/6379/3306 全被误判"关闭"
- 用判定法发现 kubelet 10250 在 10.4.1.165 / 10.4.3.189 返回 `400 HTTPS` = 端口开放
- 10.3.x 大量 403/429 = CF 虚拟化；CoreDNS 10.3.0.10:9153 `/metrics` 返回真 200

## 攻击顺序模板

1. 验证 SSRF 边界（webhook 抓包）
2. 读 metadata（若有 169.254.169.254）
3. K8s svc.cluster.local DNS 枚举（先 DNS 后 IP）
4. 内网 IP 段慢扫（限速 ≥1s/req）——**用状态码判定法（见★章）**：
 - 200/400/401/404 = HTTP 服务 → 继续打
 - 500 = 非 HTTP 协议端口开放（DB/Redis/SSH）→ 记录但无法 HTTP 交互
 - 400 含 "HTTPS" = HTTPS 服务（kubelet 等）→ 用 https:// SSRF 再试
5. 命中管理面板（ArgoCD/Grafana）→ 死磕认证/CT 墙

## 真源（原 ssrf-internal-pivoting 已并入本卡）

- 手法：`传承/定仙游·云骨.md`
- 工具：`python3 炼蛊房/ssrf_probe.py --help`
