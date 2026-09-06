---
name: 定仙游·回声
description: "用到手回显式SSRF做内网扫描时: UA陷阱/限流窗口/响应码判存活/K8s DNS枚举/metadata读取。"
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [ssrf, network-scanning, kubernetes, cloud-metadata]
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# 回显式 SSRF → 内网扫描 playbook

适用: 已获得一个"任意 URL 回显响应体"的 SSRF (POST-only / 固定头 / 固定 body), 需要内网拓扑探测、服务发现、K8s 枚举。实战案例: origami.tech `/accounts/extended?base_url=API&path=<URL>`。

脚本: `scripts/ssrf_scan_skeleton.py` — 实战收敛版扫描循环 (UA 头/自动续 token/429 冷却/响应分类/增量落盘), 改 URL 与任务列表即用。

## 1. 先摸清 SSRF 原语的约束 (10 分钟)
- 方法固定? 头固定? body 固定? 是否回显?(用 webhook.site 抓包验证转发请求的头/体)
- 支持的协议: 通常仅 http/https (file/gopher/ftp/dict → 后端 500)
- **无 Content-Type + 空 body** 的转发 → 打 grpc-gateway / 严格 CT 校验的服务全部 415(ArgoCD 教训: 别在 415 上耗时间, 除非能找到带 CT 的第二入口)
- 记录"连接失败" vs "目标响应"的表现差异, 建立响应码字典(见下)

## 2. 响应码判存活 (关键字典)
| 表现 | 含义 | 处理 |
|---|---|---|
| `000` | TCP 通但非 HTTP 响应 (黑洞/二进制协议如 Redis/PG) | 不可用 HTTP 交互, 别误判为数据库可打 |
| `500 Internal Server Error` | 连接失败 / 超时 / TLS verify 失败 (后端统一错误) | 等价"不可达" |
| `400/404/308` | HTTP 服务活着 (Squid 400、nginx 404、redirect) | 是线索, 继续 fuzz |
| `401 JSON` | FastAPI/OAuth 服务活着, 需 Authorization | SSRF 无头 → 只能确认存活 |
| `403 error code: 1010` | **Cloudflare 按 UA 拦截** | ⚠️ 见 UA 陷阱 |
| 真实业务响应 (200/422 带业务结构) | 穿透成功 | 直接用 |

## 3. UA 陷阱 (血泪教训)
- **python-urllib 默认 UA → 经 Cloudflare 的 API 全 1010 拦截** → 扫描结果全假象, 会误判网段为"CF 隧道段"
- 任何批量扫描脚本必须显式 `User-Agent: curl/8.5.0`(或浏览器 UA); curl/httpx UA 均通过
- 判定方法: 同一目标用 curl 实测 vs 脚本结果不一致 → 先查 UA/头差异

## 4. 限流与速率 (SSRF 入口通常复用 API 限流)
- 批量前先实测窗口: 20 连发 @1s 间隔全过 → ~60req/min 安全; 触发 429 后冷却 30-60s 再重试一次
- **扫描线程与手动验证不能并行**(共享同一限流窗口 → 扫描全 429 假卡死)
- "卡在 progress 0" 常见原因: 429 冷却循环 或 目标端口 DROP 导致每请求吃满 connect timeout → 扫前先单测几个 IP 估单请求耗时
- access token 1h 过期: 脚本每 ~400-500 请求自动重登; 但**频繁重登会被 WAF 403**(密码登录本身被限) → 手动重登 + 重载 token 文件更稳

## 5. K8s 集群枚举 (高价值)
- **服务 DNS 猜测**: `http://<svc>.<ns>.svc.cluster.local:80/` — argocd-server.argocd 就是这样找到的; 200 = 服务可达, 500 = 不存在/连接拒, 000 = 非 HTTP 活着
- ns 猜测: argocd/gitops/cicd/default/origami/api 等; 服务名猜测: api/backend/gateway/admin/postgres/redis/minio/grafana/argocd-* 组件
- service CIDR(如 10.3.0.0/16)全端口 000 = 黑洞(未分配 clusterIP), 不要误当成数据库
- apiserver(10.3.0.1/kubernetes.default)不可达时, 检查 pod 出口是否在集群外(网络隔离), 快速放弃比穷举强
- 每节点 metadata 不同(负载均衡会漂到不同节点): 多读几次对比, 能拿到多个节点级凭据

## 6. 云 metadata 路径 (OpenStack/EC2 兼容)
- EC2 风格: `/latest/meta-data/`, `/latest/user-data`, `/latest/meta-data/iam/security-credentials/`
- OpenStack: `/openstack/latest/meta_data.json` (含 ovh-token/SSH 公钥/node 拓扑), `/openstack/latest/network_data.json`, `/openstack/latest/vendor_data.json`
- 拿到 token/公钥只是情报: OVH 类 provider token 对外部 API 通常无效, 别浪费时间; SSH 公钥无对应私钥时无用

## 7. 表达式注入面 (若目标有公式 DSL)
- DSL 公式(如 ticker()/orderbook())服务端求值的端点: 先弄清 body schema(**flat 对象**最可能被接受, 数组形式会 422)
- 用 422 报错 "Value required for: X" 迭代补字段, 直到错误变化或 404(404 = 业务对象缺失但格式已对)
- 对象创建接口若原样存公式不重编译 → 注入不是触发点, bot/执行端才是(常常被账号墙挡)
- 422 报错里的 schema 名字/字段是免费情报, 迭代利用

## 安全注意
- 全平台限流 + 风控: 批量自动化会触发账号级 "Change e-mail" 标记与 CF 403; 高价值探测人工慢打
- 内网扫描按授权 scope 进行, 横向到新宿主前先向用户展示攻击链与归属推断确认范围