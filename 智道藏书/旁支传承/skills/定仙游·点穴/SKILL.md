---
name: 定仙游·点穴
description: "Use when SSRF 扫内网端口: 500≠closed, 按状态码+响应体判 DB/kubelet 开放."
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [pentest, ssrf, portscan, kubernetes]
    category: daaixianzun
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# SSRF 内网端口探测 — 状态码分类判定法

## 触发场景
拿到一个**回显式 SSRF**(POST 出去并回显后端 HTTP 客户端响应体, 如 python-httpx)后要**扫内网端口找 DB/Redis/kubelet/metadata**。
最常见的错误: 扫描脚本把所有"非 HTTP 响应"当成 ERR/关闭过滤掉, 结果**数据库/HTTPS 管理端口全漏判**, 误以为内网是空的。

## 核心判定映射 (必须按 状态码+响应体 判, 不能只看 timeout/exception)
对回显式 SSRF(后端用 httpx/requests, 会把目标端口的响应或连接错误转成自己的 HTTP 状态):

| SSRF 回显 | 判定 | 示例 |
|---|---|---|
| HTTP 200/开头的 4xx(非 CF 1010 页) | **HTTP 服务存活** | FastAPI、Squid 400、CoreDNS 404 |
| HTTP **500 "Internal Server Error"** | **端口 OPEN = 非 HTTP 协议**(DB/redis/ssh/mongo) | Postgres 5432、Redis 6379、MySQL 3306 |
| HTTP **400 "Client sent an HTTP request to an HTTPS server"** | **端口 OPEN = 这是 HTTPS 服务** | kubelet 10250、k8s apiserver 443 |
| HTTP **429 crl/rate_limit** | 触发全局限流, 冷却 45-60s 再继续 | 应用层全局 crl |
| HTTP **403 + "error code: 1010"** (CF 页) | **虚拟段/CF Tunnel 前置, 非真实服务** | 10.4.0.0/24 等假网段 |
| 5s+ 超时 / 连接拒绝 | 关闭 或 防火墙 drop (无法区分) | — |

**关键陷阱**: `500 Internal Server Error` 是 httpx 对非 HTTP 端口连接成功后的解析失败,被上游 HTTP 框架包成 500。
绝大多数扫描脚本写 `if '500' in code: skip` → 把数据库端口当关闭。**DB/Redis 端口开的信号恰恰就是这个 500。**

## 落地脚本要点 (db_probe 类)
- 用 `urllib/requests` 调 SSRF 端点, 目标 path = `http://<ip>:<port>/`
- 异常分类改为捕获后按 `str(e)` 文本归类, 而非直接当失败:
  - `Connection refused` / `111` → REFUSED (关闭)
  - `timed out` → TIMEOUT (过滤/墙)
  - `Remote end closed` / `Bad status line` / `EOF` → OPEN-NONHTTP (DB!)
  - `Server disconnected` → OPEN-NONHTTP
- 输出只记 `HTTP` 和 `OPEN-NONHTTP` 两类命中, 其余静默
- 限流: 每次 sleep 0.25s; 遇 429 冷却 45-60s; 对关闭端口超时设 3-4s 否则全量扫太慢
- 双入口 SSRF 若存在(如 base_url=API|ONBOARD), 用不同 base 避开同一限流桶

## 验证对照法
先把已知真/假目标各打一遍校准信号:
- 已知 HTTP: 打 Squid 8089 → 应得 400 Squid error 页 (对照"HTTP 存活")
- 已知关闭: 打 `:59999` 随机高端口 → 记它的响应形态(校准 timeout/refused)
- 已知 HTTPS: 打 kubelet 10250 → 记 "Client sent HTTP to HTTPS" 400
再对目标网段批量扫, 用校准后的映射过滤。

## 实战案例 (origami.tech, 2026-08-07)
- 早先 internal_scan*.py 把 `Internal Server Error` 当失败全部排除 → 10.4.2.96 的 5432/6379/3306 全被误判"关闭"
- 用状态码判定法发现 kubelet 10250 在 10.4.1.165/10.4.3.189 返回 `400 Client sent HTTP to HTTPS` = **端口开放** (REPORT 漏判)
- 10.3.x K8s service CIDR 大量 403/429 = CF 虚拟化; 但 CoreDNS 10.3.0.10:9153 `/metrics` 返回真 200 (认识真实 HTTP 与虚拟段的差别)
- 教训: 回显式 SSRF 的映射直接由**后端 HTTP 客户端的连接处理**决定, 不是 SSRF 端点自己的业务码

## 关联
- 本技能独立于具体站, 是通用内网端口测绘技术。
- 具体目标证据/资产清单见各站点 skill (如 daaixianzun/origami-tech-pentest) 的 references/。