---
name: 罩辨
description: Detect WAF/CDN type and choose bypass strategy.
version: 1.0.0
author: 大爱仙尊
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [waf, cdn, daaixianzun, pentest]
    category: daaixianzun
---
# WAF 检测与绕过 Skill v2.0

Detect WAF/CDN type and choose bypass strategy.

## 立刻跑

1. `NOW`: confirm task matches skill `waf-detector`
2. `NOW`: if scope not built yet, read nine-stage-auto-router / attack-router first
3. `ACT`: follow workflow below; on new finding class, switch skill immediately

本 skill 提供独立的可执行 WAF 检测与绕过 CLI 工具 `waf_hunter.py`，位于 `/workspace/waf-detector/` 目录下。

> **v2.0 升级**: 150+ WAF 厂商指纹 + 333+ Bypass Payload + 2026 最新绕过技术（HTTP/3 QUIC 绕过、AI 驱动 WAF 逆向、基于 ML 的规则预测、分块传输编码混淆、HTTP/2 多路复用、TLS 指纹伪装）+ 国内 WAF 专项（阿里云/腾讯云/华为云/百度云加速/长亭/安全狗/知道创宇/创宇盾/奇安信/深信服/绿盟/安恒/网宿/白山云/又拍云/七牛云/金山云/UCloud/京东云/火山引擎）

## 触发条件

- WAF 检测 / WAF 识别 / 防火墙检测
- WAF bypass / 绕过 WAF
- SQLi/XSS/LFI/RCE/SSRF/SSTI  payload 测试
- 检测网站是否被 WAF 保护
- 生成 WAF 检测报告
- 2026 最新 WAF 绕过技术研究

## 工具位置

所有工具文件位于 `/workspace/waf-detector/` 目录：
- `waf_hunter.py` — CLI 主入口（v2.0）
- `waf_detector/` — Python 工具包
  - `fingerprints.py` — 150+ WAF 指纹库
  - `payloads.py` — 333+ Bypass Payload 库
  - `detector.py` — 9维指纹检测引擎
  - `verifier.py` — 误报消除器（三重验证）
  - `generator.py` — Payload 变异引擎（11种变异策略）
  - `reporter.py` — 多格式报告生成（JSON/HTML/MD/CSV/SARIF）
- `requirements.txt` — 依赖（aiohttp>=3.9.0）
- `tests/test_detector.py` — 单元测试

## 执行方式

### 重要：执行前必须切换到工具目录

```bash
cd /workspace/waf-detector
```

所有 `python waf_hunter.py` 命令必须在 `/workspace/waf-detector` 目录下执行。

### 1. 查看指纹库统计

```bash
python waf_hunter.py stats
# 输出: 150+ WAF 厂商、333+ payload、9 个检测维度
```

### 2. 单目标 WAF 检测

```bash
python waf_hunter.py detect -t https://example.com
# 输出 JSON 格式: WAF 类型、置信度、匹配指标、CDN、IP
```

### 3. 批量检测（从文件）

```bash
python waf_hunter.py detect -f targets.txt --concurrency 20 -o results.json
```

### 4. 通过管道批量检测

```bash
cat targets.txt | python waf_hunter.py detect --format csv -o waf.csv
```

### 5. WAF 绕过测试

```bash
python waf_hunter.py bypass -t https://example.com --waf cloudflare --attack sqli
# 攻击类型: sqli, xss, lfi, rce, ssrf, ssti, cmdi
```

### 6. 完整流程（检测 + 绕过 + HTML 报告）

```bash
python waf_hunter.py full -t https://example.com --format html -o report.html
```

### 7. 误报验证

```bash
python waf_hunter.py verify -t https://example.com
```

### 8. 列出所有 WAF

```bash
python waf_hunter.py list
python waf_hunter.py list --category cloud
python waf_hunter.py list --category chinese
python waf_hunter.py list --category hardware
```

### 9. 输出格式

- `json` (默认) — 结构化 JSON
- `html` — 可视化 HTML 报告
- `md` — Markdown 表格
- `csv` — CSV 表格
- `sarif` — SARIF 2.1.0（CI/CD 集成）

### 10. 代理支持

```bash
python waf_hunter.py detect -t https://example.com --proxy socks5://127.0.0.1:1080
```

### 11. 2026 高级绕过

```bash
# HTTP/3 QUIC 绕过（实验性）
python waf_hunter.py bypass -t https://example.com --waf cloudflare --attack sqli --use-http3

# 分块传输编码绕过
python waf_hunter.py bypass -t https://example.com --waf imperva --attack sqli --chunked

# TLS 指纹伪装绕过
python waf_hunter.py bypass -t https://example.com --waf akamai --attack xss --tls-fingerprint chrome120
```
---
## 完整 WAF 厂商指纹库（150+ 厂商）

### 国际云 WAF / CDN WAF

| 厂商 | 类别 | 关键指纹特征 | 检测置信度 |
|------|------|-------------|-----------|
| Cloudflare | cloud | cf-ray, __cf_bm, cf_clearance, server: cloudflare, /cdn-cgi/trace | 99% |
| Cloudflare Enterprise | cloud | cf-ray, cf-edge, cf-cache-status, managed challenge | 99% |
| AWS CloudFront | cloud | x-amz-cf-id, x-amz-cf-pop, via: CloudFront | 98% |
| AWS WAF | cloud | x-amzn-RequestId, x-amzn-ErrorType, awselb | 95% |
| AWS Shield Advanced | cloud | x-amzn-* headers + DDoS mitigation patterns | 90% |
| Azure Front Door | cloud | x-azure-ref, x-azure-socketip, Server: Microsoft-Azure-Application-Gateway | 97% |
| Azure WAF (Application Gateway) | cloud | x-ms-request-id, x-azure-ref, OWASP CRS patterns | 95% |
| Google Cloud Armor | cloud | via: 1.1 google, server: Google Frontend, x-cloud-trace-context | 94% |
| GCP Cloud CDN | cloud | via: 1.1 google, Server: Google Frontend, server-timing | 93% |
| Akamai | cloud | X-Akamai-*, X-Cache, AkamaiGHost, Server: AkamaiGHost | 98% |
| Akamai Kona (WAF) | cloud | X-Akamai-*, akamai-origin-hop, akamai | 96% |
| Fastly | cloud | X-Served-By, X-Cache, via: Fastly, Fastly-Ip | 98% |
| Fastly WAF (Signal Sciences) | cloud | sigsci-*, x-sigsci-*, X-Signal-Sciences | 95% |
| Imperva Incapsula | cloud | X-CDN, X-Iinfo, visid_incap_, incap_ses_ | 97% |
| Imperva Cloud WAF | cloud | X-Imperva-*, Imperva-CDN, imperva | 95% |
| Sucuri | cloud | X-Sucuri-ID, X-Sucuri-Cache, Server: Sucuri/Cloudproxy | 95% |
| StackPath | cloud | X-StackPath-*, via: stackpath, server: StackPath | 93% |
| Edgecast / Verizon | cloud | X-EC-*, via: edgecast, server: ECD | 92% |
| CDN77 | cloud | X-CDN77-*, via: cdn77, server: CDN77 | 92% |
| BunnyCDN | cloud | X-BunnyCDN-*, server: BunnyCDN, CDN-Cache | 93% |
| KeyCDN | cloud | X-Cache: HIT, server: keycdn, via: keycdn | 91% |
| Gcore | cloud | Server: GCore, X-Cache, via: GCore | 90% |
| Quantil / ChinaCache | cloud | X-Cache, via: quantil, server: quantil | 88% |
| Leaseweb CDN | cloud | X-Cache, via: leaseweb, server: Leaseweb | 87% |
| CDNetworks | cloud | X-Cache, via: CDNetworks, server: CDNetworks | 90% |
| ArvanCloud | cloud | Server: ArvanCloud, X-ArvanCloud-*, via: ArvanCloud | 92% |
| HiberniaCDN | cloud | X-Cache, via: hiberniacdn, server: Hibernia | 85% |
| Oracle Cloud WAF | cloud | X-Oracle-*, oracle, server: Oracle-HTTP-Server | 88% |
| IBM Cloud Internet Services | cloud | x-ibm-*, via: IBM, server: IBM | 86% |
| Alibaba Cloud WAF (国际版) | cloud | X-WAF-*, aliyun, server: Alibaba | 92% |
| Tencent Cloud EdgeOne (国际) | cloud | EO-*, edgeone, server: tencent-cos | 92% |

### 国内 WAF 厂商

| 厂商 | 类别 | 关键指纹特征 | 检测置信度 |
|------|------|-------------|-----------|
| 阿里云 WAF | cloud | X-WAF-*, aliyun, ali-cdn, server: Tengine/Alibaba | 95% |
| 阿里云 CDN | cloud | X-Cache, X-Swift-*, via: alicdn, server: Tengine | 97% |
| 腾讯云 WAF | cloud | stgw-*, TencentCloud, X-NWS-LOG-UUID | 94% |
| 腾讯云 EdgeOne | cloud | EO-*, edgeone, EO-LOG-UUID | 95% |
| 华为云 WAF | cloud | X-HW-*, huawei, server: hcdn | 93% |
| 华为云 CDN | cloud | X-HW-*, huawei, via: Huawei-CDN | 93% |
| 百度云加速 | cloud | Server: bfe, YJS-*, X-Edge-IP | 93% |
| 百度 WAF | cloud | YJS-*, Server: bfe, baidu | 90% |
| 长亭 WAF (SafeLine/雷池) | cloud | X-SafeLine-*, safeline, chaitin | 92% |
| 长亭雷池 | cloud | X-SafeLine-*, X-Chaitin-*, x-cdn | 90% |
| 知道创宇 (创宇盾) | cloud | X-Knownsec-*, knownsec, 创宇盾 | 91% |
| 奇安信 WAF | cloud | X-Qianxin-*, qianxin, 奇安信 | 89% |
| 深信服 WAF | cloud | X-Sangfor-*, sangfor, 深信服 | 89% |
| 绿盟 WAF | cloud | X-NSFOCUS-*, nsfocus, 绿盟 | 88% |
| 安恒 WAF | cloud | X-Anheng-*, anheng, 安恒 | 86% |
| 网宿 WAF | cloud | X-WS-*, wangsu, via: wangsu | 91% |
| 白山云 WAF | cloud | X-Baishan-*, baishan, X-Cache | 87% |
| 又拍云 WAF | cloud | X-Upyun-*, via: upyun, server: upyun | 90% |
| 七牛云 WAF | cloud | X-Qiniu-*, qiniu, server: qiniu | 89% |
| 金山云 WAF | cloud | X-KSCDN-*, X-Cache, ksyun | 86% |
| UCloud WAF | cloud | X-UCDN-*, via: ucdn, server: ucloud | 85% |
| 京东云 WAF | cloud | X-Cache, via: jdcloud, server: jdcloud | 85% |
| 火山引擎 WAF | cloud | X-Volc-*, volc, server: volc-cache | 87% |
| 安全狗 WAF | cloud | SafeDog, safedog, X-SafeDog-* | 88% |
| 360 网站卫士 | cloud | X-360-*, 360wzb, 360 网站卫士 | 87% |
| 天融信 WAF | cloud | X-Topsec-*, topsec, 天融信 | 84% |
| 启明星辰 WAF | cloud | X-Venus-*, venustech, 启明星辰 | 84% |
| 山石网科 WAF | cloud | X-Hillstone-*, hillstone, 山石 | 82% |

### 开源 WAF

| 厂商 | 类别 | 关键指纹特征 | 检测置信度 |
|------|------|-------------|-----------|
| ModSecurity | software | Mod_Security, mod_security, This error was generated by Mod_Security | 90% |
| ModSecurity OWASP CRS | software | mod_security, OWASP_CRS, ModSecurity | 92% |
| NAXSI | software | naxsi, X-NAXSI-*, NAXSI | 85% |
| AQTRONIX WebKnight | software | WebKnight, AQTRONIX, webknight | 82% |
| Shadow Daemon | software | shadowd, Shadow Daemon, x-shadowd | 80% |
| Comodo WAF | software | Comodo, CWAF, comodo | 83% |
| Generic WAF (Apache) | software | waf, firewall, security, access denied | 70% |
| JS Challenge | software | jschallenge, javascript challenge, js_challenge | 75% |

### 硬件 WAF / 下一代防火墙

| 厂商 | 类别 | 关键指纹特征 | 检测置信度 |
|------|------|-------------|-----------|
| F5 BIG-IP ASM | hardware | F5, BigIP, ASM, X-Cnection, TS* | 93% |
| F5 BIG-IP AWAF | hardware | F5, BigIP, AWAF, X-WA-Info | 92% |
| Fortinet FortiWeb | hardware | FortiWeb, fortigate, fortiweb | 92% |
| Fortinet FortiGate | hardware | FortiGate, fortigate, fortinet | 91% |
| Citrix NetScaler | hardware | Citrix, NetScaler, ns_af, citrix_ns_id | 92% |
| Citrix NetScaler AppFW | hardware | Citrix, NetScaler, AppFW, application firewall | 90% |
| Barracuda WAF | hardware | Barracuda, barracuda_, barra | 90% |
| Barracuda CloudGen | hardware | Barracuda, CloudGen, barracuda | 88% |
| Imperva SecureSphere | hardware | Imperva, SecureSphere, visid_incap | 88% |
| Radware AppWall | hardware | Radware, AppWall, X-Radware | 87% |
| NSFOCUS WAF (硬件) | hardware | NSFOCUS, nsfocus, X-NSFOCUS-* | 86% |
| Sangfor NGAF | hardware | Sangfor, sangfor, X-Sangfor-* | 86% |
| Palo Alto NGFW | hardware | PAN-OS, paloalto, X-PAN | 85% |
| Check Point NGFW | hardware | CheckPoint, checkpoint, X-CheckPoint | 85% |
| Sophos XG Firewall | hardware | Sophos, sophos, X-Sophos | 83% |
| WatchGuard Firebox | hardware | WatchGuard, watchguard, X-WatchGuard | 82% |
| Juniper SRX | hardware | Juniper, juniper, X-Juniper | 81% |
| Huawei USG | hardware | Huawei, USG, huawei-usg | 84% |
| H3C SecPath | hardware | H3C, SecPath, h3c | 83% |
| Ruijie RG-WALL | hardware | Ruijie, RG-WALL, ruijie | 80% |
| Hillstone NGFW | hardware | Hillstone, hillstone, X-Hillstone | 82% |
| Venusense NGFW | hardware | Venusense, venustech, X-Venus | 81% |

### 新兴云 WAF (2025-2026)

| 厂商 | 类别 | 关键指纹特征 | 检测置信度 |
|------|------|-------------|-----------|
| Vercel Edge Functions | edge | x-vercel-*, vercel, x-vercel-id | 90% |
| Netlify Edge | edge | x-nf-*, netlify, x-nf-request-id | 88% |
| Cloudflare Workers WAF | edge | cf-ray, cf-worker, x-ew | 92% |
| Deno Deploy | edge | x-deno-*, deno, x-deno-ray | 85% |
| Fly.io Edge | edge | fly-*, fly.io, x-fly-* | 84% |
| Supabase Edge Functions | edge | x-supabase-*, supabase, x-sb-* | 83% |
| Bunny Edge | edge | x-bunny-*, bunnycdn, edge | 86% |
| AWS Lambda@Edge | edge | x-amz-cf-id, lambda, via: CloudFront | 88% |
| Azure Functions (Edge) | edge | x-azure-ref, x-functions-*, functions | 85% |
| GCP Cloud Functions | edge | via: 1.1 google, function, cloudfunctions | 84% |
| Railgun | accelerator | cf-railgun, railgun, x-cf-railgun | 82% |
| APISIX | api-gateway | apisix, x-apisix, APISIX | 83% |
| Kong | api-gateway | kong, x-kong-*, X-Kong | 85% |
| Traefik | api-gateway | traefik, x-traefik, Traefik | 84% |
| Envoy Proxy | proxy | envoy, x-envoy-*, x-envoy | 83% |
---
## 2026 最新 WAF 绕过技术

### 一、HTTP/3 QUIC 绕过

HTTP/3 QUIC 协议使用 UDP 传输，许多 WAF 仍基于 TCP 检测，存在检测盲区：

```bash
# 使用 curl HTTP/3 绕过 WAF
curl --http3 -X POST https://target.com/api -d "malicious_payload"

# 使用 quiche 客户端
quiche-client https://target.com --http3
```

**绕过原理**：多数 WAF 不支持 HTTP/3 流量检测，QUIC 加密握手层超出传统 WAF 检测范围。

### 二、AI 驱动 WAF 规则逆向

使用 LLM 分析 WAF 拦截页面，推断规则并生成绕过 payload：

```python
# AI 辅助 WAF 规则逆向
from waf_detector.generator import WAFPayloadGenerator

gen = WAFPayloadGenerator(use_ai=True)
gen.analyze_block_page("https://target.com", response_html)
generated_payloads = gen.generate_adaptive_payloads("sqli", waf_type="cloudflare")
```

**技术要点**：
- 分析 WAF 拦截页面的差异特征
- 提取被拦截的 token 模式
- 使用 LLM 生成安全语义等价但语法变异的 payload
- 基于规则的强化学习策略优化

### 三、分块传输编码绕过

利用 HTTP/1.1 Transfer-Encoding: chunked 进行 WAF 欺骗：

```http
POST /api/login HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5
admin
3
' OR
6
 1=1--
0
```

**变体技术**：
- 分块大小混淆（不同 WAF 解析器对分块大小处理不一致）
- 分块扩展字段注入（`;comment` 语法绕过）
- 分块 smufling（多个 Transfer-Encoding 头）
- 分块边界在关键字中间（`ad` + `min` + `' OR 1=1`）

### 四、HTTP/2 多路复用绕过

利用 HTTP/2 帧多路复用特性绕过 WAF：

```python
import h2.connection
import socket

# HTTP/2 多流并发绕过
conn = h2.connection.H2Connection()
conn.initiate_connection()
# 流1: 正常请求
conn.send_headers(stream_id=1, headers=[(':method', 'GET'), (':path', '/')])
# 流3: 恶意请求（WAF 可能忽略奇数流）
conn.send_headers(stream_id=3, headers=[(':method', 'POST'), (':path', '/api'), ('x-payload', 'malicious')])
```

### 五、TLS 指纹伪装

使用不同 TLS 指纹绕过基于 JA3/JA4 的 WAF 检测：

```bash
# 使用 curl-impersonate 伪装成 Chrome 120
curl-impersonate-chrome -X POST https://target.com/api -d "payload"

# Python 使用 tls_client
import tls_client
session = tls_client.Session(client_identifier="chrome_120")
session.post("https://target.com/api", data={"payload": "malicious"})
```

### 六、2026 AI 驱动的 WAF 绕过框架

```python
from waf_detector.generator import AdaptiveWAFBypass

bypass = AdaptiveWAFBypass(target="https://target.com", waf="cloudflare")
bypass.auto_learn()  # 自动学习 WAF 行为
bypass.optimize()    # 强化学习优化 payload
results = bypass.run_attack("sqli")
```

**核心能力**：
- 自动探测 WAF 规则边界
- 基于强化学习的 payload 自适应优化
- 多轮交互式规则学习
- 成功率实时反馈闭环
---
## 常用 WAF 绕过策略矩阵（2026 增强版）

### 按攻击类型分类

| 攻击类型 | 通用绕过技术 | Cloudflare 专项 | 阿里云 WAF 专项 | 腾讯云 WAF 专项 |
|---------|-------------|----------------|----------------|----------------|
| SQLi | 注释拆分, 大小写, 内联注释, 编码组合 | 换行+注释组合, 版本注释 | 双重URL编码, 宽字节 | GBK宽字节, 参数污染 |
| XSS | 编码变异, 事件处理器, SVG载体 | HTML实体+JS编码, 非标准标签 | 双重编码, 大小写组合 | Unicode编码, 冷门标签 |
| LFI | 路径编码, 双写绕过, null字节 | 路径截断, 编码链路 | 编码递归, 路径混淆 | 编码+截断, 路径回环 |
| RCE | 命令分隔符, 通配符, 编码 | 管道+编码, 反引号 | 编码+分隔符, 环境变量 | 编码+通配符, 管道组合 |
| SSRF | URL编码, DNS重绑定, 302跳转 | IP编码变体, 短链接 | 302重定向, 编码组合 | DNS重绑定, URL编码 |
| SSTI | 编码标签, 条件表达式, 过滤器绕过 | 多标签嵌套, 编码 | 双标签, 编码组合 | 编码+标签, 条件表达式 |

### 按 WAF 类型分类

| WAF 类型 | 首选绕过策略 | 次级策略 | 2026 新增策略 |
|---------|------------|---------|-------------|
| Cloudflare | 换行+注释组合, 版本注释 | HTTP/3 绕过, 分块传输 | TLS指纹伪装, 请求走私 |
| AWS WAF | URL编码组合, 超长payload | 多部分表单, JSON格式 | HTTP/2 多路复用 |
| Azure WAF | 编码组合, 请求方法变换 | 分块传输, 内容类型变换 | HTTP/3 QUIC |
| GCP Cloud Armor | 编码组合, 参数污染 | 请求方法变换, JSON格式 | HTTP/2 帧操纵 |
| Akamai | 注释+大小写, 编码 | 请求方法变换, 内容类型 | 分块传输, QUIC |
| Imperva | HTML实体编码, 编码组合 | 分块传输, 内容类型 | HTTP/2 多路复用 |
| 阿里云WAF | 双重URL编码, 宽字节注入 | 分块传输, 编码组合 | AI驱动自适应绕过 |
| 腾讯云WAF | Unicode编码, GBK宽字节 | 参数污染, 编码组合 | 请求走私, QUIC |
| 华为云WAF | 编码组合, 参数污染 | 分块传输, 内容类型 | HTTP/2 帧操纵 |
| 长亭雷池 | 编码组合, 语义绕过 | 请求方法, 内容类型 | AI规则预测绕过 |
| 安全狗 | 编码组合, 大小写 | 分块传输, 参数污染 | 请求走私 |
| ModSecurity | 关键字拆分, 注释 | 编码, 大小写, 参数污染 | 分块传输, HTTP/2 |
---
## 2026 WAF 演进趋势与对抗

### 趋势一：AI 驱动的 WAF 检测

2026 年 WAF 厂商大规模引入 AI/ML 检测模型：
- **Cloudflare AI WAF**：基于 LLM 的语义分析检测，理解请求意图而非仅匹配规则
- **AWS WAF ML**：基于 SageMaker 的自定义 ML 模型
- **阿里云 AI WAF**：基于大模型的攻击检测

**对抗策略**：
- 使用 AI 生成语法正确但语义变异 payload
- 对抗样本攻击（Adversarial Examples）
- 梯度泄露攻击（Gradient Leakage）
- 模型投毒（Model Poisoning）— 在训练数据中注入对抗样本

### 趋势二：API 安全与 WAF 融合

WAF 和 API 网关融合，检测 GraphQL/gRPC 等新型 API 协议。

**对抗策略**：
- GraphQL 查询拆分（多片段/别名）
- gRPC 流式分段发送
- WebSocket 帧分段

### 趋势三：边缘计算 WAF

WAF 部署在边缘节点（Cloudflare Workers, AWS Lambda@Edge）。

**对抗策略**：
- 利用边缘函数冷启动时延
- 跨区域请求差异化
- 边缘缓存投毒

### 趋势四：零信任架构下的 WAF

WAF 作为零信任架构的一部分，持续身份验证和动态策略。

**对抗策略**：
- 长期会话维持
- 信任链攻击
- 策略学习与时序分析
---
## 输出结果说明

### detect 结果字段

| 字段 | 说明 |
|-----|------|
| `target` | 目标 URL |
| `waf_detected` | 是否检测到 WAF |
| `waf_name` | WAF 名称（如 Cloudflare） |
| `confidence` | 置信度 0-1 |
| `matched_indicators` | 匹配的指标列表 |
| `response_status` | 响应状态码 |
| `ip_address` | 目标 IP |
| `cdn_detected` | 是否检测到 CDN |
| `cdn_provider` | CDN 提供商 |
| `detection_methods` | 命中的检测维度 |
| `waf_category` | WAF 类别（cloud/hardware/software/chinese） |
| `2026_tech_detected` | 是否检测到 2026 新技术特征 |

### bypass 结果字段

| 字段 | 说明 |
|-----|------|
| `payload` | 测试的 payload |
| `technique` | 绕过技术名称 |
| `blocked` | 是否被拦截 |
| `block_reason` | 拦截原因 |
| `bypass_success` | 是否绕过成功 |
| `confidence` | 绕过成功率预测 |
| `recommended_chain` | 推荐的组合绕过链 |
---
## 依赖

首次使用前安装依赖：
```bash
cd /workspace/waf-detector
pip install -r requirements.txt --break-system-packages
```

核心依赖：`aiohttp>=3.9.0`
---
## 技术架构

```
waf_hunter.py (CLI 入口 v2.0)
├── detect 子命令 → WAFDetector.detect() → 9维指纹匹配
│   ├── 维度1: HTTP 响应头关键字
│   ├── 维度2: 响应头值正则
│   ├── 维度3: Cookie 关键字
│   ├── 维度4: 响应体关键字
│   ├── 维度5: 状态码
│   ├── 维度6: HTML title
│   ├── 维度7: 主动探测
│   ├── 维度8: 行为指纹
│   └── 维度9: IP/ASN 范围
├── bypass 子命令 → WAFPayloadGenerator + WAFDetector.test_bypass()
│   ├── 11种变异策略
│   ├── AI驱动自适应优化
│   └── 多轮学习反馈
├── full 子命令 → 检测 + 多向量绕过 + 报告
├── verify 子命令 → WAFVerifier 三重验证
└── stats/list 子命令 → 指纹库查询
```
---
## 注意事项

1. **必须在工具目录下执行**：`cd /workspace/waf-detector` 后运行 `python waf_hunter.py`
2. **首次使用安装依赖**：`pip install -r requirements.txt --break-system-packages`
3. **批量扫描控制速率**：默认 5 req/s，可通过 `-r` 调整
4. **代理支持**：`--proxy http://...` 或 `--proxy socks5://...`
5. **断点续扫**：`--resume` 启用
6. **生产环境**：使用 `--insecure` 跳过 SSL 验证（仅测试环境）
7. **2026 高级功能**：`--use-http3`、`--chunked`、`--tls-fingerprint` 需要额外依赖
---
## 与其他技能联动

| 技能 | 联动场景 |
|------|---------|
| cdn-origin-tracing | WAF 检测后确认 CDN 类型，联动溯源找源站 IP |
| waf-bypass-techniques | 深度 WAF 绕过技术参考 |
| webshell-evasion | WAF 穿透 WebShell 上传 |
| sqli-sql-injection | SQL 注入 WAF 绕过实战 |
| xss-cross-site-scripting | XSS 绕过 WAF 实战 |
| request-smuggling | 请求走私 WAF 绕过 |
| web-cache-deception | 缓存投毒结合 WAF 绕过 |
| ai-llm-attack-surface | AI 模型投毒绕过 AI WAF |
---
## 深度知识库

完整的 WAF 检测理论知识、绕过技术详解、60 章深度优化内容见 `SKILL_knowledge.md`（本 skill 目录下）。
