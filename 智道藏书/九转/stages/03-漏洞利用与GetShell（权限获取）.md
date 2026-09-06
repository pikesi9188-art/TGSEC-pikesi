# 03. 漏洞利用 & GetShell（权限获取）

> 写作原则：本章按图中第 3 个板块整理，面向授权靶场、CTF、本地样本和企业自查。工具事实必须有来源；找不到可靠来源的工具只标“待核验”。本章重点讲“如何把漏洞验证做成可复现证据”，不把工具命中当作最终结论。

## 1. 这个板块到底在干什么？

大白话：第 2 章发现“门锁可能坏了”，第 3 章要做的是：**在授权范围内，用最小影响的方式证明这把锁是不是真的坏，并记录证据。**

“GetShell”在安全测试里通常表示获得目标系统上的命令执行或文件写入控制能力。在真实企业环境里，证明到什么程度要看授权范围：

```text
版本证据 → 可控回显 → 可控 DNS/日志 → 受限命令执行 → 受限文件写入 → 完整交互 Shell
```

越往后风险越高，越需要明确授权、隔离环境和回滚方案。

事实依据：

- OWASP WSTG 把测试过程建立在识别入口点、验证输入处理、认证/授权、会话管理等基础上，强调测试要基于证据。[^owasp-wstg]
- NIST SP 800-115 将漏洞扫描和渗透测试区分开：扫描给线索，渗透测试通过实际验证证明风险。[^nist-800-115]
- CISA 和 NSA 的 Web Shell Malware 指南强调 WebShell 是攻击者常用持久访问方式，防守方需要检测、清除和加固。[^cisa-webshell]

---

## 2. 图中第 3 板块拆解

| 图中分类 | 图中工具/关键词 | 入门者理解 |
|---|---|---|
| 抓包调试工具（漏洞复现） | burpsuite pro、fiddler、httpcanary、RequestTemplate | 把浏览器/APP 请求抓出来，改参数、重放、对比响应。 |
| WebShell 管理工具（核心提权入口） | 蚁剑、冰蝎 Behinder/Behinder4、哥斯拉、天蝎、webshells、webshell_Key | 管理已存在的 WebShell、分析流量特征、做本地靶场复现与防守检测。 |
| 专项漏洞利用工具 | poc2jar-WINDOWS、serain、oracleShell、postger、redis-rogue-server、LiqunKit、ask_tool.jar、MYExploit.jar | 针对某些组件或漏洞链的复现工具；必须绑定版本、环境和证据。 |

---

## 3. 抓包调试工具：漏洞复现的“显微镜”

### 3.1 可核验工具事实

| 工具 | 可核验事实 | 来源 |
|---|---|---|
| Burp Suite / Burp Suite Professional | PortSwigger 官方说明 Burp Suite 是 Web 应用安全测试平台，包含 Proxy、Repeater、Intruder、Scanner 等功能。 | [PortSwigger Burp Suite](https://portswigger.net/burp) |
| Fiddler | Fiddler 官方说明其是 Web debugging proxy，可捕获、检查和调试 HTTP/HTTPS 流量。 | [Telerik Fiddler](https://www.telerik.com/fiddler) |
| HTTP Canary / HttpCanary | 官方/应用页面描述其用于 Android HTTP/HTTPS/HTTP2/WebSocket/TCP/UDP 抓包与调试；不同分发源版本差异较大，安装源需核对。 | [HttpCanary 站点](https://httpcanary.com/) |
| RequestTemplate | 本轮没有找到能唯一对应图片名称的稳定官方来源。 | 待核验 |

### 3.2 大白话理解

抓包工具不是“攻击工具”，它首先是**证据工具**：

- 看登录到底发了什么参数；
- 看接口是不是带 Token；
- 看服务端返回了什么错误；
- 看改一个参数后响应是否变化；
- 把可复现请求保存成报告证据。

### 3.3 新手复现流程

```text
1. 正常访问一次业务流程，保存 baseline 请求/响应。
2. 找输入点：URL 参数、JSON 字段、Cookie、Header、文件名、上传内容。
3. 每次只改一个变量，避免不知道哪个变量导致变化。
4. 对比状态码、响应长度、响应字段、时间、日志或 DNS 证据。
5. 保存原始请求、响应、截图和工具版本。
```

证据模板：

```markdown
## REQUEST-ID

- 目标：https://HOST/PATH
- 工具：Burp Suite VERSION
- 原始请求：raw/request-001.txt
- 原始响应：raw/response-001.txt
- 改动点：PARAM 从 A 改为 B
- 观察结果：STATUS / LENGTH / BODY_DIFF / TIME_DIFF
- 结论：observed / negated / needs-auth
```

---

## 4. WebShell 管理工具：理解风险与防守检测

### 4.1 先讲清楚 WebShell 是什么

大白话：WebShell 就是放在 Web 服务器上的一个脚本入口，攻击者通过 HTTP 请求让它执行文件管理、命令执行、数据库连接等操作。防守视角看，它是**服务器被入侵后的控制入口**。

CISA/NSA 指南把 WebShell 描述为攻击者在被入侵 Web 服务器上放置的恶意脚本，用于维持访问、执行命令、移动和窃取数据。[^cisa-webshell]

### 4.2 图中工具事实表

| 工具/关键词 | 可核验事实 | 来源 |
|---|---|---|
| 中国蚁剑 / AntSword | GitHub 项目说明 AntSword 是跨平台网站管理工具。 | [AntSwordProject/antSword](https://github.com/AntSwordProject/antSword) |
| 冰蝎 / Behinder | GitHub 上 rebeyond/Behinder 项目存在，常见说明为动态二进制加密 WebShell 管理客户端。 | [rebeyond/Behinder](https://github.com/rebeyond/Behinder) |
| 哥斯拉 / Godzilla | GitHub 项目存在，常见说明为 WebShell 管理工具。 | [BeichenDream/Godzilla](https://github.com/BeichenDream/Godzilla) |
| 天蝎 | 同名工具/项目较多，本轮没有找到能唯一对应图片名称的稳定官方来源。 | 待核验 |
| webshells | 更像 WebShell 样本/工具集合目录名，不是唯一工具名。 | 待核验 |
| webshell_Key | 更像常见连接密钥/密码字典概念，不是唯一工具名。 | 待核验 |

### 4.3 防守视角看 WebShell 的证据

| 证据 | 可能说明什么 |
|---|---|
| Web 目录出现新 `.php/.jsp/.aspx` 文件 | 可能被写入脚本入口。 |
| 访问日志里出现奇怪 POST、长 Base64、固定密码字段 | 可能是 WebShell 通信。 |
| Web 进程启动系统命令 | 可能存在命令执行入口。 |
| 文件修改时间异常 | 可能是入侵后写文件或篡改。 |
| 出站连接异常 | 可能是反连或数据外传。 |

### 4.4 真实案例：Microsoft Exchange / HAFNIUM

Microsoft 在 2021 年披露 HAFNIUM 利用 Exchange Server 漏洞后部署 WebShell 的活动；CISA 也发布了与 Microsoft Exchange 漏洞相关的紧急指令和检测建议。这个案例说明：**漏洞利用和 WebShell 往往是连续链条：先利用漏洞，再落地脚本入口，再横向移动或窃取数据。**[^microsoft-hafnium][^cisa-exchange-2021]

---

## 5. 专项漏洞利用工具：工具只是“复现实验器”

### 5.1 图中工具状态

| 工具 | 本章处理方式 |
|---|---|
| poc2jar-WINDOWS | 本轮没有找到稳定官方来源；名称看起来像 POC 转 jar 或 Java POC 批处理工具，不做功能断言。 |
| serain | 本轮没有找到能唯一对应的稳定官方来源；图片备注为 DNSlog 反连，本章只讲 DNSlog 证据原理。 |
| oracleShell | 同名脚本/工具较多，不做功能断言。Oracle 相关漏洞以 Oracle CPU 与 CVE 为准。 |
| postger | 可能与 PostgreSQL 漏洞利用相关，但名称不稳定，不做功能断言。PostgreSQL 安全以官方公告为准。 |
| redis-rogue-server | GitHub 存在 redis-rogue-server 项目，用于 Redis 安全研究；Redis 官方安全文档强调保护 Redis 实例访问。 | [n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)、[Redis Security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/) |
| LiqunKit | 本轮没有找到能唯一对应图片名称的稳定官方来源。 |
| ask_tool.jar | 本轮没有找到能唯一对应图片名称的稳定官方来源。 |
| MYExploit.jar | 本轮没有找到能唯一对应图片名称的稳定官方来源。 |

### 5.2 DNSlog/反连证据怎么理解

大白话：很多 RCE/SSRF/反序列化漏洞不会直接把结果显示在页面上。测试者可以让目标访问一个自己控制的 DNS 域名，若 DNS 平台收到解析请求，就说明目标某个代码路径被触发。

记录模板：

```text
payload_id: PAYLOAD
callback_domain: TOKEN.dnslog.local
request_path: /PATH
observed_time: YYYY-MM-DD HH:MM
source_ip: TARGET
conclusion: only proves outbound DNS reached; does not prove full command execution
```

关键点：**DNS 请求能证明“有出网/有解析行为”，但不能自动证明“拿到 Shell”。**

### 5.3 Redis 相关风险怎么理解

Redis 官方安全文档强调，Redis 设计上应部署在受信任环境，并通过网络隔离、ACL、认证、TLS 等手段保护。[^redis-security]

入门者看到 Redis 时要先看：

- 是否暴露到不应暴露的网络；
- 是否需要认证；
- 是否允许危险命令；
- 是否启用 ACL；
- 是否有持久化/写文件相关配置风险。

### 5.4 Oracle / PostgreSQL / 数据库类利用

数据库类验证不要一上来追求命令执行。优先顺序：

```text
1. 端口和服务确认
2. 认证方式确认
3. 版本与补丁确认
4. 权限边界确认
5. 配置风险确认
6. 在授权环境验证具体 CVE
```

来源建议：

- Oracle Critical Patch Updates：Oracle 安全更新主入口。[^oracle-cpu]
- PostgreSQL Security Information：PostgreSQL 官方安全信息入口。[^postgres-security]

---

## 6. 从“工具命中”到“漏洞成立”的证明分级

| 级别 | 说明 | 例子 |
|---|---|---|
| hypothesis | 只是猜测 | 标题像 Jenkins。 |
| observed | 有观察证据 | 页面 footer 显示 Jenkins 版本。 |
| primitive | 证明一个基础原语 | 可控 DNS 请求、可控报错、可控时间差。 |
| local_proof | 本地靶场复现成功 | 同版本 Docker 靶场可复现。 |
| remote_proof | 授权目标低风险验证成功 | 授权窗口内得到可控、可回滚证据。 |

报告里不要跳级：

```text
发现 DNSlog 回连 ≠ 已 GetShell
发现可上传文件 ≠ 已 RCE
发现 WebShell 文件 ≠ 已完全控制内网
```

---

## 7. 入门练习：本地靶场漏洞复现报告

在本地靶场 `HOST` 做一次完整漏洞复现，不要求 Shell，只要求证据链：

```text
1. baseline：正常请求/响应。
2. modified：只修改一个参数的请求/响应。
3. observation：状态码、响应体、时间、DNSlog 或日志变化。
4. conclusion：漏洞是否成立，成立到哪个证明级别。
5. cleanup：删除测试文件、还原配置、记录影响。
```

目录建议：

```text
artifacts/03-exploit/
  raw/
    request-baseline.txt
    response-baseline.txt
    request-test-001.txt
    response-test-001.txt
  img/
    burp-repeater-001.png
  notes/
    proof-chain.md
```

---

## 8. 常见误区

| 误区 | 为什么错 | 正确做法 |
|---|---|---|
| 工具能连上 WebShell 就算报告完成 | 需要说明漏洞入口、写入方式、权限和影响 | 写清楚入口、请求、文件路径、进程权限、清理步骤。 |
| DNSlog 有回连就写 RCE | 回连只证明某个出网路径 | 明确写“出网原语成立”，不要扩大结论。 |
| 复现时一次改很多参数 | 无法判断哪个变量有效 | 每次只改一个变量。 |
| 不保存原始请求 | 不能复现，也不能让别人审核 | 保存 raw request/response。 |
| 忽略清理 | 会留下风险或污染环境 | 复现后按清单删除测试文件、临时账号、日志标记。 |

---

## 9. 本章来源

[^owasp-wstg]: OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
[^nist-800-115]: NIST SP 800-115: https://nvlpubs.nist.gov/NISTpubs/Legacy/SP/NISTspecialpublication800-115.pdf
[^cisa-webshell]: CISA / NSA, Web Shell Malware: https://www.cisa.gov/resources-tools/resources/web-shell-malware
[^microsoft-hafnium]: Microsoft, HAFNIUM targeting Exchange Servers: https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
[^cisa-exchange-2021]: CISA Emergency Directive 21-02, Microsoft Exchange vulnerabilities: https://www.cisa.gov/news-events/directives/ed-21-02
[^redis-security]: Redis docs - Security: https://redis.io/docs/latest/operate/oss_and_stack/management/security/
[^oracle-cpu]: Oracle Critical Patch Updates: https://www.oracle.com/security-alerts/
[^postgres-security]: PostgreSQL Security Information: https://www.postgresql.org/support/security/

### 工具资料来源

- Burp Suite：https://portswigger.net/burp
- Fiddler：https://www.telerik.com/fiddler
- HttpCanary：https://httpcanary.com/
- AntSword：https://github.com/AntSwordProject/antSword
- Behinder：https://github.com/rebeyond/Behinder
- Godzilla：https://github.com/BeichenDream/Godzilla
- redis-rogue-server：https://github.com/n0b0dyCN/redis-rogue-server
