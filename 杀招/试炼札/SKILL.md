---
name: 试炼札
description: >-
  大爱仙尊·CTF实战速查手册。工具指纹/漏洞速查/组合链/效率铁律。应对网络探测、指纹采集、漏洞匹配、攻击链构建场景。
---

# ctf-combat-notes（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/ctf-combat-notes/SKILL.md`
- 手法：`传承/逆骨·认族.md`
- 工具：`python3 炼蛊房/reverse_skill_route.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name ctf-combat-notes`

---

# CTF · 实战笔记与速查手册

> 遇到 CTF / 红队探测 / 指纹采集场景时，按此速查手册执行。覆盖：工具速查、端口指纹、常见场景、组合思路、效率铁律、坑点。

---

## 工具速查

### 网络探测
```bash
masscan -p1-65535 --rate=10000 <target>
nmap -sS -sV -O --script=banner -p <ports> <target>
httpx -l targets.txt -title -tech-detect -status-code -server
```

### 子域名 / DNS
```bash
subfinder -d <domain>
amass enum -d <domain>
ffuf -w subdomains.txt -u https://FUZZ.<domain>
dnsx -l domains.txt -a -txt -cname
```

---

## 指纹采集关键元数据

每个开放端口提取：
- HTTP：Server / X-Powered-By / Cookie名（PHPSESSID/JSESSIONID）/ CMS特征
- 数据库：版本（5.7.38 / PostgreSQL 13.2）/ 允许外部连接标志
- 中间件：Tomcat / nginx / Jetty / IIS / Docker / K8s / Redis / MongoDB / ES / Memcached
- 云元数据：`169.254.169.254` (AWS) / `100.100.100.200` (阿里云) / `/latest/meta-data/iam/security-credentials/`
- 特殊端口指纹：Redis +OK / MongoDB 服务器信息 / ES cluster_name / Docker ApiVersion

---

## 源码泄露侦测（自动化爬虫）

并行触发路径：
- `.git/HEAD` → `git-dumper` 全量下载 + 历史提交敏感关键词（password/secret/api_key/token）
- `.env` → 提取 DB_HOST / DB_PASSWORD / REDIS_PASSWORD / JWT_SECRET / AWS_ACCESS_KEY_ID
- `.svn/entries` / `.env.bak` / `backup.sql` / `wp-config.php.bak`

---

## 广域指纹映射表（20+攻击面）

| 指纹 / 现象 | 链式推理（发现→推断→组合→目标） | 终极目标 |
|---|---|---|
| Apache 2.4.49 | CVE-2021-41773 路径规范化绕过 → 可读 `/etc/passwd` / 写文件 → Webshell | Shell |
| Nginx + PHP-FPM | path_info 解析漏洞 → `?file=` 测试 LFI → 包含 `/proc/self/environ` / 日志注入 | Shell |
| Tomcat 8.5.23 | 默认弱口令 admin:admin → Manager 登录 → 部署 WAR 后门 | Shell |
| JBoss 4.x | `jmx-console` 未授权 → MainDeployer 远程部署 WAR | Shell |
| Redis 6379 未授权 | `CONFIG GET dir` → 写 SSH 公钥 / cron 任务 | Shell |
| MySQL 3306 弱口令 | `SELECT INTO OUTFILE` / UDF 提权 | Shell / DB |
| PostgreSQL 5432 弱口令 | `COPY ... FROM PROGRAM` 执行命令 | Shell |
| MongoDB 27017 未授权 | 空密码 → `admin` 库用户表 → 凭证重用 | DB / 后台 |
| Elasticsearch 9200 | CVE-2014-3120 / 2015-1427 Groovy 脚本 RCE | Shell |
| Memcached 11211 | 未授权 → 缓存敏感信息（Session/API Key）→ 劫持会话 | 后台 |
| Git 泄露（.git） | `git-dumper` → 硬编码密钥/数据库密码 → 登录后台/DB | 后台 / DB |
| SVN 泄露（.svn） | 遍历 `.svn/entries` → 发现配置文件 → 数据库凭证 | DB |
| 云元数据 API（169.254.169.254） | `/iam/security-credentials/` → 临时 AK/SK → 接管对象存储 / ECS | Shell（云主机） |
| Kubernetes 6443 匿名 | 匿名访问 → Pod 列表 → `kubectl exec` → 容器 Shell | Shell |
| Docker 2375 未授权 | TCP 开放 → 挂载宿主机根目录启动特权容器 → 逃逸 | Shell |
| Jenkins 8080 | `/script` Groovy 执行 → 直接命令执行 | Shell |
| WebLogic 7001 | CVE-2020-14882 控制台绕过 → 部署 WebShell | Shell |
| Struts2（.action） | 版本特征 → CVE-2017-5638 / S2-045 OGNL → RCE | Shell |
| WordPress xmlrpc.php | 爆破 / 插件漏洞 / File Manager 任意上传 → Shell | Shell |
| Drupal 7 | CVE-2018-7600（Drupalgeddon2）→ 写 Shell | Shell |
| Swagger UI | 暴露 API 接口 → 测试未授权接口 → 直接敏感操作（如加管理员） | 后台 |
| Spring Actuator `/env` | 未授权 → 修改配置 → `bootstrap.location` 远程加载恶意配置 → RCE | Shell |

---

## 组合链（多指纹联动）

| 组合场景 | 链式推理 | 目标 |
|---|---|---|
| Git泄露 + SSH弱口令 | `.git` 提取源码 → 密码与 SSH 相同 → 直接 SSH 登录 | Shell |
| Redis未授权 + Web可写路径 | `CONFIG SET dir /var/www/html` → 写 Webshell → 访问 Shell | Shell |
| Jenkins + 云元数据 | 脚本执行 → 访问 `169.254.169.254` 获取 AK → 云 CLI 操作 | Shell |
| SQL注入 + 文件写权限 | 联合查询写一句话木马到 Web 目录 → Shell | Shell |
| 文件包含 + 日志污染 | 包含 `/var/log/apache/access.log` → User-Agent 注入 PHP → RCE | Shell |
| SSRF + 内网 Redis | 利用内网 SSRF 访问 Redis 6379 → `gopher` 协议 → 写 SSH 公钥 | Shell |
| .env + 数据库直连 | 提取凭证 → 直连 DB → UDF / 写文件 | DB / Shell |

---

## 效率铁律（六条 + 五条禁止 + 五条正确行为）

### 六条铁律
1. **零秒启动**：接到目标瞬间触发所有扫描子任务，不等待任何确认
2. **30秒并行窗口**：指纹采集 + CVE 匹配并行，30秒内首轮全端口 + TOP 50 CVE
3. **子代理并行委派**：无依赖任务（Redis写SSH、MySQL写shell、Tomcat弱口令）立即并发
4. **CISA KEV 绝对优先**：KEV 目录中漏洞优先验证（在野利用成功率远高）
5. **源码发现 = 最短路径**：发现 `.git`/`.env`/备份压缩包立即中断低优先级任务，集中提取凭证
6. **链式推断 + 即时验证**：每条新发现立即触发推理链并执行验证，不堆到"待处理队列"

### 五条绝对禁止
1. ❌ 只跑工具不解读输出（每个版本必须转化为攻击假设）
2. ❌ CVE 失败后不降级到通用测试（必须试默认凭证/路径遍历/盲注）
3. ❌ 发现敏感文件（.env/.git）而不深入提取
4. ❌ 对同一目标重复扫描（已采集指纹的 IP:Port 不再全扫）
5. ❌ 发现管理后台（Swagger/Druid/Actuator）而不深入验证

### 五条正确行为
1. ✅ 指纹 → 立即启动源码狩猎（source_hunt.py）自动枚举
2. ✅ 指纹 → CVE 匹配，优先 KEV，按可用性排序
3. ✅ 每步回答"这告诉我什么？"、"能和什么组合？"、"通向哪个目标？"
4. ✅ 每30秒更新进度摘要（已发现资产数、已测漏洞数、最高权限级别、下一步计划）
5. ✅ 三大目标达成（有效后台 Session / 数据库写权限 / 远程 Shell）立即汇报并停止后续

---

## 常见坑

- nmap 扫完端口不去查对应版本漏洞 → 白扫
- 一个 CVE 打不通就放弃整个服务 → 应降级测默认口令/路径遍历/注入
- `.env`/`.git` 只标记存在不下载解析 → 白发现
- 同一个 IP:Port 反复全扫 → 浪费
- Swagger/Druid/Actuator 面板发现后不深入验证 → 放过关键入口
- `notify` 返回 success 但订单状态未变 → 不伪造"已到账"（⚠️ 未打穿）
- `.env` 路径返回 200 但内容是首页 HTML → 前端 SPA 路由伪装，非真实泄露（判断：Content-Type text/html + body 含 `<html>` 且长度接近首页 >10KB → 伪装）

---

## 报告纪律（每份报告必须遵守）

- 不伪造 CVE / 端点 / 证据
- 实际到账 / 200 / 数据量才标 ✅，否则 ⚠️
- 打不穿明确记"未攻破"，不硬编成功
- 身份/Token/APIKey 只是钥匙，只有可换成钱（卡密/用户数据/余额）的才算资产
- 即使无法变现，已攻破成果也必须完整写入报告
