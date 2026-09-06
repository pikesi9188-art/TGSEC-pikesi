---
name: 春府·开棺
description: >-
 授权目标上 Spring Boot 业务 JAR 暴露 /actuator（含 heapdump）时的杀伤链：
 探测端点 → Range/分桶下堆 → 抽阿里云AK/JDBC/Redis → GetCallerIdentity/RunCommand
 或上传RCE落SSH → 芋道隐藏超管 syscache。金标准 admnrlytlhub / bk_assets。
  若出现 gateway/routes 则改走 Spring Gateway Playbook。
  下堆后必须 heap_cred_scan（正则+蓝鸟蜘蛛），禁止只扫 health。
---

# Spring Boot Actuator → 云/主机接管

**前提**：目标在 `授权范围`。静默扩权 API/ECS IP。

**不是** Spring Cloud Gateway SpEL 链。Gateway 指纹（`/actuator/gateway/routes`、白名单旁路）→ 读 `spring-actuator-cloud-takeover` rule + 对应 Playbook。

## 何时启用

- `/actuator` 列出 endpoints，或 `/actuator/heapdump` 可 HEAD/Range 
- 芋道/股票盘 API（`admin-api`、`tenant-id`）伴生 Druid/Swagger 
- 若同时出现 `mock-enable` / `file-config` / `df-user` → **并行** `yudao-daifu-mock-file-rce`（可能比 heapdump 更短）
- 用户点名：heapdump、阿里云 AK、RunCommand、syscache
- 案卷里已经有 `.hprof` / `.phd`：**先拆堆**（`heap_cred_scan.py`），不必等用户说蓝鸟 

## 强制顺序

1. `python3 炼蛊房/actuator_probe.py --base https://API --out …/案卷/actuator/` 
2. 若 `gateway/routes` 像 SCG → **切换** Gateway Playbook，勿只扫 health 
3. heapdump：分桶下载（按 IP+HOSTNAME+total）→ `炼蛊房/heap_cred_scan.py`（正则 + 蓝鸟对象图，见 `heapdump-lanniao-hunter`） 
4. 验证凭据：`LTAI` → Identity；JDBC/Redis 探针 
5. Root AK → `DescribeInstances` + Cloud Assistant `RunCommand`（22 可不开） 
6. 无云 Root → 超管/上传 RCE 写 SSH（参考 `bk_assets` CHAIN） 
7. `yudao_hidden_admin_sql.py` 生 SQL → 本机 mysql 植入 → `tenant-id: 201` 登录探针 
8. STATUS + 凭据 JSON；大 heapdump 可外置 

## 成功口径

- 云：`whoami`/RunCommand root 或 Identity 确认后可控 ECS 
- 业务：`syscache`（或等价）登录成功且可调管理 API 
- 仅 `health:UP` **不算**成功 

## 真源

- Playbook：`传承/春府·开棺.md` 
- 总册：`传承/春秋蝉·分案.md` §C1–C2 
- 案卷：`admnrlytlhub_20260805/完整接管报告.md` · `bk_assets_20260806/接管/deep/rce_ssh/CHAIN_ACTUATOR_TO_SSH.md` 

## 禁止

- 未授权账号/桶扩展 
- 真删 ECS 全集群（先问） 
- 混节点合并 heapdump 
- 把报告第三方 UAT 扩进 scope 
