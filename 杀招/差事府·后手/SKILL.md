---
name: 差事府·后手
description: >-
  XXL-JOB 后渗透基础设施链：GLUE 拿到 shell 后的完整后渗透路径。
  JAR 反编译提 application.yml、JDBC 侧向移动、Redis session 劫持、
  JWT 伪造、bcrypt 批量碰撞、Druid 监控接管、云凭据验活（Firebase SA / 微信小程序 / 腾讯云 AK）。
  当 xxljob-admin-glue-chain 打到 L3（GLUE 可执行）后自动交接到本卡。
  触发词：xxl-job 后渗透、GLUE 拿到 shell 后、XXL-JOB jar 提取、
  RuoYi Redis session、login_tokens、JDBC 侧向、JWT secret 伪造。
---

# XXL-JOB 后渗透 → 基础设施全链

前置：`xxljob-admin-glue-chain` L3（GLUE 可执行）  
真源：`传承/差事府·后手.md`  
实战案例：`案卷/xxljob-combo-20260901/`

## 何时用

- `xxljob-admin-glue-chain` 打到 L3 后，需要从"容器内 shell"升级到"数据库+session+云服务"
- 发现 Spring Boot JAR 部署的 Java 应用，已有命令执行权限
- 发现 RuoYi 系统，需要从 Redis 读取活跃 session 伪造 JWT

## 7 步链

```
1. JAR → application.yml  → JWT secret + Redis addr + MySQL JDBC + 云密钥
2. JDBC → 内网 MySQL      → 员工表(bcrypt) + 配置表(API keys) + VIP 规模
3. Redis → login_tokens:*  → 活跃 admin session UUID（注意 SELECT db1）
4. JWT secret + UUID        → 伪造 admin Bearer token
5. bcrypt → 离线碰撞       → 632 账号 123456 / admin321
6. Druid → weburi.json     → 请求中泄漏的 JWT + JDBC 明文密码
7. 云密钥 → Firebase SA / 微信 / 腾讯云 → 验活 + 枚举
```

## 关键陷阱

1. **RuoYi Redis 用 db1 不是 db0** — `SELECT 0` 看到 DBSIZE=0 不要放弃，`SELECT 1`
2. **外挂 YML 覆盖 JAR 内 YML** — 先查 `/app/volumn/*.yml`，再查 JAR 内的
3. **JWT 伪造外网可能被网关挡** — 从容器内 curl 内网应用 IP 绕过
4. **bcrypt 不能用 hashcat 模式直接碰** — 先检查是否多账号共享同哈希（=同密码），优先碰 123456/admin321

## 输入

| 参数 | 来源 |
|------|------|
| XXL-JOB GLUE 执行权 | `xxljob-admin-glue-chain` L3 |
| 案卷目录 | `案卷/<case>/` |

## 输出

| 产物 | 路径 |
|------|------|
| 凭据总表 | `接管/cred_inventory.md` |
| Redis session dump | `接管/prod_redis_db1.json` |
| 生产库查询结果 | `接管/prod_deepdive.json` |
| 云凭据验活 | `接管/firebase_sa.json` / `deepdive_batch.json` |
| 综合清单 | `接管/deep_inventory_final.md` |

## 立刻跑

```bash
# 还没确认 GLUE / 执行器时先探管理面
python3 炼蛊房/xxljob_admin_probe.py --base http://<host>:8080 --case <案>
```

GLUE 已能执行后读 `传承/差事府·后手.md`，按 7 步链顺序做。每步产出写到案卷 `接管/`。
