---
name: 无极·职分
description: >-
 RBAC/BFLA 垂直越权：已有低权票时打管理 API、角色继承/参数提权、
 X-HTTP-Method-Override、PATCH/PUT、批量 ids、/me 写 role/authorityId、
 JWT 撤权后 TTL 误报闸、撤权后 version/jti 枚举复活。
 
 水平 IDOR 走对象矩阵；GVA authorityId 走静默提权；弱 JWT 走 jwt_gql_probe。
 TG `/proxy/list` `/admin/users` 先经 tg-cloud-panel 认族。
---

> **无极**
> 从来是疯魔道痴，俯仰问阴阳乾坤。
> 百万年筹谋积蓄，待今朝无极永生！
> 规矩为盘律为棋，世间万法皆可寻！

# RBAC 权限绕过

**前提**：目标在 `授权范围`。先有低权身份；没有会话先 `authz-probe` / 注册 / 弱口。

**成功口径（按档，禁止跳级）**

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L1 | 管理 path 清单 + 低权票已打 | 只打开 OpenAPI |
| L2 | 低权 200 + **他人列表/分页**（匿名 401） | 401/403；单条 `/me`；匿名也能读（交 authz-probe）；回显含 admin |
| L3 | `/me` 角色升高，或批量改到他人 | 给自己加款失败就停 |
| 误报 | 撤权后旧 JWT 在 `exp` 内仍可用（未改 claim） | **预期行为**，禁止当洞 |
| 真洞 | 撤权后枚举 `ver`/`version`/`v`/`jti` 五次内复活 | TTL 内未改 claim 仍 200（那是误报） |

## 何时启用

- 已有普通用户 / viewer / 会员票
- 前端或文档出现 `/api/admin`、`/admin-api`、`permissions`、`role`
- 只测过换 `userId` 的水平面，还没打垂直功能面

**不要走这张卡**

| 指纹 | 走 |
|------|-----|
| 无会话 | `authz-probe` · `auth-brute` · 开放注册 |
| 只换 uid 读他人 | `object-matrix-authz` |
| GVA `authorityId` | `ginvue-admin-stealth-takeover` |
| Shop `shop_id` / `filter/op` | `fastadmin-shop-tenant-bola` |
| 芋道 `Bearer test1` | `yudao-daifu-mock-file-rce` |
| 弱 HS256 / 不验 exp | `jwt_gql_probe` · `李代桃僵·星念.md` |

## 强制行为

1. 先填 `案卷/object_matrix.md`（自己 × 配置/角色；批量则他人 × 写）。 
2. 默认只 GET 管理面 + PATCH `/me` 角色字段。**禁止**对真用户发 Override DELETE。`--method-probe` 只打假 id。`--write` 只建/清本轮标记号，禁止 DELETE `--other-id`。 
3. 撤权后 TTL 内旧票仍可用（未改 claim）= PASS。过期仍 200 才报 JWT 洞。  
   已撞开 HS256 时再枚举 `ver`/`version`/`v`/`token_version`/`jti`（1..5）重签；五次内复活才报，与 TTL 误报不是一回事。 
4. 进超管后收配置/COS 钥，禁止截后台首页结案。 
5. 专卡/本卡阴性必须回矩阵换格，禁止写「RBAC 阴性 → 复工」。

## 最短命令

```bash
python3 炼蛊房/rbac_bypass_probe.py \
 --base https://授权站 --token "$LOW_TOKEN" --case <案卷>

python3 炼蛊房/rbac_bypass_probe.py \
 --base https://授权站 --prefix /prod-api --token "$LOW_TOKEN" \
 --header 'X-Token:…' --method-probe --case <案卷>

# 已撞开 HS256 时枚举 version（不撤权）
python3 炼蛊房/rbac_bypass_probe.py \
 --base https://授权站 --token "$TOKEN" --jwt-secret your_secret_key --case <案卷>

python3 炼蛊房/object_matrix.py check --case <案卷> --strict
python3 main.py authz-probe -u https://授权站 --scope 授权范围
```

## 五帧（缺一帧就停在该档）

```text
① 低权票 + 管理 path（OpenAPI/JS/默认表）
② 直接打管理读（BFLA）
③ JWT/权限接口 vs 参数注入 role/authorityId
④ Override / PATCH / OPTIONS
⑤ /me 敏感字段 + 双 id 批量；TTL 误报闸；撤权后 version/jti 枚举（1..5）
```

## 真源

- 手法卡：`传承/无极·职分.md`
- 探针：`炼蛊房/rbac_bypass_probe.py`
- 闸：`object-matrix-authz`
- 匿名/水平面：`万我·信门.md` · `authz-probe`
- 改编自 Auth9 `docs/security/authorization/02-rbac-bypass.md`（M-AUTHZ-02）
