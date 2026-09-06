---
name: 快府·横夺
description: >-
 FastAdmin Shop 多租户 GT-filter 杀伤链：shop_hq / shop_keeplogin / filter+op
 改运算符（GT/GTE/LT/IN）绕过 shop_id 隔离，再打 attachment 与匿名 /uploads/
 拿 tdata。
 勿与 FastAdmin 代付 /sh.php /ks.php、Sticker 云控、「系统选择」tgcloud_pc 混用。
---

# FastAdmin Shop 多租户 GT-filter

**前提**：目标在 `授权范围`。同源产品子域可静默扩权；报告旁站不扩。

**成功口径（按档，禁止跳级）**

| 档 | 成立条件 | 不算 |
|----|----------|------|
| L1 | `/shop_hq` 登录页或 `window.Config` | 只看到 ThinkPHP 报错 |
| L2 | 任意身份 + **GT/IN 等** 后 `total`/异 `shop_id` 超过本店 | EQ 改 shop_id 阴性；WAF 拦 EXP |
| L2b | 附件 URL + 匿名下到 tdata/2FA **样本** | 只数到 60 万附件条数 |
| L3 | 跨商户 session 可外连，或自控管理号 | 改原超管密；本店 0 设备当结案 |

## 何时启用

- `/shop_hq/index/login`、`shop_keeplogin`、`window.Config`
- 标题/文案：出海、TG 云控、多商户 `shop_id`
- 已有低权票（客服坐席），上一轮写过「shop_id 隔离正确」
- **不要**再打 `tg.507.mx` 复现（2026-08-17 已修）；换其他授权 Shop 站

**不要走这张卡**

| 指纹 | 走 |
|------|-----|
| `/sh.php` `/ks.php` `part/index` | `fastadmin-daifu-pentest` |
| 「系统选择」`/tgcloud_pc` | `tg-cloud-control-pentest` |
| Sticker / Fernet `gAAAAA` | `tg-cloud-panel` |
| 只有 `X-Powered-By: ThinkPHP` | `幻页·认族.md` |

## 强制行为

1. 有任意身份先填 `案卷/object_matrix.md`（他人 × 读用户 / 附件 / 配置）。 
2. **EQ 改 shop_id 阴性禁止结案**。必须跑运算符矩阵（GT/GTE/LT/IN/BETWEEN）。 
3. WAF 拦 `EXP` / `OR 1=1` 只说明 SQL 关键字被拦，**不是** ORM 隔离。 
4. `/uploads/` 目录 403 ≠ 文件无认证；必须用 attachment 的具体 URL 测。 
5. 本店 0 台设备 → 用 GT 打他人 `shop_id`，不要写复工。 
6. 默认只拉 1 页做差分。全表 / 批量下 tdata **先问**。 
7. 默认不改原超管密、不绑生产超管组死磕。 
8. 测完临时账号能删则删；完整 PIN / session 不写可同步 STATUS。

## 最短命令

```bash
python3 炼蛊房/fastadmin_shop_tenant_probe.py recon \
 --base 'https://授权站' --case <案卷> --insecure

python3 炼蛊房/fastadmin_shop_tenant_probe.py gt-probe \
 --base 'https://授权站' --app shop_hq --path user/user \
 --cookie 'shop_keeplogin=…' --case <案卷> --insecure

python3 炼蛊房/fastadmin_shop_tenant_probe.py dump-index \
 --base 'https://授权站' --app shop_hq --path attachment/index \
 --cookie 'shop_keeplogin=…' --case <案卷> --insecure --pages 1
```

## 八帧（缺一帧就停在该档）

```text
① 指纹：shop_hq / shop_keeplogin / window.Config / uploads 匿名
② 任意身份进门 → 填对象矩阵（本店空不是结案）
③ 假阴性：EQ 换租 + SQLi/EXP（WAF）对照
④ GT/IN 覆盖 shop_id → user/user 出现异店
⑤ 同 op 打 attachment/index → 枚举 /uploads/ck/*.zip
⑥ 匿名下载样本 → 2FA.txt / tdata
⑦ 并行 BFLA：auth/group 读 * ；admin/add 默认可探测、--create 才建号
⑧ 死胡同停：TP RCE / 源站 104.21 / keeplogin salt / 超管组静默失败
```

## 真源

- 手法卡：`传承/快府·横夺.md`
- 探针：`炼蛊房/fastadmin_shop_tenant_probe.py`
- 参考：（开源包不收个案摘记）
- 对象矩阵：`object-matrix-authz`
- session 入库：`tg-account-library`
- 对照（勿混）：`fastadmin-daifu-pentest` · `tg-cloud-panel` · `tg-cloud-control-pentest`
- 案例笔记（已修站勿复打）：`智道藏书/旁支传承/skills/redteam/507mx-fastadmin-bola/SKILL.md`
