---
name: 旁支认族
description: >-
 路由到 智道藏书/旁支传承 的 120 张白标/家族业务卡（芋道TMA、Qzino、
 1Z/曼巴/鼎艺、加密网关、TG系统选择云控、易支付后台、FastAdmin代付）。
 
 假支付/Actuator/GVA/ACG/Sticker云控仍优先对应专用 Skill。
---

# 扩展技能包路由（大爱仙尊）

## 本仓探针

```bash
python3 炼蛊房/pack_surface_probe.py drive --name <旁支卡> --case <案>
```

L2=挂号落到本仓 SKILL.md。证据进案卷 `测绘/`。

## 真源

| 内容 | 路径 |
|------|------|
| 总览 | `智道藏书/旁支传承/README.md` |
| 作业面索引 | `智道藏书/旁支传承/INDEX.md` |
| 卡全文 | `智道藏书/旁支传承/skills/<name>/SKILL.md` |
| 分流手册 | `传承/商心慈·白标.md` |
| 导入清单 | `智道藏书/旁支传承/IMPORT.json` |

## 强制优先级

1. `授权范围`
2. 业务专用：假支付 / ACG / PocketBase / GVA / Actuator / `tg-cloud-panel`（Sticker/Fernet）
3. 本包家族卡（认族后 Read 对应 `SKILL.md` 并执行）
4. 九阶段通用洞（`九转`）
5. 广谱扫描

## 关键词 → 先读哪个

| 用户说法 | 先打开 |
|----------|--------|
| 白标 / 家族站 / 认不出哪套盘口 | **`商心慈·白标.md`** + `gambling-family-router` |
| 芋道 / `/app-api` / `app-config.js` / 世博 TMA | **`yudao-appapi-pentest`** |
| Qzino / `/api.html` / Mini App 赌 bot | **`telegram-tma-gambling`** |
| `sk_encrypt.json` / `/app-api/encrypt` | **`encrypted-api-spa`** |
| 直读失败、key 绑 token、ATO | **`account-takeover-chain`** |
| 「系统选择」`/tgcloud_pc` / OSS STS | 扩展包 `tg-cloud-control-pentest`（不是 feijikong 那套） |
| JWT `your_secret_key` / `/proxy/list` / `/admin/users` / Session ZIP | `tg-cloud-panel` 认族 → `jwt-bypass-pentest` + `rbac-bypass-authz`（第三族，勿打 OSS/Fernet） |
| 支付管理中心 / `admin_login.lock` | 扩展包 `epay-admin-pentest` + 假支付矩阵 |
| FastAdmin 代付 / `/sh.php` `/ks.php` / `part/index` | **`fastadmin-daifu-pentest`**（勿与彩虹易支付混） |
| FastAdmin Shop / `shop_hq` / GT filter / 跨商户 tdata | **`fastadmin-shop-tenant-bola`**（勿与代付、Sticker 混） |
| 号库 / 投递 session / 清库 | **`tg-account-library`** |
| 盯客服回复 / 代理社工推进 | **`tg-account-library`** |
| 扩展包齐不齐 | `IMPORT.json` + `INDEX.md` |

## 行为

- 读完卡给出**可执行下一步**（命令 + `$CASE`）。 
- 号库/投递/社工走 `tg-account-library` / `tg-account-library`（根目录 `_tg_accounts/`，不要 `/opt/data`）。 
- 不把 C2 / 免杀当本库命令。 
- 命中密钥或未授权读 → 立刻验证，不要只记指纹。
- 工具：`python3 炼蛊房/auto_campaign.py --help`
