---
name: 坞·插件
description: >-
 授权目标上 WordPress 插件未认证接管/假付：CVE-2026-15341 User Session Synchronizer
 弱 AES 种 cookie、CVE-2026-15303 6Storage 按邮箱登录、CVE-2026-14484 RapiSafe
 删文件、CVE-2026-15965 MaxUpload 未认证上传、CVE-2026-8840/12128 预约已付与改价。
 
 广谱 1day 走 1day-nuclei-kit；入库走 cve-daily-intel；易支付 notify 仍走假支付专卡。
 已落地 WP 马（wp-includes 下 11 位随机 php / 最新shell目录）走 坞壳落子猎，不把情报域名扩进 scope。
---

# WordPress 插件未授权接管 / 假付（Cursor Skill）

## 何时用

- WP 站且 `nday_route` hit `wp-plugin-unauth-20260815`
- 用户点名 CVE-2026-15341 / 15303 / 14484 / 15965 / 8840 / 12128
- 插件目录出现 user-session-synchronizer、6storage-rentals、rapisafe-multi-file-cf7、maxupload-upload-larger-files-easily、booking-calendar、booking-system

## 真源（按序）

1. `传承/坞·接管.md`
2. `炼蛊房/wp_plugin_unauth_probe.py`
3. `tools/1day-kit/custom-templates/wordpress-plugin-unauth-20260815.yaml`
4. `传承/CVE日报-2026-08-15.md`
5. 假付主卡仍可能并行：`payment-callback-forgery`

## 强制步骤

1. 目标在 `授权范围`。
2. 授权内默认打到 **L2**（枚用户 → 种 cookie → `/wp-admin/`），不要停在 readme：
 ```bash
 python3 炼蛊房/nday_route.py -u <URL> --case <案卷>
 python3 炼蛊房/wp_plugin_unauth_probe.py -u <URL> --case <案卷>
 ```
3. 按命中补刀（同样直接跑）：
 - 指定邮箱：`--email admin@站 --email 其它@站`
 - 假付：`--reservation <预约id>` 或 `--price 0.01`
 - 删文件：`--delete <路径>`
 - 上传：`--upload <本地文件>`
4. 证据：`案卷/1day/wp_plugin_unauth.json`。进后台后走对象矩阵。
5. **仍不动**：改原超管密码。

## 成功口径

| 级别 | 口径 |
|------|------|
| L1 | readme 命中且版本在影响区间 |
| L2 | 已登录 `/wp-admin/` **或** 预约已付/改价成立 |
| L3 | 指定路径删除成功或指定文件上传成功 |

## 不要做

- 未授权扫 WP 全网
- 改原超管密
- 命中后只报 CVE 编号 / 只跑 nuclei 结案

## 衔接

- 假支付 notify → `payment-callback-forgery`
- 进 WP 后台 → `object-matrix-authz`
- 情报入库 → `cve-daily-intel`
- JetEngine `jet-engine` / CVE-2026-66613 → `jetengine-unauth-rce`（只读 readme，不混本卡 ATO）
