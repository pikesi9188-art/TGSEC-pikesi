---
name: 铁血冷·远控
description: >-
  大爱仙尊·I-RAT/Craxs类安卓远控面板渗透。应对阿力科技AdminPro前端+远控后端。
---

> **铁血冷**
> 铁血冷眼看人间，探路拆骨不留情。
> 家法如刀先自冷，安器一开见真形。

# android-rat-panel-pentest（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/android-rat-panel-pentest/SKILL.md`
- 手法：`传承/安器·探路.md`
- 工具：`python3 炼蛊房/apk_recon.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name android-rat-panel-pentest`

---

# I-RAT/Craxs 类安卓远控面板渗透

安卓远控（间谍软件）管理面板的完整打法。典型架构：AdminPro 前端壳（阿力科技）+ PHP 后端 + Node.js WebSocket（127.0.0.1:8080）。面板控制被控手机：截图、短信、通讯录、键盘记录、文件读写、注入。

## 指纹识别（第一眼确认）

1. 登录页 `<title>阿力科技</title>`，AdminPro 框架（`/app.config.js`、`/assets/index-*.js`）
2. **app.config.js 有域名替换逻辑**：`var D='p4q2.cn'`，把请求中模板域名替换成当前 origin → 泄露模板源站（可能已挂）
3. 典型路径：`/login?redirect=/list/basic-list`
4. 同源码多站可交叉验证（主 JS MD5 一致）

## 关键端点清单（全部存在即确认同源码）

| 端点 | 行为 | 用途 |
| :-- | :-- | :-- |
| `/api/auth.php` POST | `{usrname,password}` JSON，成功返回 `{userid,usrname,email}`，失败 401，暴力触发 `{"error":"rate_limited"}` 429 | 登录 |
| `/api/devices.php` POST | `{token,page,pageSize}` + `Authorization: Bearer <token>`，无 token 401 | 设备列表（拿 pid） |
| `/api/remove.php` POST | 同 token 认证，body 设备ID | 删设备 |
| `/api/settings.php` POST | 无 token 恒 401 | 配置 |
| `/api/ws/` (wss) | nginx 反代到 127.0.0.1:8080，无 Upgrade 头返回 426 | 实时控制通道 |
| `/private/cb_custom.php` | GET 返回 `{"Fail":"Invalid request."}`；**POST 被 WAF 拦 403** | Builder 回调（可伪造写库） |
| `/private/build_api.php` | POST 返回 `{"Fail":"Invalid request param."}` | APK 构建 |
| `/private/inventory_api.php` | 同上 | 库存 |
| `/private/profile_api.php` | POST 空参数返回 200 空；ma() 用 multipart 上传，wa() 用 JSON | 配置 |
| `/dl.php?pkg=xxx` | 无参=Invalid，无效包=Error，参数化良好无法注入 | APK 下载 |

## WebSocket 协议（漏洞3核心）

- 连接：`wss://host/api/ws/`，握手即可连（服务端不校验 Origin）
- 面板加入：`{"itype":"w_pnl","subc":"join","pid":"<设备ID>","usercheck":"<CURRENT-USER>"}`
- 心跳：`{"itype":"w_pnl","subc":"ping","pid":"..."}`、`disag`、`out`（admin 才发）
- 命令下发（w_cmd）：`{"itype":"w_cmd","subc":"OPENINJ"|"SMS"|"screen"|"changefiles"|"viewfile"|"Keylog"|"Contacts"|"cam"|"mic"|"rename"|"Hideico"|...,"pid":"..."}` 
- 服务端推送 type：`statusBatch`（设备状态）、`screen`/`screenshot`/`snap`（截图 base64）、`sms`/`klog`/`loc`/`cam`/`mic`/`files`/`savefiles`/`thumb`/`injapps` 等
- 管理命令：`idf_adminsend` 分支（type:"screen" 的 snap 截图、phonepass 锁屏密码、usdtadress、键盘注入；file 的读写；OPENINJ/changefiles/viewfile 窃取指令）
- **认证绕过前提**：`WS_ADMIN_TOKEN` 为空时仅校验来源 IP（127.0.0.1、10/8、172.16/12、192.168/16）。WS 监听 127.0.0.1:8080，经 nginx 反代后 REMOTE_ADDR 恒为 127.0.0.1 → **公网连进来即通过 IP 校验**（若 token 为空）
- **blocklist 绕过**：`WS_BLOCKED_ADMIN_SUBCOMMANDS` 按小写精确匹配 subc → 用大小写变形绕过（OPENINJ vs openinj）

## 前端 token 存储

localStorage 键：`ACCESS-TOKEN`、`CURRENT-USER`、`CURRENT-EMAIL`、`CURRENT-AUTHORTY`、`CURRENT-ID`。所有 API 靠 Bearer token。

## 加固特征（复现失败时判断）

- `.env` 全变体返回 404 "Request error"（nginx deny all 或 PHP 路由吞）→ 站点已加固
- cb_custom POST 固定 403（WAF），路径大小写变体 404（严格文件系统）
- auth.php 有 rate limit（429），弱口令爆破效率极低
- dl.php 注入 payload 直接断连（000）→ WAF 拦 SQLi
- devices.php 无 token 恒 401

## 攻击路径优先级

1. **.env 泄露**（Critical）：直接 `/.env` 拿到 DB 凭据 + SECRET_KEY/IV（解密全部被控数据）+ ADMIN_PANEL_ACCESS_KEY（绕过管理密钥门）
2. **登录** → devices.php 拿设备 pid → WS 下发管理命令（真实利用链）
3. **cb_custom 伪造写库**：BUILDER_CALLBACK_TOKEN 为空时仅校验来源 IP（127.0.0.1/::1），反代后 REMOTE_ADDR 为本机 → POST 伪造 userid/appid/apppath/build_state
4. dl.php 硬编码 DB 凭据（历史库）

## 坑

- 别盲目爆破 auth.php（rate limit 快），先找 .env / 源码泄露 / 用户枚举
- 用户枚举有微弱响应差异：admin/root/Administrator 返回 401（继续验密码），未知用户名直接 429
- WS 无响应不代表没进通道：命令对无效 pid 静默丢弃；pid 从 URL `?id=` 参数来，需先拿到设备列表
- 三个"同源码站"可能分布在多台服务器（证书对比确认：同一域名证书 = 同机；不同证书 = 独立服务器），各自配置可能不同
- X-Forwarded-For 伪造对 cb_custom/WS 无效（服务端用 REMOTE_ADDR）

## 参考
- references/case-2026-08-27-three-sites.md（三站实测：端点行为、WS 测试序列、加固判断）
