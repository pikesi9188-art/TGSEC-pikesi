---
name: 若府·飞头若
description: "飞投/若依系博彩集团管理后台渗透: GA-TOTP锁分析, Druid弱口令全农场, 过滤器绕过."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, ruoyi, gambling, admin, druid, totp]
    category: daaixianzun
---
# 飞投 (Feitou) / RuoYi 系博彩集团管理后台渗透

Use when the target is a 博彩/包网集团的管理后台 running the **飞投后台管理框架 v3.9.0** (a RuoYi fork; swagger title "若依管理系统"), typically fronted by a Vben-style Vue3 admin SPA whose `_app.config.js` points `VITE_GLOB_API_URL` at an `int.tgbetXXX.net`-style host. Covers: farm discovery, Druid weak-cred chain, GA(TOTP) login lock analysis, auth-filter bypass attempts, druid-as-oracle blind SQLi detection, shared-DB topology.

## 1. Fingerprint
- API root banner: `欢迎使用飞投后台管理框架，当前版本：v3.9.0，请通过前端地址访问。`
- Swagger: `/v2/api-docs` `/v3/api-docs` `/swagger-ui/index.html` → title "若依管理系统", contact "飞投" (only test-controller documented: `/dev-api/test/user/*`)
- Admin frontend SPA: Vue3 + Vben (chunks: `AssignRolesDrawer`, `RoleAuthModal`, `MenuDrawer`, `VxeGrid`, `_app.config.js` with `VITE_GLOB_APPID`)
- **Farm discovery**: FOFA `body="飞投后台管理框架"` → 60+ hosts; naming `int.tgbet{271,221,331,771,881,321,291,341,551,231,661,691,621,...}.net` (+ `.com`). All brands of the operator share one farm.
- Frontend server hosts many brand sites on one IP (e.g. 154.9.25.34: tgbet9008/6296/9876/... 旺博/金貝/天胜/嘉百) — Windows box, public MySQL 3306, FTP 21, RDP 3389, BT 888/8889 host-bound.

## 2. Attack surface checklist (all verified 2026-08)
| 面 | 结果 |
|---|---|
| `/login` | **GA(TOTP)强制**: `code` 是 Integer 字段; 空→"谷歌验证码不能为空"; 存在用户错码→"谷歌验证码错误"; 用户不存在→"谷歌验证错误" = **用户名枚举oracle** |
| GA校验顺序 | **在密码校验之前** → 无TOTP则密码爆破不可能; `rememberMe`/`captchaEnabled`/`googleCode`/`mode` 附加字段不绕过; 数组/对象/空白字符串类型混淆失败 (Integer反序列化) |
| `/register` | 关闭 ("当前系统没有开启注册功能") |
| `/captchaImage` | captchaEnabled=false |
| 全局过滤器 | 除 `/login /captchaImage /register` + `/druid/**` 外全401; Spring经典绕过 (`;` `..;/` `%2e` `%252e` 双斜杠 大小写 尾斜杠 NUL) 全部失败 — filter先于路由 |
| `/common/download*` `/profile/*` `/actuator/*` `/tool/gen/*` | 全401 (含穿越 payload) |
| **Druid** | ✅ 默认口令 `ruoyi/123456` **全农场通用** (每个 int.tgbet* 主机都试!) |

## 3. Druid chain (the main foothold — monitoring only, no RCE)
```
POST /druid/submitLogin  loginUsername=ruoyi&loginPassword=123456  → success
```
- `datasource.json` → DB topology: `jdbc:mysql://172.22.0.4:3888/ftgames` user root (**所有品牌API服务器共指同一库**, Docker内网不可达; 无密码字段)
- `sql.json` → **全量业务表结构+MyBatis mapper SQL** (109+条去重): 本族表 cp_user(24字段: id/ucode/uname/moneys/needmons/botid/parent_botid/iscw/allcz/alltx/allbuy/allpay/backsprop/allwin/allkfjiangmons/uanum/status/cztimes/remark/packcount/fromtype...), cp_busi, cp_buys, cp_userback, cp_change, cp_issue(开奖), cp_config, sys_user 含 **google_key 列**
- `weburi.json` → **管理员活动情报**: URI+请求数+LastAccessTime; 轮询端点(如 /cp/busi/count 74k次)证明管理员在线; 可发现前端未暴露的业务端点 (/cp/busi/merInfo, /cp/change/doWalletBusiAud, /cp/user/selectAllMoney...)
- `session.json`/`connection.json`/`log.json` 通常 "Do not support" (被禁用); `activeConnectionStackTrace.json` 空
- LastSlowParameters 默认不落 (慢SQL才带参数, 可挂监控碰运气)

## 4. Druid-as-blind-SQLi-oracle (login 无注入验证法)
- 前置: 抓 `sql.json` 的 SQL 文本集合 A
- 发送探针 (如 /login username=`' OR '1'='1`) → 再抓集合 B
- B−A 无新SQL = 参数化 (安全); 有新SQL含payload = 拼接注入确认
- 注意 druid 按 SQL 文本 hash 去重, 同文本只更新统计 — diff 只看**新文本**

## 5. Vben 前端附加模式
- `_app.config.js` 可能泄露 `VITE_GLOB_RSA_PRIVATE_KEY` (**私钥直接暴露!** 例: ht.crypto777.vip 人人支付系统) + `VITE_GLOB_API_URL` (相对路径如 /test-api) + `VITE_GLOB_ENABLE_ENCRYPT`
- 相对路径API: 同主机 nginx 反代, 后端可能 502 (宕机) — 换端口+Host头重试 (8889/8000/6001/888)
- 兄弟应用同IP不同vhost: Host头直接打 (FOFA同IP结果), 如 154.9.25.34 上人人支付/操作手册后台

## 6. 操作手册/工单后台 (geshanzsq-blog-admin 系) — 默认口令可进 (2026-08实证)
- 指纹: Vue2 + `/geshanzsq-blog-admin-api` 前缀, whitelist 含 `/clintWorkOrder`, superAdmin 角色
- **默认口令突破法 (gitee源码→SQL种子→BCrypt破解)**: 开源项目 `geshanzsq/geshanzsq-blog` 的 `doc/sql/geshanzsq_blog.sql` 含 sys_user INSERT (BCrypt hash) → 用 python bcrypt `checkpw` 对常见密码列表 → 默认用户 admin/geshanzsq/xgz 密码全为 `123456`
- 实证: admin 密码被改 (admin/admin123、admin/123456 均失败) 但 **geshanzsq/123456 登录成功** → token 直接 `Authorization: <token>` 头 (Bearer 前缀亦可)
- 权限模型: 普通角色 permissionCodes 空 → 除 getUserInfo/getRouters 外几乎全 403 (连自身 getById 也403); admin 才有业务数据权限 → 若 admin 密码已改则需验证码爆破
- **验证码一次性** (TTL=2分钟): 每次 login 消耗 (密码错也失效) → 每密码需新图; **单张图→用户快读快回→立即用** (批量5图会因TTL全过期, 实测0命中); 响应三分: 不正确=读错 / 已失效=超时 / 用户名或密码不正确=验证码过但凭据错
- 未授权接口: `/system/dictionary/getAllDictionaryInfo` (200); SecurityConfig 源码白名单: swagger-ui.html / swagger-resources/** / webjars/** / `/*/api-docs` / doc.html (knife4j) / `file-upload.map-prefix` (默认 /profile) /**
- 该后台≠飞投后台, 属运营支撑系统 (操作手册/工单) → 完整打法见 references/geshanzsq-rrqa888.md

## 7. Pitfalls
- GA锁是硬墙: 错误消息枚举用户名 (admin, sysadmin 常见) 但密码+GA双锁; 不要浪费时间在类型混淆/字段注入
- Druid 只读: 无SQL执行、无会话劫持 (RuoYi token 在Redis, 无Redis暴露)
- DB 在内网Docker (172.22.0.x), 仅从API服务器可达; 公网MySQL 3306 (如 154.9.25.34) 是前端服务器独立实例, 弱口令命中率低
- 玩家侧同族 (JWT iss=666BetGame, gameN.mzbxdt.com) 另见 `666bet-tma-pentest`; suid直登/短信轰炸/提现绑定删除在此家族通用
- 报告要区分: 半程利用 (Druid监控+拓扑+枚举, admin数据未得) vs 打穿 — 禁止虚报

## References
- `references/jiabai-tgbet-session.md` — 嘉百(tgbet9008/jb173)会话细节: 资产清单/端点/表结构/实测结果
- `references/geshanzsq-rrqa888.md` — geshanzsq手册后台: gitee源码SQL种子→BCrypt破解默认口令、验证码一次性+批量人工识别流程、白名单/权限清单
