---
name: 太白云生·牌照
description: "TG群发卡密授权后台渗透: launch-token无签名绕HMAC、cloud-config密钥泄露。"
version: 2.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, tg, groupcast, license, card, aaatg, fastapi, hmac, jwt]
    category: daaixianzun
---

> **太白云生**
> 江山如故人未还，一羽千里破云关。
> 师弟二字恩与债，逆流河底鹤难还。

# TG群发卡密授权后台渗透 (License/AAATG-style Group-broadcast backend)

## 触发条件
- 目标为 TG 群发/群控工具的**卡密授权后台**（AAATG License Server），非 loginKey+点数的营销SaaS（后者走 `tg-bot-pool-panel-pentest`）。
- 变现模型：卖「卡密/授权卡」→ 客户端 telegram-tool.exe 用卡激活；后台管卡+代理分销。品牌名常为「海浪」「木鱼」等，域常为拼音缩写（`hlqf.xyz`=海浪群发）。
- 典型指纹：`title="海浪群发 - 管理后台"`（Vue SPA 壳）/ `body="AAATG"` / `body="telegram-tool.exe"` / `title="AAATG 卡密后台"`；授权服务是 FastAPI(uvicorn)，JSON 错误 `{"success":false,"message":"..."}`。

## 第一步 · 全面信息收集
1. `GET /openapi.json` + `/docs`（Swagger UI）——多站同型号常公网可访问，**全量端点+schema**（requestBody 在 `components.schemas`）。
2. SPA bundle 逆向 `index-{hash}.js`：找 `baseURL`、`localStorage.getItem("xxx")`、`Authorization: Bearer`、`/glht/...` 路径。
 - JWT key 名：xadmin 后台 `aaatg_admin_jwt`；glht 代理后台 `agentUser`；主站 `adminToken`。表格列 `operator`=“操作人”字段，勿当用户名。
3. TLS 证书 SAN/CN 泄露真实域（`api.hlqf.xyz`）→ 域常套 Cloudflare 但**源站 IP 证书仍挂此域** → 源站 IP 暴露，可绕过 CDN 直连。FOFA `cert="..."`/`domain="..."` 找同族。
4. 全端口 SYN 扫（python socket 并发线程池）确认面，主站通常只开 22/80/443/8080。
5. 主站 :80 常是纯静态 SPA 壳（nginx 对 `/api` POST 一律 405、GET 兜底 index.html）→ 真实 API 在 :443/:8080 FastAPI。

## ⭐⭐ 核心技巧 · launch-token legacy 端点绕过 HMAC（最高价值）
兼容旧 Go telegram-server 的端点（OpenAPI 描述注明 `HAILANG_LAUNCH_TOKEN` 环境变量）**不校验 X-API-Key/X-Timestamp/X-Signature 任何签名头**：
```
POST /api/auth/launch-token
{"launchToken":"","machineHash":"<绑定设备>","licenseKey":"<有效卡>"}
```
- 卡有效且 machineHash=绑定设备 → `{"success":true,"valid":true,"licenseToken":"lt_...","features":{...},"edition":"full","expiresAt":...}`（token 为随机二进制，每请求轮换）
- 卡有效但 machineHash≠绑定设备 → `bound to other device`；卡无效 → `invalid launch token`
- **意义**：即使 X-Signature 算法未知，只要有一张有效卡 + 已知绑定设备，就绕过整个 HMAC 认证链拿到授权 token。**先试 legacy 兼容端点，再死磕签名**。
- 后续端点签名强度不一致（见下），逐个探测端点签名强度，挑弱的打。

## ⭐ 核心技巧 · cloud-config 跨站密钥泄露（主打）
主站 `/api/loader/cloud-config` 需有效卡才给 hmac_secret；但**同套代码的兄弟/备份/演示站可能无认证就泄露**：
```
GET http://<弱兄弟>/api/loader/cloud-config # 无任何 header → 200 直接给
{"success":true,"base_url":"...","api_key":"aaatg_client_2024","hmac_secret":"...","expires_in":86400}
```
- 找兄弟站：FOFA 搜同型号独立 IP（`title="AAATG 卡密后台"`），常是主站备份/演示实例。
- 兄弟站特征（弱防线信号）：cloud-config 无认证 200、`/glht/api/versions` 无认证 200、admin 登录无锁定、**任意/无签名都通过**（宽松 demo）。
- **api_key 常主/备站共享** → 回主站验证：`X-API-Key:<key>` → `/api/v1/license/health` 若返 `{"success":true,"status":"inactive",...}` 而非 `bad api key` = key 主站有效。
- 关键坑：**主站 hmac_secret ≠ 兄弟站 hmac_secret**（每部署独立），主站签名严格。主站 secret 只能靠主站自身 cloud-config，需一张**有效未过期未绑定的卡**。

## 卡密激活/绑定语义
- `GET /api/loader/cloud-config`（带 X-License-Key + X-Machine-ID）**会把卡绑定到该 machine-id**：unused → active、deviceId 写入、expiresAt 生成。用户给 unused 卡 → 直接用它拿主站专属 hmac_secret。
- 设备级限制：同一设备用过天卡后报「该设备已使用过天卡，请购买月卡」→ 换新 device-id 即可绕。
- 主站 hmac_secret **周期轮换**（非每次变；短间隔多次调用值相同，隔久才变）→ 签名测试时取最新值即可；api_key 固定（如 `aaatg_client_2024`，非每次随机）。
- 绑定设备后 `launch-token` 可反复签发 licenseToken。

## 卡密信息泄露 oracle（未授权）
`POST /api/auth/license-info` + header `X-License-Key`，无认证返回卡的到期/版本/绑定设备hash/edition/features：
- 无效卡→`license not found`；有效未激活→`"status":"unused",deviceId:null`；有效过期→`"status":"expired"`+expiresAt；有效已激活→`"status":"active"`+deviceId。
- 判定差异=枚举面，但卡号随机，只能验证【用户提供的】已知卡，不可爆破。

## HMAC 签名规范（逆向确认，已定稿）
- 头：`X-API-Key`（cloud-config 的 api_key）+ `X-Timestamp`（**秒级** str(int(time.time()))，毫秒报 `timestamp skew`）+ `X-Signature`。
- **算法**：`X-Signature = HMAC-SHA256(ts + "." + compact_json_body, hmac_secret)`，hmac_secret **就是 cloud-config 响应里的 `d["hmac_secret"]`**（非硬编码、非环境变量），服务端用 api_key 查对应 secret 验签。
- **body 必须是 compact JSON 原始字节**：`json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`——冒号后无空格、无换行；发送必须 `data=body_bytes`（requests 的 `json=` 会重新序列化导致签名不匹配）。Python `json.dumps` 默认 separators 带空格 = 永久 bad signature。
- 校验顺序：timestamp → signature（缺 ts 报 `invalid timestamp`，有 ts 无/错签名报 `bad signature`）。
- **端点验签强度不一致**（黑盒判定：带 api_key 无签名，返回业务错误=不验签，`bad signature`=验签）：
 - 宽松（不验签）：`health`、`refresh`（invalid refresh token）、`unbind`（invalid token）、`launch-token`
 - 严格（验签）：`issue`、`exchange`、`captcha/*`、`extend-with-key`、`unbind-by-key`
- 限流：`请求过于频繁` 为独立 IP 级限流（冷却 60-120s+，高频试探误报遮蔽命中判定），单测间隔 ≥25s。
- 签名判官端点：`extend-with-key` 返回 `current and new key cannot be the same` = 已过签名进业务逻辑；`exchange` 无 ts 报 `invalid timestamp`、加 ts 后 bad signature = 严格。
- **若黑盒 100+ 组合仍 bad signature**：唯一确定方法是捕获真实客户端请求三元组（X-Timestamp / X-Signature / 原始 body）用已知 secret 反推 msg 格式；或让用户逆向客户端 JS/Rust 确认 msg 构造。勿无限穷举 secret 字典（强随机 32 字节不可暴力）。

## Loader/授权接口
- `/api/loader/version?platform=windows&version=X&brand=hailang`：泄露 file_name/size/sha256 + download_url；**`brand` 参数枚举产品线**（hailang/muyu…）。**version 对任意 key 都返回 success**（不校验卡）→ 别用它判断卡有效，用 license-info。
- `/api/v1/license/issue|exchange|refresh|captcha/*|unbind*`：需 `X-API-Key`+`X-Timestamp`+`X-Signature`(HMAC)。
 - 响应区分：`bad api key`(key无效)/`bad signature`(算法错)/`invalid timestamp`(缺秒级ts)/`timestamp skew`(毫秒或过期ts，**必须秒级**)/`license expired`/`卡密不存在`(卡通过但库无)/`请求过于频繁`(IP级限流)。
 - `revoke` 只需 `X-API-Key`（无签名）→ api_key 有效性 oracle。
- `loader/download` 需额外 grant（`loader v2 download grant required`），即使卡激活也 403 → 客户端下载受阻时不要反复试。

## 逆向确认的 JWT 结构（客户端 Tauri localStorage）
- `alg:HS256`，payload: `{exp, licenseHash, licenseId, licenseKey, machineHash, sub:"license", tokenVersion}`。
- licenseHash = SHA256(卡密+ServerSecret) 派生；machineHash = 客户端机器指纹（非 sha256(deviceId) 简单值）；JWTSecret 强随机（常见字典全灭，勿浪费时间）。
- 注意卡前缀：`ANYK-****-****-KEY1` 是另一套测试卡，`AAATG-` 才是目标体系。
- Tauri 应用优先让用户从 localStorage/内存 dump 提 JWT 与前端 JS，比强行脱壳高效。

## 加壳客户端 (telegram-tool.exe) 分析要点
- PE x64：`.text/.rdata/.data` rawsize=0（运行时解密），`.d(f` 节 23MB flags=0x68000060 (RWX) 含 EP，`.zMK` 加密 payload → 一次性加密强壳；entropy 7.75-8.0、字符串全加密。
- wine 动态：需 `WINEPREFIX`+`WINEARCH=win64` 重建 prefix（wineboot 失败报 `could not load kernel32.dll`），装 `wine32:i386`；但强壳有 wine 环境检测，exe 静默退出（exit 0 无 NtCreateUserProcess 记录）。
- `.d(f` 内 MZ 是巧合字节（PE offset 无效），非明文嵌入 → 静态脱壳难，优先动态 dump 或用户提取。

## 登录防爆破
- **admin 后台** `/glht/api/auth/login`：账号级 5 次失败→30 分钟锁定（响应「还剩 N 次机会」/「账号已锁定 30 分钟」）。剩余次数可探真实账号存在性（各账号独立计数见底）。别名 admin/operator/boss。强密码+被爆后台纯字典低效 → 爆破放最后。
- **代理端** `/glht/api/agent/auth/login`：无锁定计数回显、无用户枚举差异（统一「用户名或密码错误」），可较安全批量尝试，但用户名未知时命中率低。
- 无注册/忘记密码/重置接口（405/404）是常态。

## 报告口径（诚实）
- 分栏：**已提取**（openapi/隐藏后台/卡密oracle/兄弟站密钥/共享api_key/launch-token绕过）| **仅信息泄露** | **未突破**（admin/agent凭据、完整loader链）。
- 登录锁定、无签名接口、未授权拦截等如实记为防御措施，不虚报漏洞。

## 相关
- 同一「TG群发」另一变体（loginKey+点数营销SaaS）→ `tg-bot-pool-panel-pentest`。
- FOFA 资产搜索工作流 → reverse-skill 个案附件未入库（原 references/fofa-cloud-control-scanning.md）。
- 本库无此外门 `scripts/license_sign.py`。按本卡用 cloud-config 密钥算 `X-Signature` 后 curl 探测。

## 真源

- 手法：`传承/秦百胜·拍卖.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
