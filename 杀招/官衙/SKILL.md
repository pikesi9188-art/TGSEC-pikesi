---
name: 官衙
description: >-
  政务微信小程序安全审计专项：WePolice/粤省事/粤信签 认证流、
  SM2/SM4 国密加密面、tokenRequired 猎杀、MMKV JWT 提取、
  政务 API 网络隔离绕过、PII IDOR（人口编码/证件号/大头照）。
  触发：政务小程序 / 公安 / 粤省事 / 粤居码 / WePolice / 微警 / SM2 /
  gd.gov.cn / gdga / 居住证 / tokenRequired / 人口编码 / rkbm。
  前置：wxapkg 已解包（Mac 走 wxapkg-mac-decrypt），目标在 scope。
---

# gov-wxmini-audit — 政务微信小程序安全审计

## 何时用

目标是政务类微信小程序（公安/民政/社保/住建等），且已完成 wxapkg 解包。
本卡在 `wxmini-static-audit` 通用审计之上，专打政务特有的攻击面。

## 政务小程序特征指纹

出现以下任一指纹即触发本卡：

| 指纹 | 含义 |
|------|------|
| `wePolice` / `微警` / `WEI_JING_APP_ID` | 微警认证（人脸核身） |
| `sm2.doEncrypt` / `miniprogram-sm-crypto` | SM2 国密加密 |
| `tokenRequired:!1` / `tokenRequired: false` | 客户端标记无需 JWT |
| `gd.gov.cn` / `gdga` / `省厅` / `公安` | 广东政务域名 |
| `rkbm` / `zjhm` / `sfzhm` / `certNo` | 人口编码 / 证件号字段 |
| `粤省事` / `粤信签` / `YXQ` / `yxqLogin` | 粤省事/粤信签登录 |
| `decodeYJM` / `粤居码` | 粤居码 QR 解码 |
| `specialRequestPaths` | 特殊路径（自动注入 jsCode） |

## 审计清单（6 步）

### Step 1: tokenRequired 猎杀

在 `app-service.js` 中搜索所有 `tokenRequired:!1` 或 `tokenRequired: false` 的端点：

```bash
rg 'tokenRequired:\s*(!1|false|!0|true)' app-service.js
```

分类统计：
- **CRITICAL**: OCR / 文件上传 / 写入类无鉴权（如 `photoSave`、`ocr/sfzhm`）
- **HIGH**: 注册/登录类无鉴权（如 `wePoliceNoPhone`、`getTokenByAuthcode`）
- **MEDIUM**: 短信/验证码类无鉴权（如 `sendSmsCode`）
- **LOW**: 字典/元数据类无鉴权

### Step 2: specialRequestPaths 分析

搜索 `specialRequestPaths` 数组——这些端点会自动注入微信 `jsCode`：

```bash
rg 'specialRequestPaths' app-service.js
```

典型政务模式：
```javascript
var d = [
    "/api-am/sys/wePolice/token",        // 微警换 token
    "/api-pm/families/addIterate",        // 家庭关系
    "/api-am/sys/api/getTokenByAuthcode"  // authcode 换 JWT
];
```

**攻击面**：如果 `getTokenByAuthcode` 标记 `tokenRequired:!1`，意味着仅凭微信 jsCode 即可获取有效 JWT → 任何微信用户可获取 token。

### Step 3: SM2 国密加密面分析

搜索 `crypto-list` 确定哪些端点使用 SM2 加密：

```bash
rg 'crypto-list|new Set\(' app-service.js
```

**关键发现模式**：政务小程序通常只对 **登录/注册/改密** 端点加密，PII 查询端点（地址/照片/个人信息）**不加密**，明文 JSON 传输。

提取 SM2 公钥：
```bash
rg 'PUBLIC_KEY' app-service.js
```

### Step 4: PII 端点 IDOR 分析

搜索涉及个人信息的端点及其参数：

```bash
rg 'getLivePersonPicture|userinfo|addressMsg|personalDetail|auditGuestInfo|decodeIteration' app-service.js
```

**政务 IDOR 高危模式**：

| 参数 | 说明 | IDOR 风险 |
|------|------|-----------|
| `rkbm` | 人口编码 | **极高** — 如可枚举则遍历全省居民 |
| `content` (QR 码) | 扫码获取他人信息 | **高** — QR 内容如可伪造 |
| `id` (粤居码 ID) | 解码个人信息 | **高** — 如 ID 可猜测 |
| `dzbm` | 地址编码 | **中** — 地址树遍历 |
| `fwxxbm` | 房屋编码 | **中** — 房屋信息遍历 |

### Step 5: 认证流审计

政务小程序常见 3 条认证路径：

| 路径 | 入口函数 | 机制 |
|------|----------|------|
| 微警认证 | `loginWithWJ` | 身份证号+姓名+手机号 → certToken → 人脸核身 |
| 粤信签 | `loginWithYXQ` | 粤信签 App 跳转 → token |
| 微信授权 | `getByWechat` | 微信 openid → 系统内匹配 |

检查点：
- `wePoliceNoPhone` 是否真能无手机号注册
- `fetchAuthCodeInfo` (`getTokenByAuthcode`) 是否仅凭 authcode 即可获取有效 JWT
- certToken 与 JWT 之间的转换是否有越权

### Step 6: 网络可达性判断

政务后端常见网络隔离模式：

```
┌─────────────┐     wx.request      ┌───────────────────────┐
│ 微信客户端   │ ──────────────────→  │ 政务 API (非标端口)    │
│ (用户设备)   │   经微信框架转发      │ 如 :9000 :8443 :8080 │
└─────────────┘                      └───────────────────────┘
        ↑                                     ✗
   外网 curl/代理 ────────── Connection Refused
```

**应对**：
1. Mac 微信已打开小程序 → MMKV 提取 JWT（见 `wxapkg-mac-decrypt`）
2. Proxifier 劫持微信进程 → 走 Charles/mitmproxy
3. 安卓模拟器 + Xposed/Frida → hook `wx.request` 抓请求
4. 如果 JWT 有效且非绑定 IP → 可在外部拼 curl 测 IDOR（如果网络可达）

## 产物

| 文件 | 路径 | 内容 |
|------|------|------|
| tokenRequired 清单 | `案卷/wxapkg/token_required_audit.json` | 所有无鉴权端点 |
| PII 端点清单 | `案卷/wxapkg/pii_endpoints.json` | IDOR 风险端点 |
| SM2 加密分析 | `案卷/wxapkg/sm2_crypto_analysis.json` | 加密覆盖范围 |
| API 分析报告 | `案卷/wxapkg/wxapkg_api_analysis.json` | 完整汇总 |

## 真实案例指纹（粤居码）

```
AppID:    wx9f75b01dcb4b1a79
后端:     gdrk.gdga.gd.gov.cn:9000
baseURL:  /service/yjm
SM2 覆盖: 仅 register/login/changePassword (9个端点)
未覆盖:   getLivePersonPicture / userinfo / addresses / OCR 全部明文
无鉴权:   ocr/sfzhm / photoSave / sendSmsCode / wePoliceNoPhone / getTokenByAuthcode
PII IDOR: getLivePersonPicture({rkbm}) → base64 人脸照
网络:     :9000 外网拒连，仅 wx.request 可达
```

## 立刻跑

```bash
# 解包后的目录做静态三刀（默认不对外 GET）
python3 炼蛊房/wxmini_static_probe.py run --dir <解包目录> --case <案>
# 抽出的 URL 要打授权域再加：--probe-urls
```

tokenRequired / rkbm / SM2 命中后，按本卡 6 步把结果写进 `案卷/wxapkg/`。

## 真源

- 手法 Playbook：`传承/微包·开锁.md`
- 工具：`python3 炼蛊房/wxmini_static_probe.py run --help`
- 前置 杀招：`微包`（Mac 解密）/ `wxmini-static-audit`（通用审计）

## 分流

| 场景 | 走 |
|------|----|
| 非政务普通小程序 | `wxmini-static-audit` |
| Mac wxapkg 未解密 | `wxapkg-mac-decrypt` |
| 发现 Actuator/heapdump | `spring-actuator-cloud-takeover` |
| 发现 AK/SK 云密钥 | `cloud-credential-leak-exploitation` |
| 发现支付密钥 | 假支付 Playbook |
| 认证绕过需打 RBAC | `rbac-bypass-authz` |
