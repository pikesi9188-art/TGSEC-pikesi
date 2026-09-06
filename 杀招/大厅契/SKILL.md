---
name: 大厅契
description: >-
  大爱仙尊·白标博彩大厅AES配置解密。OSS密文→ECB解api_domain→体验号。
---

# cg-lobby-config-decrypt（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/cg-lobby-config-decrypt/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name cg-lobby-config-decrypt`

---

# 白标博彩大厅 · AES配置解密与接口定位手册

> 应对 CG/Cocos 白标博彩大厅（siteCode 族）。核心链：**落地页HTML拿OSS桶 → 桶上config_data.json密文 → 前端JS/AES口令解密 → 明文api_domain → 同族path表定位接口 → 第二层AES-CBC登录拿体验号**。

## 目标判定
- 落地页/APP下载页 HTML 内有 `siteCode=XXXX`、`ossName`、`ossType` 字段。
- 主页/大厅是 Cocos 引擎或白标模版。
- 静态资源在 OSS（阿里云/AWS 桶），不在业务 API。

## 双层加密 · 不要混

| 层 | 文件/通道 | 算法 | 钥匙来源 | 解开得到什么 |
|----|----------|------|---------|-------------|
| **配置层** | OSS `cocos/config_data.json` | AES-ECB（16字节口令） | 官网JS字符串+APK字符串，同一段 | api_domain/oss_url/客服/下载域 |
| **登录层** | `POST /hall/api/member/getFastLogin` | AES-CBC，key+IV | 大厅前端JS（与配置层不同钥匙） | 体验号session、假金币 |
| **客服层** | 聊天 sendMsg | AES key=iv | 客服页JS | 消息体；和大厅登录钥匙又不是一把 |

先解配置层，才知道登录该打哪个 host。**不要拿配置口令去解登录 body**。

## 步骤 1 — 从 HTML 拿到桶（不要先猜 API）

打开落地页/APP下载页，**存HTML**，抽内嵌字段和URL：

| 从 HTML 直接读到 | 用途 |
|-----------------|------|
| `siteCode=1916`、`siteName` | 所有大厅请求都带这个 siteCode |
| `ossName`/`ossType` 占位 | 说明静态资源在 OSS |
| 完整 `*.oss-accelerate.aliyuncs.com/...` 或 x-oss-* 响应头 | **桶名+地域** |
| 客服 `https://<IP>:1584/chat/index?channelId=...` | 客服链，先记下 |

## 步骤 2 — 配置文件路径（不是扫出来的）

同族（CG/Cocos）静态布局固定：
```
https://<桶>.oss-accelerate.aliyuncs.com/cocos/config_data.json
```
HTML 或解密前的 `oss_url` 字段里就有这条。`GET` 下来是**看不出 JSON 的二进制/密文**，不要当坏文件丢掉。

## 步骤 3 — AES 口令怎么定位（不是爆破）

对**官网自己的 JS** 做字符串扫描，模式是短 ASCII、逗号、常见默认口令：
```
https://<官网>/js/index-<hash>.js
```
本案命中一段 **16 字节**口令（本族多站复用，形态类似公开框架默认串）。
同一段字符串在下载的 APK 里再扫一次，**只命中这一把**，交叉验证。

**不要**先猜算法再撞 16 字节空间。钥匙在前端里。

## 步骤 4 — 解密
```
GET config_data.json → raw.bin
AES-128-ECB 解密，key = 16 字节 ASCII（无独立 IV）
得到 JSON
```
解完应直接看到字段名，不是再套一层 gzip。明文顶层包括：
- `api_domain`：**大厅 API 主机列表（多活，逐个探）**
- `oss_url`/`web_bucket_url`：确认没解错
- `oss_domain`/`download_domain`：另外的桶
- `siteCode`：与 HTML 对齐
- 客服/gossip/report URL：横向入口

解错的标志：不是 JSON 或没有 `api_domain`。换 ECB/CBC 之前先确认钥匙和文件对不对。

## 步骤 5 — 敏感接口怎么找（不是 ffuf）

来源只有三个，按顺序用：
```
① 解密 JSON 的 api_domain → 知道打哪台主机
② 同族固定 path 表（Cocos 大厅）→ 知道 path 长什么样
③ 官网/大厅 JS 里的 /hall/api/ → 补表、核对参数名
```

### 未登录就能打的（先验证"解对了"）
这些 path 是同族大厅公开布局，带 `siteCode=19XX`：
```
/hall/api/lobby/site/getSiteInfo          → 站点名/币种/开关
/hall/api/lobby/webapi/h5/config/getInfo  → H5 配置
/hall/api/lobby/currencyInfo/getAllCurrency → 币种
/hall/api/lobby/config/getAppDownloadInfo  → 下载入口
/hall/api/message/smsCountry               → 短信区号
/hall/version                               → 版本钉扎
```
63 次探测 = 上述 path × api_domain 各 host。未带会话时部分回"设备已登出"→路径对、差 cookie，不是 404。

### 登录接口：第二层加密
JS 里登录不走 JSON，走：
```
POST /hall/api/member/getFastLogin
Content-Type: text/plain
language: zh / currency: USDT / timeZone: Asia/Shanghai / siteCode: 1916
```
body = **AES-CBC(明文JSON)**，钥匙/IV 在大厅 bundle 里（和配置层 ECB 口令分开）。

还原顺序：
1. 大厅 JS 搜 `getFastLogin`、`CryptoJS`、`AES`、`mode.CBC`。
2. 记下 key、IV、是否 `Utf8.parse`。
3. 明文最小字段按同族：体验/快速登录（无验证码）。
4. 响应若仍是密文，用同一把 CBC 解；本案回包已是 JSON，code=1 即体验号。

### 有会话后补的接口（仍是表，不是爆破）
| 类 | 例 |
|----|----|
| 系统 | `/hall/api/gohal/getSysInfo` |
| 资金 | `finance/setting`、`payChannel`、`withdrawInfoV2` |
| 客服坐席 | `staff`/`staffAllV3` |
| 上传 | `ossSts`（presign 空则写不了） |
| 代理 | `agent_index`（看是否下发敏感字段） |

path 来源：同族已打站的表 + JS 里 `/hall/api/` 字符串。**没有**对 `/hall/api/` 做万级字典爆破。

### 客服接口
不在 api_domain 里。来源是 HTML 的客服URL。进页后跟 XHR：`chatStart` → `transferAgent` → `sendMsg`。消息体另有一把 AES（key=iv，在客服 JS）。后台 `/chat/admin` 存在则登录口可能通。

## 实现顺序
```
落地页HTML → siteCode+OSS桶+客服URL
官网JS/APK → 16字节配置口令
GET /cocos/config_data.json → AES-ECB解出api_domain
对每个api_domain → 同族未登录path确认是大厅
大厅JS → getFastLogin+CBC key/IV
POST text/plain密文 → 体验号session
同族已登录path表 → 资金/坐席/STS
HTML里的:1584 → 客服链（与大厅钥匙无关）
```

## 诚实纪律
- 配置解密成功 = 明文JSON且有api_domain才成立。
- 体验号纸面额度不可提，不要当"余额到账"。
- 客服XSS投递后坐席离线未触发则如实标注。
- 云SK/主机root/全站用户库没拿到=没拿到。
