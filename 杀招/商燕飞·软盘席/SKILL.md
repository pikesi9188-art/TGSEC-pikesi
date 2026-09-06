---
name: 商燕飞·软盘席
description: "PG Soft 运营商 session 链：gameurl/seoul/pgs 指纹、gi 参数关键、verify 换 tk、WebLobby 登录。触发：PG Soft/gameurl/seoul.net/pgs.net/gi 参数。"
version: 1.0.0
created_by: agent
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# PG SOFT 聚合商 Operator 会话链渗透

PG Soft 通过随机域聚合商(one_api 模式)向博彩平台提供游戏。平台侧拿到 launcher URL，客户端协议为 blob 解密 + 会话验证。本 skill 覆盖从 launcher 到玩家会话(tk)的完整链，并判定资金面。

## 触发条件

- 平台游戏 URL 形如 `https://<rand>.store/gameurl/seoul/pgs/<uuid>.html`（launcher 域名每次随机）
- 或聚合 API 域 `api.<rand>.com`（阿里云 DDoS 防护）、lobby 域 `m.<rand>.com`（腾讯云 CDN）
- launcher HTML title = `game-launcher BY PG SOFT®`

## 利用链

### 1. 提取 ot/ops/lobby 域
launcher HTML 尾部 IIFE 内嵌 base64 MessagePack blob（`(function(){...` 前），解码后含:
- `f[0].url` = `https://m.<lobby>.com/65/index.html?ot=A-<uuid>&ops=<uuid>&l=zh&f=<平台跳回URL>` → **ot**(operator_token, A- 前缀) + **ops**(player session)
- `tid/ci/rt/at` 等字段（tid 与会话相关）

### 2. verifyOperatorPlayerSession（核心，gi 是关键）
```
POST https://api.<lobby域>/web-api/auth/session/v1/verifyOperatorPlayerSession
form: os=<ops>&otk=<ot>&gi=<PG游戏数字ID>&btt=1
```
- **gi 必须是 PG 游戏数字 ID**（不是平台 game_id！）
- 平台 firm_game_id 形如 `PGS_65` → **gi=65**
- **gi=0 → 1402** "Failed to verify operator player session"（误导性错误！表象是 8G 的 OneApiVerifySign 拒绝）
- **gi=平台 game_id(如 590704) → 1404 Game not exist**
- gi 正确 → `dt:{oj:{jid}, pid, pcd, tk, st, geu:"game-api/xxx/", lau, bau, cc, cs, nkn, gm:[{gid,msdt,medt,st}], uiogc:{...}}`
 - **tk** = 玩家会话 token（可无限次 verify 刷新 = 会话铸币）
 - **pid** = 玩家 ID（平台生成的 PG 玩家账号）
 - **cc** = 货币（8G 场景 CNY）

### 3. WebLobby/Get（余额+游戏列表）
```
POST https://api.<lobby域>/game-api/lobby/WebLobby/Get
form: otk=<ot>&atk=<tk>&lang=zh&du=https://m.<lobby域>&cc=CNY&pf=1
```
→ `dt.wlii.ti.t[].gid`（数千 PG 真实 gid）；含钱包/余额字段

### 4. GetLaunchURLHTML（无鉴权游戏启动）
```
POST https://public-api.<lobby域>/web-api/operator-proxy/v1/Game/GetLaunchURLHTML
form: ot=<ot>&gi=<PG游戏ID>&ut=game-entry
```
→ 仅 ot+gi 即生成 launcher 页（无玩家校验）——**ot 泄露即商户身份冒用面**

### 5. 资金面判定
- `Cash/TransferIn/TransferOut/Player/Report` 等 operator-proxy 端点 → **404 Route Not Found = 钱包禁用**（资金链断，无法铸币/转出/提现）
- 钱包禁用时 verify/tk 链仅信息级（会话滥用、商户凭证泄露证据）

## Pitfalls

- **gi 传错是 verify 失败的头号原因**——1402/1404 都是 gi 问题表象，不是"铸币链关闭"
- verify 无频率限制 → 同一 ops 可刷无限 tk
- launcher 会话(uuid)被 launcher 页面加载消耗与否与 verify 无关（gi 对了一切通）
- ot 是 A- 前缀带商户 ID 格式；去掉 A- 前缀 → 1204 Failed to get operator
- PP(Pragmatic Play) 是**不同聚合商**: game_path 形如 `<rand>.giiraokvtf.net/gs2c/playGame.do?key=token=<uuid>...&userId=<9位随机>`，302 → ssid → /gs2c/game/load；gs2c 端点 reloadBalance.do/SingleSessionAPI/data 需 JSESSIONID；玩家侧无转账（钱包在商户 API）

## 案例：8g8888.com（kk8 平台, business_id=254）

- 平台 game/enter 参数: `{"game_id":"590704","home_url":"https://8g8888.com","demo":false,"currency":"","is_pc":true}`（game_id 必须字符串; 缺 home_url/demo/is_pc → [20203] 厂商异常）
- ot 泄露: `A-25dbe7c8-db56-470b-8cad-266da88ea8ae`; PGS_65 → gi=65 打通
- 完整请求/响应样例见 references/operator-verify-examples.md
- 平台端更多细节（注册/协议/pprof/宝塔）见 kk8-tma-platform-pentest（用户自有）

## 真源

- 手法：`传承/凤九歌·天地歌.md`
- 工具：`python3 炼蛊房/session_pipeline.py --help`
