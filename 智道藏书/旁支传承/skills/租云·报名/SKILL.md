---
name: 租云·报名
description: "SaaS 邮箱验证注册+多租户ACL测试: mail.tm收码, 头对比扫BOLA, 隐藏端点diff."
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
    tags: [pentest, saas, multitenant, bola, fastapi, email-bypass]
    category: daaixianzun
---
# SaaS 邮箱验证注册 + 多租户 ACL 测试 (打站通用章)

触发: 目标要邮箱验证才能注册(收到验证码的邮箱可以绕过), 或 FastAPI/多租户 SaaS (项目/租户头隔离数据)。源自 origami.tech 实战, 方法通用。

## 1. 临时邮箱收验证码 (mail.tm) — 免真实邮箱注册
- `POST https://api.mail.tm/accounts` {"address":"x@<domain>","password":"..."} — 域名先 `GET /domains` 取
- `POST https://api.mail.tm/token` → JWT; **长 token 必须 curl `-o file` 落盘再读**, 终端输出会把 eyJ... 掩码截断成 13 字符 (parse 会拿到坏的 token → 401 Invalid JWT)
- 轮询 `GET /messages` (Bearer) — **响应是 hydra Collection** (`{"hydra:totalItems":1,"hydra:member":[...]}`, 不是数组!) → `GET /messages/{id}` 拿 text/html, 验证码 regex `\b(\d{4,8})\b`
- 邮件通常几分钟内到; 建多账号轮换可骑多注册并发
- 该邮箱还能当"第二个身份": 邀请 → 确认 → 拿第二项目/第二视角

## 2. 注册-登录-会话保持
- 注册: send_mail → confirm (code) → `POST /auth/token` (OAuth2 password grant) → access+refresh JWT
- **会话续期**: access 1h 过期 → `grant_type=refresh_token` 即可, 不用重登; 2FA 账号 password grant 返回 `token_type:2fa` 的 otp_token → `grant_type=2fa&otp_token&otp_code`
- FastAPI 工程: `/api/openapi.json` + `/api/docs` 常直接公开 → 秒得全端点图

## 3. 多租户 ACL 探测 (核心)
租户头 (如 X-ORIGAMI-PROJECT-ID) 下所有 GET 端点 × 分组对比:
- 头=自己的项目 vs 头=别人的项目 (已知存在, 如缺项目 100) → 全部跑一遍
- **响应码分诊**: 404 = 成员校验生效 (闭); 400/422 (参数错误) + 换别项目头仍是 400/422 = **参数校验先于权限校验 → 修正参数后可能 BOLA**; 200 = 误放通
- 修参数技巧: 参数含义从 openapi 422 错误回显的 input 结构反推; 时间窗类端点试 "无 Z 后缀 + 30 分钟窗" 常见通过
- 别忘对比 mine vs foreign 时同参数同 body, 一次抓 20-40 个端点约 1 分钟

## 4. BOLA-Write 两种形态
1. **body project_id 注入**: 某些 POST schema 里有 `project_id` (前端代码从不传这个字段, 纯后端 DTO 残留) → 传任意租户 id → 后端信任 body 不校验成员 → 跨租户写入
   - 判定: 前端 bundle 里 diff 出来 `POST xxx {project_id}` 而前端调用只传其余字段
   - 附带 oracle: 报 "Duplicate item" = 该租户存在且该记录已存在 (存在性枚举)
   - 对照: PUT/update 版端点往往校验成员 (404), 只有 POST 漏 — 不要误判整个资源面
2. **跨租户写失败 ≠ 封闭**: 对端 500 (Internal Server Error) 也是"尝试写入"的信号 (权限异常未捕获), 换 body 变体再试

## 5. WS 私有频道隔离测试
- WS worker (前端 /assets/socket-worker-*.js chunk) 直接暴露协议: 首帧 `{"request_id":..,"data":{"op":"auth","token":<at>}}` → authorized; 订阅 `{"request_id":key,"data":{"op":"subscribe","data":{...topic,project_id}}}`; 响应 op: subscribed/update/error
- 私有 topic (orders/positions/balances/...) 用别的租户 id 订阅 → "Permission denied" 即闭
- **先客户端恢复协议再测?**: 双向: 先读 worker JS 拿帧格式 (别像盲 fuzz 浪费时间)

## 6. 隐藏端点 diff (客户端 vs OpenAPI)
- `grep -oE 'url:"(/[^"]+)"'` 前端 bundle (main-*.js) ∪ ty.js 同系旧 bundle → norm `{x}` → diff `openapi.json` paths → 旧版端点列表
- 旧端点大概率 404 (服务升级已删) — 但 5 秒一次验证值得, 万一有活口
- 响应码对比 mine vs foreign + `"Project doesn't exist" vs "Not Found"` 文案差异有意义 (前者常=成员筛选错误文案)

## 7. JWT 矩阵 (一次性验证完)
- 解码 header/payload (HS256? 有 role claim?) → 试 alg=none, FastAPI 文档默认密钥 `09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7`, 常见弱密钥, 再后台全量 rockyou (下载 SecLists rockyou.txt.tar.gz → 解压 → 后台 python HMAC 跑, 1434万条约 1 分钟)
- 全部 NOT FOUND 就终判强密钥, 别耗

## 8. 限流现实 (Cloudflare crl)
- token/confirm 等端点 3 次/窗口 → 429, XFF/X-Forwarded/Forwarded/大小写/多header 全无效 (keyed by CF 真实 IP) — 无代理池别想爆破
- 大量请求 → 全局限流 {status:banned,cause:crl} ~45s 冷却; 脚本要: 失败重试 + 批次间隔 + 增量存盘

## 9. 最终目标判据 (密钥类)
明文存密钥 + 读接口按租户成员隔离 → 最终入口 = 成为目标租户成员 (invite 绑邮箱 / owner 行为 / staff 账号), 不是硬读取接口; BOLA 写 (预设/配置) 与聚合读 (spread_graph 类) 是半程战果, 不要当打穿

## pitfalls 快速表
- token 落盘再读 (终端掩码截断)
- mail.tm hydra Collection 不是数组
- "Duplicate item"/500 是 oracle 不是错误
- 先 diff client URLs 再打隐藏端点, 而不是猜路径
- 会话续期用 refresh_token, 不用重注册

## 支持文件
- references/origami-tech-case.md — 实战样板 (BOLA 端点、payload、封闭面清单)
- scripts/mailtm_receive_code.py — mail.tm 建号+轮询收码脚本 (改目标注册调用即用)