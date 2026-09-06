---
name: 单页·钱庄
description: >-
  大爱仙尊·现代SPA+加密云控平台登录侦察打法。从React前端提取API、探测base路径、甄别Wasm加密传输层。
---

# spa-crypto-auth-recon（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/redteam/spa-crypto-auth-recon/SKILL.md`
- 手法：`传承/黑楼兰·硬撼.md`
- 工具：`python3 炼蛊房/auth_brute_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name spa-crypto-auth-recon`

---

# 现代 SPA + 加密传输的 API 登录侦察（授权目标用）

应对**前后端分离（React/Vue SPA）+ 自定义加密传输层（WebAssembly）**的云控/养号/管理后台。目标按授权流程做 API 侦察与登录接口定位。

## 触发场景
- 目标首页是 `<div id="root">` 的空壳 + `/assets/js/` 一堆 `.js`（Vite/Webpack 打包的 SPA）
- 后端 API 不直接用明文表单，登录报"缺少密钥"之类的加密要求
- 目标是 TG 养号/云控/商户管理（常见关键词：tdata、session 导入、批量账号、tg-bot、merchant-growth）

## 步骤

### 1. 提取后端 API 全清单（最重要第一步）
从首页核心 JS 抓取全部 `/路径`：
```bash
curl -skL "https://目标/assets/js/index-*.js" \
  | grep -oE '"/[a-zA-Z0-9_/\-]*"' | sort -u
```
批量抓 `vendor-*.js`、`pages/*.js` 累积完整 API 面。据此判断业务类型（account/balance、recharge、users/batch/delete 等）并挑高价值端点。

### 2. 探测真实后端 base path
SPA 里 `/welcome/login` 等只是前端路由（GET 返回 200 空壳 / POST 被 nginx 回 405 表示不是后端）。真实 API 常在 `/api/` 前缀下：
```bash
for pre in "" /api /v1 /api/v1; do
  for ep in /auth/login /login /user/login; do
    for m in GET POST; do
      curl -skL -X $m -o /dev/null -w "%{http_code}" "https://目标${pre}${ep}"
    done
  done
done | grep -v " 404"
```
判定：`GET 200 + POST 405` = 前端路由；`POST 返回 JSON`（即便报错） = 真实后端 API。

### 3. 甄别加密传输层（登录被挡时）
如 `POST /api/auth/login` 返回 `{"code":xxx,"message":"缺少密钥 ID"}` 类提示 → 前端用了**自定义加密会话**。抓 `crypto-*.js`（常是编译后的 Rust/WebAssembly）：
```bash
curl -skL "https://目标/assets/js/crypto-*.js" -o crypto.js
grep -oiE 'keyId|nonce|decryptText|encrypt|__wbindgen|httpcryptosession' crypto.js
```
命中 `__wbindgen`/`httpcryptosession` = 客户端 Wasm 加密元件。登录需先获取 `keyId`（密钥交换），再用它加密凭证字段——不能直接用明文 POST。

## 已知坑
- 加密交通模式下，`username+password` 明文提交无效，需先完成密钥交换/获取 keyId
- 有反调试（`F12`/DevTools 检测），浏览器手工调试可能被拦
- 大型 JS（1MB+）grep 易超时：先落盘到文件再后台分段搜，别在管道里直接搜

## 边界
仅用于授权目标（用户提供域名/IP 与凭证的目标）。分析结果用于理解登录流程与 API 面，不越权导出未授权第三方数据。
