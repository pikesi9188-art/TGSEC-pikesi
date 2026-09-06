---
name: 信门参寻
description: "Unknown API params: error-driven probing + JS chunk mining."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, api, param-discovery, error-driven, minified-js]
    category: daaixianzun
---
# API 参数名逆向: 报错驱动爆破 + 前端 chunk 挖参

## 触发场景
- 接口报 `xxx.notBlank` / "Can Not Be Blank" / "Invalid parameter format", 但不知道正确字段名
- 前端表单构造代码在未下载的弹窗/页面 chunk 里, 已有 chunks/ 目录 grep 不到
- 已知端点(从 entry.js 的 API 清单拿到)但参数名反直觉, 瞎猜浪费时间

## 核心技术 1: 报错驱动参数名爆破(核心教训)
服务端对 DTO 的校验错误消息**泄露字段名语义**, 但有两个坑:

1. **主/确认字段都缺失时, 错误消息随机返回**(同一请求两种缺失, 返回哪个看 Map 迭代序)。
   实测: 单发 `{code:X}` → `confirm.notBlank`; 单发 `{newCode:X}` → "Withdrawal Code Can Not Be Blank" — 单发探测结果全是误导, 无法判断主字段是否绑定。
2. **正确姿势(两阶段)**:
   - 阶段A 探确认字段: 逐个候选名单发, 看哪个触发 `confirm` 类错误(说明主字段已绑定、只差确认字段)或先试常见名 `confirm`。
   - 阶段B 固定确认字段, 只换主字段候选名, 每次带两个值:
     - `{"<candidate>": "Test1234", "confirm": "123456"}` → 报 "Password Format Error" / 格式错 = **绑定成功**
     - `{"<candidate>": "Test1234", "confirm": "99999999"}` → 报 "mismatch" = **绑定成功**
     - 报 "Can Not Be Blank" = 没绑上, 换下一个候选
3. 候选词表: `code, newCode, withdrawalCode, newWithdrawalCode, withdrawCode, password, newPassword, verifyCode, authCode, oldCode, confirmCode, <field>Password, <field>Code...` — 命中的往往是最反直觉的那个(如 msg389 提现密码 = `newWithdrawalCode` + `confirm`)。
4. 探针脚本: `scripts/param_probe.py <base> <token> <path> <confirm_field> <cand1> <cand2> ...`(JSON 模式);multipart 端点改传 `--multipart`。

## 核心技术 2: 前端 chunk 补抓(已有 chunks/ 不全时)
- Nuxt/Vite 应用: entry.js 路由段直接给出页面→chunk 映射:
  `name:"profile-wallet-add-wallet", path:"/profile/wallet/add-wallet", component:()=>p(()=>import("./chunks/index-index-CHMAGC40.js")...)`
  → 直接 `curl https://<site>/_nuxt/chunks/index-index-CHMAGC40.js` 补抓, 不用整站爬。
- 表单构造代码特征: `new FormData` + `Object.keys(t).map(s=>(s!==void 0&&r.append(s,t[s])))` 的 API 包装 = **multipart 端点**;直接传对象 = JSON 端点。
- **minified 单行 JS 陷阱**: search_files/ripgrep 默认行模式对超长行会 0 命中或截断 → 用 `rg -o '.{0,80}<pattern>.{0,200}' file` 提取上下文;python `re.finditer` 也一样可靠。
- 找 API 方法调用方: 先 grep entry.js 里的方法定义(如 `addWallet(t,n={})`), 再 `rg -o '.{0,100}\.addWallet\(.{0,200}' chunks/*.js` 找调用点拿实参;调用方可能在未下载 chunk, 回到补抓。

## 辅助技巧
- 令牌失效/账号被锁(登录错 15/20 次): 白标博彩一般注册即返回 token, 直接注册新号, 不必过登录滑块。
- 枚举/配置端点(`*-enum/get`, `chain-type/get`, `bank/get{currency}`, `kyc-config/*`)能拿到字段枚举值(int/字符串)、必填项和字段名, 先拉再猜。
- 绑定/设置的"内容字段名"以 `*-user-info/get` 返回的 content dict 为准, 比猜表单快。
- KYC/绑定类端点常是 multipart(含文件字段), 用 `multipart/form-data` 而非 JSON, 否则报 "Missing Servlet Request Parameter" / Type Mismatch。

## 实战记录
- msg389.com(dingyi 白标)提现密码/钱包绑定/KYC 参数全记录: `references/msg389-wallet-kyc-params.md`（⚠️本包未含此案例文件，跳过）

## 交付
- 参数模板 + 每个接口的成功/失败响应贴进战报;证据落 `evidence/<date>-<target>/`。
