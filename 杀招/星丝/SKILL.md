---
name: 星丝
description: >-
  大爱仙尊前端 JS 逆向。签名链路、SourceMap、webpack 加密模块、JSVMP/WASM/Worker。
  盘口 webpackChunk / js-websocket / 国密走 spa-protocol-reverse。
  二进制/APK/so 不要用本卡。
---

> **星宿**
> 一生不利己，忧济在元元。
> 捐躯赴难死，星光照人间。
> 三百万年转瞬封，半为天意半为空。
> 算尽天下穷心力，逆转宿命显神通！

# js-reverse（大爱仙尊）

目标须在 `授权范围`。本卡绑定**仓库里真有的工具**，不绑定不存在的 MCP 前缀，不引用空的 `references/`。

盘口 webpackChunk / js-websocket / 国密 → `spa-protocol-reverse`。  
`sk_encrypt` → `encrypted-api-spa`。仅 MD5/VITE → `gambling-api-crypto-reversal`。  
微信小程序目录 → `wxmini-static-audit`。

## 真源

- 手法：`传承/星念蛊.md`
- 作业层：`传承/逆骨.md` §3
- 专题表：`传承/逆骨·分科.md` §2
- 工具：`python3 炼蛊房/js_secret_hunter.py doctor`
- 分诊：`python3 炼蛊房/re_sample_triage.py --path <bundle.js>`

## 立刻跑

```bash
python3 炼蛊房/js_secret_hunter.py doctor
python3 炼蛊房/js_secret_hunter.py hunt --base https://授权站 --case <案>
# 已有 bundle
python3 炼蛊房/js_secret_hunter.py file --path app.js --case <案>
```

产物：`案卷/js_secrets/js_secrets.json`。  
L1：score≥60 的 aes/salt/jwt，或 sourcemap 非空。有密钥立刻接协议/假支付。

## 五步（观察优先）

1. **Observe** — 目标请求 URL、initiator、可疑脚本。抓页用 `scrapling` / 浏览器，不要先猜环境。
2. **Capture** — 最小采样：请求体、签名字段、调用顺序。能 hook 入参就不要先下断。
3. **Hunt** — 跑 `js_secret_hunter`（会跟 `.map`）。不要手写第三套正则。
4. **Rebuild** — 本地 Node 复现必须有页面证据。一次一个最小补丁。
5. **Verify** — `verify` 或业务探针只读重放；服务端接受才算过闸。

JSVMP：先找 dispatcher，禁止盲补环境。  
WASM：先导入表/桥，再反编译。  
Worker：先看 `postMessage` 契约。

## 本库钉死的坑

webpack 第三参才是 require，返回值不是：

```js
window.__req = null;
window["webpackChunk"].push([["se-temp"], {}, function (r) { window.__req = r; }]);
```

国密复现用 Node `sm-crypto`，不用 Python `gmssl`。  
报错差异当 oracle，比读压缩 JS 快。

## 没有的东西不要找

- 仓库没有 `js-reverse/references/*.md`
- 仓库没有 `bootstrap-reverse.ps1`
- 当前 Cursor 会话没有 `js-reverse_*` MCP 时，用 `js_secret_hunter` + 浏览器，不要假装工具在

## 交接

| 发现 | 切 |
|------|----|
| `js-websocket` / `/clientapi` / SM2 | `spa-protocol-reverse` |
| 支付 notify/sign | `payment-callback-forgery` |
| APK 同 salt | `apk-recon` |
| 自定义 TCP/PCAP | `protocol-reverse` |
