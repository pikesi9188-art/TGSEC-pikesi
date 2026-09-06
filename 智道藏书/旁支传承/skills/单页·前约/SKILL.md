---
name: 单页·前约
description: "SPA前端逆向(webpack/umi): webpackChunk注入、模块源码逆向API参数、复用页面加密."
version: 1.0.0
created_by: agent
---
# SPA 前端逆向（webpack/umi/react）渗透技术

适用于：目标前端是 webpack/umi 打包的 SPA（特征：单 HTML + 巨型 bundle.js + 异步 chunk），
API 全加密（AES/RSA）或参数未知、Cloudflare/WAF 拦 curl 直连的场景。
本类技术在 8g8888.com（kk8 博彩盘）实战验证：game/enter 参数、注册参数、WS 协议、
localStorage 解密全部靠这套方法打通。

## 1. webpackChunk 运行时注入（核心技巧）

umi/webpack5 打包的页面在 `window["webpackChunk"]` 暴露模块注册表（对象 {chunkId: [modules, requireFn]}）。

```js
// 拿 __webpack_require__（先清空再 push，避免污染）：
window.__req = null;
window["webpackChunk"].push([["t"], {}, function(r){ window.__req = r; }]);
// 之后 window.__req 就是 require
```

用途：
- **加载任意模块**：`req(42858)` → 模块导出（如加密模块 `.e.encrypt/.decrypt`）
- **遍历全部已加载模块源码**：`req.m`（moduleId → 函数）→ `String(mods[id])` 搜字符串
  （`"game/enter"`、`"page_size"` 等）→ 拿到**调用处的真实参数构造**（比猜参数快 100 倍）
- 注意：未加载的异步 chunk 模块不在 `req.m` 里——先触发页面路由（如点游戏/打开弹窗）再搜

## 2. 页面内加密 fetch（绕过 WAF/Cloudflare）

用页面自己的加密模块在页面上下文构造请求（同源、带实时 token、加密一致）：

```js
const cryptoMod = req(42858);           // AES-ECB 模块（id 随目标变化，从源码找）
const enc = cryptoMod.e.encrypt(JSON.stringify(payload));
const resp = await fetch("/api/path?c=" + encodeURIComponent(enc), {headers:{"Accept":"application/json"}});
const j = await resp.json();
const data = j.c ? JSON.parse(cryptoMod.e.decrypt(j.c)) : null;
```

比 curl 稳定（无 409/1010），且 token/会话与页面完全一致。
找加密模块：搜 `req.m` 里含 `"AES.encrypt"` 或 `mode.ECB` 或 `encrypt:function` 的模块。

## 3. localStorage 加密值解密

SPA 常把 uid/token 用**同一 AES key** 加密后存 localStorage（键名是 MD5 哈希，值 base64）：
- 用目标前端的 AES key（ECB）直接解密所有 localStorage 值
- 实战：键 `9871d3a2c554b27151cacf1422eec048` = AES 解密 = `[35317396]`（uid！）
- 用途：确认浏览器当前登录的 uid（token 绑定 uid，对不上会报"用户异常"）

## 4. 从模块源码逆向 API 参数（替代抓包）

frx/net_capture 抓不到页面内 XHR 时，直接搜模块源码：

```js
for (const id of Object.keys(req.m)) {
  const src = String(req.m[id]);
  if (src.includes("game/enter")) { /* 打印上下文 */ }
}
```

实战收获（kk8 平台）：
- game/page 参数是**复数** `cate_codes`/`firm_codes` + `is_hot:-1` + `keyword` + `page` + `page_size`（单数全返回 list:null）
- game/enter 参数 `{game_id(字符串!), home_url, demo, currency, is_pc}`（game_id 数字→json unmarshal error；缺 home_url/demo/is_pc→[20203] 厂商异常）
- 注册参数平铺 ext `{login_type, nation_code, phone, gaid, did, user_icon, password, telegram:"register", pid}`（不是 params 包裹；phone 不是 account）

## 5. 配套技术

- **WS 协议逆向**：js-websocket 库特征（`TYPE_HANDSHAKE=1/ACK=2/HEARTBEAT=3/DATA=4`、Package=[type 1B, len 3B BE, body]、Message=type<<1|compress + varint id + route + body）；从 bundle 搜 `"js-websocket"` 常量 `pt=`/`Je=` 拿握手格式
- **管理面板入口枚举**（宝塔 domain.conf Host 头枚举、Laravel 异常页版本指纹）：见 `references/panel-entry-and-laravel-fingerprint.md`

## Pitfalls

- webpackChunk.push 的返回不是 require——必须用第三个参数回调 `function(r){window.__req=r}`
- 页面导航后 `window.__req` 丢失——每次 page_eval 前重新注入
- `req.m` 只含已执行模块；搜不到就先去目标页面触发异步 chunk 加载
- 页面内 fetch 用相对路径（同源），别写绝对 URL
- 解密 localStorage 值失败时先检查 key 是否同一（有些值可能是别的算法/明文）
