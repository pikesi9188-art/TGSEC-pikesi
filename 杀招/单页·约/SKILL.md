---
name: 单页·约
description: "SPA 前端协议逆向: webpackChunk 运行时注入、js-websocket 帧协议、SvelteKit+国密SM2/SM4 clientapi、第三方钱包链。"
version: 1.0.0
created_by: agent
---
# SPA 前端协议逆向（webpack 注入 + WS 帧协议 + 国密 clientapi）

自定义 TCP/Protobuf/PCAP（不是 SPA JS 帧）→ Skill `约`。  
`spa-frontend-reversing` 已并入本卡，不要再开那张。  
仅 MD5/VITE 盘口签名 → `gambling-api-crypto-reversal`；sk_encrypt 网关 → `encrypted-api-spa`；其余 webpack 签名 → `js-reverse`。

本卡只管 webpack / js-websocket / 国密 clientapi。

当目标 SPA（umi/webpack5 或 SvelteKit 打包）用前端加密调 API、用 js-websocket 推送、且需要精确参数但抓包不全时使用。  
本库实测两条链路写在正文里：AES-ECB + js-websocket（8G/kk8），以及 SvelteKit + 国密 SM2/SM4 clientapi。仓库**没有** `references/*.md` 和 `scripts/sm_crypto_client.js`，按下面章节复刻。

## 1. webpackChunk 运行时注入（核心技巧）

webpack5 打包的 SPA 即使没暴露 `__webpack_require__`，也能通过 push 回调拿到 require：

```js
// 页面控制台/page_eval 里执行：
window.__req = null;
window["webpackChunk"].push([["temp"], {}, function(r){ window.__req = r; }]);
// 之后 window.__req 就是 webpack require
```

**用途**：
- **复用页面自己的加密模块**：`req(<module_id>)` 加载，如 kk8 的 42858 = `{e:{encrypt(json)→base64 AES-ECB 密文, decrypt(...)}}`（key h4gT9Pkl2Lq7DsFm）→ 页面内构造加密请求，token 永远最新、加密格式 100% 一致
- **扫描模块源码找 API 调用参数**：`req.m` 是模块表，遍历 `String(mods[id])` 搜 `"game/enter"` 等路径 → 拿到调用处的完整 ext 构造（本例：模块 76122 泄露 game/enter 真参数）。比抓包可靠（frx net_capture 常漏 XHR）
- 页面内 fetch 同源 API（带页面 token/uid），绕过 Cloudflare 对 curl 的 409/1010

**坑**：`webpackChunk.push` 的返回值不是 require；正确姿势是第三个参数回调收 require（如上）。`window["webpackChunk"]` 是对象（chunkId→[modules, requireFn]），不是数组。

## 2. 页面内精确调用 API 的完整链路

1. `req(42858)` 拿加密模块 → `enc = mod.e.encrypt(JSON.stringify({common, ext}))`
2. `fetch("/gc/<path>?c=" + encodeURIComponent(enc), {headers:{Accept:"application/json"}})` 同源调用
3. 响应 `{s, m, c}` → `JSON.parse(mod.e.decrypt(c))`
- 页面 localStorage 的 token/uid 可能**加密存储**：值形如 `acliJurKrHgDQw/U68EAtg==` 用同一 AES key 解密得到 `[35317396]`（uid）。**token 每次请求滚动更新**（net 里同接口 token 不同）——要用当下最新的
- 响应 c 被 Cloudflare 概率截断（base64 长度非 4 倍数）→ curl 必须 `--compressed` + 重试

## 3. js-websocket 帧协议逆向（js-websocket 库）

目标 `wss://<host>` 用 js-websocket 库（握手 JSON 含 `"type":"js-websocket"`）时，帧格式：

**Package**（外层）: `[type(1B) | len(3B big-endian) | body]`
- type: 1=HANDSHAKE, 2=HANDSHAKE_ACK, 3=HEARTBEAT, 4=DATA, 5=KICK

**Message**（DATA 的 body 内层）: 第一字节 `type<<1 | (compressRoute?1:0)`；type 0/1/3 后跟 route（1B 长度+字符串 或 2B 数字 id）；type 0/2（REQUEST/RESPONSE）在首字节后跟 varint id；剩余为 body

**握手时序**：
1. 客户端发 `Package(1, UTF8(JSON{"sys":{"type":"js-websocket","version":"0.0.1","protoVersion":1},"user":{...}}))` —— 明文不加密
2. 服务端回 `Package(1, JSON{"code":200,"sys":{"heartbeat":10,...}})`（code 200=成功）
3. 客户端必须回 `Package(2)`（空 body）ACK
4. 心跳：`Package(3)` 空 body，按服务端 heartbeat 秒数周期发

**DATA 层 body 加密**：`AES-ECB(base64) 的 UTF-8 字节`（与 HTTP API 同一 key）→ `Package(4, Message(route, body))`，decoder 端 `JSON.parse(decrypt(bytes))`

**坑（2026-08 实测细化）**：
- **握手 `sys` 必须带 `"protoVersion":1`**——缺失时浏览器内连接也在 ACK 后立即断开（Python 客户端从一开始就断）
- **断开主因是客户端环境不是 token**：Python `websocket-client`（非浏览器 UA/上下文）即使带有效 token 也断；**页面内原生 `new WebSocket`（真实浏览器上下文）握手+ACK 后保持连接**（服务器/CF 放行真实浏览器）——要连这类 WS 就在 frx 浏览器 page_eval 里注入原生 WS 客户端
- **发错误订阅路由（如 gate.login / user.subscribe）→ 服务端立即断开**；正确路由未知时别乱发——只握手+心跳能保持（服务端会推 `Package(3)` 心跳）
- 前端可能**根本不实例化 socket**（封装类存在但无 new）→ 已加载模块里永远找不到订阅路由；可先 `window.WebSocket` 钩子拦截确认页面是否真连 WS

**逆向来源**：umi 主 JS 里搜 `"js-websocket"` / `TYPE_HANDSHAKE` / `heartbeat` 定位库代码；握手常量 `pt="js-websocket", Je="0.0.1", We=200`；encoder 定义在 connect 默认参数里（`Et.strencode(Ve.e.encrypt(JSON.stringify(...)))`）。

## 4. 参数逆向的通用套路

- **报错差异当 oracle**：同一接口不同参数 → 不同错误码（如 kk8: game_id 数字→json unmarshal error；字符串→20203 厂商异常；缺字段→20203；game_id 不存在→20201）。对照错误码反推字段类型/必填
- **错误码表**（kk8/8G 实例）：10=token/uid 不匹配或过期、20002=密码错误、20012=账号异常、20201=游戏不存在、20203=游戏厂商异常（多为参数格式）
- **正确参数从 JS 调用处挖**（webpack 扫描）优先于盲试组合
- **字段名 fuzz（"X不允许为空"链）**：加密 API 报 `xxx不允许为空` 时,用候选字段名列表逐个打,错误信息跳到下一个必填字段即命中当前字段名。lj5888 实测:`付款方名称`→`payingName`,`请求流水号`→`requestSeq`,`货币类型`→`rateType`,`第三方支付账号配置Id`→`thirdAccountId`。比静态分析压缩 JS 快得多,一次请求换一个字段名,看错误变化。

## 5. SvelteKit SPA + 国密 SM2/SM4 clientapi 逆向（lj5888 蓝箭体育验证）

识别特征:SvelteKit(`/_app/immutable/entry/*.js`)+ 所有 API 走 `/clientapi` 前缀 + 请求头带 `X-TENANT-CODE` / `X-DEVICE-ID` / `X-TIMESTAMP` / `Request-Encrypt`。加密体系与 AES-ECB 完全不同,是国密 SM2/SM4。

### 5.1 抓 bundle（base64 混淆绕过）
- HTML 可能把整页 JS 用 `document.write(atob(...))` 混淆:正则 `_d\("([A-Za-z0-9+/=]+)"\)` 提取 base64 解码即得真实 HTML,里面才有真正的 entry script
- 从 app.js 里 `import\("\.\./nodes/([^"]+)"\)` 正则提取全部 node 文件名,批量下载(`nodes/` + `chunks/`),再 grep `["'\`](/LIVE-[A-Z]+/[a-zA-Z0-9_/\-\.]*)["'\`]` 得到完整 API 地图(本次 367 条)

### 5.2 加密协议（完整复刻,不需破 AES）
- **访客认证换密钥**:`GET /clientapi/LIVE-MEMBER/visitor/auth`(明文请求,Request-Encrypt:false)→ 响应是 **SM4-ECB 加密**,key = `md5(X-TIMESTAMP + X-DEVICE-ID)`(hex 32 字符),解密得 JSON,内含 `token` + `webPublicKey` + `webPrivateKey`(SM2 密钥对)
- **请求体加密**:`"04" + SM2.encrypt(JSON, webPublicKey, cipherMode=1)`(C1C3C2),头 `Request-Encrypt: true`;URL 参数加密后要 `+ "&0=" + 同一密文` 重复一份
- **响应解密**:`response-encrypt: true` → base64 或 hex,去 `04` 前缀后用 `webPrivateKey` SM2 解密。400 错误体也是加密的(base64 包 hex),同样解密才能看真实错误
- **密码哈希**:`md5(md5Key + 明文)` — md5Key 常可通过 `GET /api/pub/env/md5Key` 未授权拿到(本次:`ruanjie2018@jlj34ij34lkj?d30RJcaipiao`)。登录/注册/支付密码全可预测
- **白名单接口不加密**:`/LIVE-FILESERVER/oss/uploadFile`、`/im/`、`visitor/auth` 本身

### 5.3 工具链关键坑
- **Python gmssl 库与前端 sm-crypto 不兼容**(C1C3C2 密文格式/04 前缀处理不同,解密报 `'str' object has no attribute 'hex'` / `invalid literal for int() base 16`)→ **用 Node + sm-crypto npm 包**,与前端 100% 一致:`sm2.doEncrypt/doDecrypt(msg, key, 1)`、`sm4.decrypt(hex, keyHex, {output:'string'})`
- 工作客户端：按本节用 Node + `sm-crypto` 复刻，跑通后落 `案卷/protocol/sm_client.js`。仓库不内置 npm 包。

### 5.4 资金链路快速验证点(赌博站变现面)
- **订单状态机**:`1111`=待支付,`6666/2222/4444`=处理中/已确认,`0000`=成功入账。`updatePayStatus`/`updatePaymentSuccessState` 无签名即可改状态(1111→6666 成功),但**余额入账只发生在支付平台回调后**——改状态≠到账,别误报
- **注册免验证码** = 无限账号 + 无限 SM2 密钥对,直接拿会员 token 全接口访问
- **借呗**:`borrow/amount`(memberEntrySwitch=1 开启)→ `borrow/borrow {borrowAmount}`,VIP 分级免费额度(VIP1=2元…VIP9=5000+),是潜在免费资金入口
- **绑卡/提现参数**:`savePayWithdraw {amount, paymentType, withdrawType, rateType, requestSeq, password}` + `saveBankCard`;支付密码 `setPayPwd` 无需旧密码(新号直设)

### 5.6 变现可行性验证(哪些是死路,别再重复踩)
lj5888 第二波验证结论(2026-08):
- **登录验证码是硬性的**:即使密码哈希 100% 正确,`noauth/login` 仍报 `21049 需要图形验证码`;带空 captcha → `21069 验证码错误次数过多,5分钟锁定`(腾讯防水墙)。**撞库链(md5Key+check/memberName 枚举+弱密码哈希)卡死在验证码**——注册免验证码≠登录免验证码
- **借呗 VIP0 被锁**:`borrow/amount` 返回 `vipEntrySwitch=0` 时,`borrow/borrow` 报"后台错误"(不是参数错,是等级门槛),升 VIP 需真实充值(如 VIP1 需 800)
- **提现/免提直充都有余额校验**:`savePayDirectWithdraw` 报"提现金额不能大于账户可提现金额"
- **改密有保护**:`updateLoginPwd {oldPwd, newPwd}`(旧密码 = md5(md5Key+旧密码));`resetLoginPwd` 需短信验证码(region+86, 报 21019)
- **ABpay 支付密码格式坑**:钱包侧密码提交 = `md5(6位密码)`(前端 js-md5 模块);`setPayPwd` 报"会员已设置过支付密码"说明 createBindAndLogin 时 payPwd 已存;confirm 接口传明文→"支付密码为空或无效"(格式校验),传 md5→"支付密码错误,4次后冻结"(值不对)→ 创建时格式与确认时不匹配则钱包入金确认永久死路,且**有冻结计数,别乱试**
- **ABpay quickBuy 无对手盘**:`130004 暂无可匹配订单` = 平台无真实卖家挂单;电子回单确认(payed)成功但**需卖家放行**,无真实付款不放币
- **结论**:纯漏洞链无法免费变现;要么真实入金走无损划转(充→钱包→unify/abpay/pay→提现),要么解决验证码后撞库。变现验证记录详见 reference。

### 5.5 第三方钱包绑定链(ABpay/slpay 系)
目标站点接第三方数字钱包(ABpay)时,可通过 **sign 链免登录建钱包**:
1. `GET /clientapi/LIVE-PAYMENT/getPaymentWayHallUrl` → 第三方支付链接 `https://atf.6ofe.com/bus/openapi/amount/trade?sign=...`
2. 调第三方 `GET /bus/noauth/openapi/amount/tradeH5?sign=<sign>` → 已绑定返回 `token`,未绑定返回 `secretToken`
3. 未绑定时浏览器走注册表单 → 抓 Vue 组件 `$data` 拿 `loginToken`,再 `POST /member/noauth/createBindAndLogin {loginToken, realName, payPwd}` → 建钱包并绑定目标站
4. 钱包 token 可调全部钱包 API(余额/转账/入金);**必须带设备头链** `x-device-code/x-device-id/x-device-brand/x-device-brand-type/x-device-sys-version/x-device-system/x-device-browser/X-Device-System-Version/X-Device-Browser-Version`,缺一个报 `Don't find deviceX in chain`
5. 钱包网关域名常可 FOFA/JS 提取多个(`wg.*.net` 等),互相可换
- **Vue 组件内省拿参数**:页面 `#app.__vue__.$children` 遍历,按 `$data` 特征键(如 `password2 && ruleForm2`)定位表单组件,读 `$options.methods` 的函数源码即得真实请求参数(本次:ruleForm3={realName, payPwd, loginToken})

## 真源

- 作业手法：`传承/逆骨.md` §3（webpack 第三参 / protoVersion / 国密用 Node）
- 盘口协议：`传承/星宿·秘语.md`
- 工具：`python3 炼蛊房/hall_crypto.py --help`
- 密钥：`python3 炼蛊房/js_secret_hunter.py hunt --base https://授权站 --case <案>`
- gRPC：`python3 炼蛊房/grpc_probe.py --help`
- 分诊：`python3 炼蛊房/re_sample_triage.py --path <bundle.js>`
