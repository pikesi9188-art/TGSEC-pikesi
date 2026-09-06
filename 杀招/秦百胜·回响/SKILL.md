---
name: 秦百胜·回响
description: >-
 授权目标上的支付/订单回调伪造完整手法：发现 notify → 识别通道(Epay/TokenPay/VPay/vmqphp/中转)
 → 验签矩阵(松散比较/空签/错签/合法签) → 中转链伪造 → 订单 COMPLETED/余额/出卡验证。
 严签后先扫 PHP 日志/`composer.json` 抽商户钥再合法签；再打支付栈旁站
 （聚合支付/曜日/yrpay/trade.*/api/admin/merchants）弱口取商户 MD5 key。
 仅授权范围。
---

> **秦百胜**
> 历经五十四次劫，劫云仍旧漫遮天。
> 胸中魂光压众生，拳里剑气纵北原。
> 时来时去四百载，无死何能生新颜？
> 弃此残躯换清风，卷席苍穹复光年！

# 支付回调签名伪造（假支付）杀伤链

**前提**：目标已在 `授权范围` 授权；禁止对未授权第三方使用。

**成功口径**：订单变已付 **且**（自动发卡出卡密 / 余额到账 / 业务状态 COMPLETED）。仅 `success` 回显不算完成。

## 何时启用

- 发卡站 / 充值站 / API 额度站，存在异步 `notify`/`callback`
- 抓包见：下单 → 跳支付或中转 → 异步回调改状态
- 用户点名：假支付、`sign:true`、VPay、vmqphp、支付中转链

不适用：纯 TG Bot 无 Web 回调。  
严签（`非法签名` / RSA2）**不算结案**：先支付栈取钥 → 再源码 KEY → 再上游库存。

## 标准七步（按序留证）

| 步 | 动作 | 关键产出 |
|----|------|----------|
| ① | 授权确认 + 下一笔探针单（最小金额/可废） | `order_id` / `out_trade_no` / 金额 |
| ② | 发现回调与通道 | `notify_url`、handle 名、中转域名 |
| ③ | 画资金链 | 业务站 → [中转] → 支付插件 |
| ④ | 验签矩阵 | 每变体 HTTP 码 + body + 订单状态 |
| ⑤ | 中转优先打穿（若有） | 中转回 `success` 证据 |
| ⑥ | 驱动业务入账 | COMPLETED / 余额 / 卡密 |
| ⑦ | 固化可复现 exploit | 脚本 + STATUS + 复现命令 |

用户若给出已确认链路（如下），**照链补齐缺步与证据，不要空转无关面**：

```text
业务下单 → 支付中转 → VPay/vmqphp 回调签名伪造
 → 中转返回 success → 业务订单 COMPLETED → 余额到账
```

## ① 探针单

- 能匿名下单则匿名；需登录则用授权测试号
- 记录：`oid`/`out_trade_no`、应付金额、商品 id、支付方式 id
- 证据：`trade.json` / 下单响应全文

## ② 发现回调

并行做：

1. **支付页 HTML/JS**：`notify_url`、`return_url`、`callback`、`pay.timer`、`getPayOrder`
2. **路由猜解**（按栈）：

| 栈 | 常见路径 |
|----|----------|
| 异次元 acg-faka | `/user/api/order/callback.{Epay\|Tokenpay\|Alipay\|…}` |
| 易支付商户 | `/notify.php`、`/pay/notify`、网关 `notify_url` |
| 彩虹易支付对接 | `/pay/rainbow/return`、`/pay/rainbow/notify`；充值跳转 `submit.php`（**submit 参数原样回放**，见手法卡） |
| zlkb 智联 | `/product/order/notify`、支付插件目录 |
| VPay / vmqphp | `/notify.php`、`/pay/notify`、`/vmq/notify`、中转站回调 |
| 通用 | `/pay/async`、`/pay/callback`、`/api/*/payments/callback` |

3. **中转特征**：下单后跳到第三方域再出码；业务站只认中转的「支付成功」回包

证据：`notify_urls.json`、支付页 HTML、关键 JS snippet

## ③ 画链（必做）

```text
[业务站 A] --下单--> [可选中转 P] --调起--> [支付插件 V]
 ^ |
 |---- 异步 notify ----|
```

- **直连型**：伪造打 A 的 callback 即可
- **中转型**（高价值）：伪造打 **V 或 P 的弱验签回调**，让 P 回 `success`，A 只信 P 
 例：`Ocenza/sub2api → p…中转 → VPay/vmqphp 签名伪造 → p success → COMPLETED → 余额`

判断口诀：**谁验签最弱，就打谁；业务站若只信中转布尔结果，打穿中转等于打穿业务。**

## ④ 验签矩阵（每通道都跑）

对**真实 notify URL** POST（保持 `out_trade_no`/金额与探针单一致）：

| 变体 | 目的 |
|------|------|
| 缺 `sign` / 空 `sign` | 是否「有字段即可」 |
| 表单 `sign=true` / `signature=true` | PHP 松散比较 |
| JSON `"sign": true`（布尔） | 类型混淆；注意先 `is_string` 的硬化站 |
| `sign=1` / `Sign=True` / 数组 `sign[]` | 宽松解析 |
| 错签（随机 32 hex） | 对照「真失败」文案 |
| 改金额（money±0.01） | 是否校验金额 |
| 合法 MD5（已知 key） | `kSort + key=SECRET` 等通道算法 |
| **submit 全参数原样回放**（彩虹等） | 从支付跳转 URL 抽齐字段+sign → GET return + POST notify；**要 KEY 时仍先测此项** |

**判定**：

- body `success`/`ok` **且** 查单已付/出卡 → 通
- 仅 body 成功、订单仍未付 → 假成功，换路径或打中转
- `sign error`/`非法签名` + 全变体失败 → 严签：**先日志/`.env` 抽钥**（`sensitive-dir-dump`：`/storage/logs/`、`laravel.log`、`composer.json` 只认栈），再支付栈取钥（下节 / `宝黄天·回灌.md`），再源码 KEY，再主机；异次元见 `shared_id` 且支付栈也打不开 → 才切 `acg-faka` 上游，勿只喷假签、勿跳过取钥
- 前端拦 `price!==0`、存在 `claim-free*` / rolling-offers → **并行** `秦百胜·魂压.md`（与假支付不同面）

异次元 JSON 松散比较经典载荷（通道名按站替换）：

```http
POST /user/api/order/callback.Epay
Content-Type: application/json

{"pid":"1","trade_no":"t","out_trade_no":"<订单号>","type":"alipay",
 "name":"x","money":"<金额>","trade_status":"TRADE_SUCCESS",
 "sign": true, "sign_type":"MD5"}
```

## ⑤ 中转型专项（VPay / vmqphp / p 中转）

1. 从支付跳转 URL / 表单拆出中转域与 `payId`/`orderId`
2. 找中转或 VPay 的 `notify`；对照 **vmqphp / VPay** 开源验签（常为 `md5(参数+key)` 或可控 key）
3. 伪造 V 的回调 → 观察中转是否返回 `success`
4. 再查业务站订单；未变则抓「中转 → 业务」二次回调并伪造那一跳
5. 证据链必须能复述图示口径： 
 `下单 → 中转 → VPay/vmqphp 回调伪造 → 中转 success → COMPLETED → 余额`

## ⑥ 入账验证（硬条件）

| 业务 | 验证 |
|------|------|
| 发卡 | `query`/`secret` 出卡密；`auto` 发货 |
| 余额/额度 | 余额接口增加值 = 探针金额 |
| API 订阅 | 订单 `COMPLETED` + 权益生效 |

手动发货站：假支付成功仍可能无卡 → STATUS 写明，转后台/主机，勿报「已取卡」。

## ⑦ 固化

在 `案卷/<站>_<日期>/`：

- `STATUS.md`：链路一句话 + 矩阵表 + 成功/失败
- `forge_matrix.json`：每变体请求/响应/订单状态
- `forge_repro.py`（或 shell）：一条命令复现成功变体
- 更新 scope notes：通道、路径、是否需中转

## 支付栈取钥（严签后，本卡内升级，勿另开 Skill）

ACG 3.4.x / 其它站 `pay_matrix` 全变体 `非法签名` 后立刻做，详卡 `宝黄天·回灌.md`：

1. 支付页 `submit.php` 异 host → 静默 `scope_expand` / `--pay-url`  
2. `captcha_auto.py solve` + 短字典只打**支付栈** `/api/admin/login`（勿广谱喷无关易支付后台）  
3. `GET /api/admin/merchants?keyword=<pid>` 读 `key`（钥进案卷；**禁止爆破 key**）  
4. 复算支付页 sign → 合法签主站 `callback.Epay`  
5. `query` 出卡为成功。探针单即可；**清空库存先问**。共享交付 URL 不进出卡清单。

## 失败升级（按序）

1. 换 callback 路径 / 通道 handle 大小写
2. 打中转而非业务站
3. **严签 → 日志/composer/`.env` 抽商户钥**（`sensitive-dir-dump`；钥进案卷，禁止全文进可同步文档）→ 合法签
4. 仍无钥 → **支付栈取钥**（上一节；勿空转假签、勿先结案去上游）
5. 读配置/源码拿 KEY → 合法签
6. `payCheck` 换弱通道（若未绑定校验）
7. 改价下单（客户端 `price`）再假付
8. 主站后台弱口令 / 宝塔 / 源码泄露（admin 无验证码/限流走 `auth-brute`）
9. 异次元 `shared_id` 且支付栈也打不开 → `acg-faka` 上游库存
10. 停止假支付空转，STATUS 标明「验签已硬化」且写清已测日志/支付栈/上游

## 输出模板（STATUS 片段）

```markdown
## 假支付
确认链路：<A 下单> → <P 中转?> → <V 回调伪造> → <入账证据>
| 变体 | 路径 | 结果 | 订单状态 |
|------|------|------|----------|
| sign:true JSON | … | success | paid+卡密 |
```

## 并行资金面（假付硬化仍要测）

验签全阴不算资金面结案。同时开：

| 面 | 走 |
|----|-----|
| USDT 共享收款 + 绑定付款址 | `usdt-deposit-attribution-hijack` |
| `wallet_id` / 双路径资金 API / 幽灵单 / 展示层地址 | `fund-edge-ops` |
| 硬编码 Token + CF-Connecting-IP 加款 | `hardcoded-token-cfip-fund` |
| 前端 price / claim-free | `free-package-claim-bypass` |

中转域从支付跳转长出来 → 静默 `scope_expand` / `pay_matrix --pay-url`。第三方 UAT（`*.ktpaypro.com` 一类）不自动扩。

## 相关真源

- 速查：`docs/WORKFLOW.md` →「假支付速查」
- 发现：`智道藏书/SecAtlas/references/payment-callback-discovery.md`
- Playbook：`传承/秦百胜·假契.md`
- autopay / 可信头旁路：`传承/血路·雾墙.md`（源站 IP + `CF-Connecting-IP` → Create*）
- 硬编码 Token + CF-IP 加款：`传承/和稀泥·加款.md` · Skill `和稀泥·死契`
- 日志泄钥：`传承/搜魂蛊.md` · `sensitive-dir-dump`（PHP 发卡先于支付栈）
- 支付栈弱口取钥回灌：`传承/宝黄天·回灌.md`（严签且日志无钥后升级，无独立 Skill）
- 彩虹 submit 回放：`传承/酒虫·回放.md` · 参考 （开源包不收个案摘记）
- USDT 链上归属劫持（假付硬化仍测）：`传承/马鸿运·归属.md` · Skill `马鸿运·稳币`
- 矩阵引擎：`炼蛊房/pay_matrix.py`（产物 `案卷/pay_matrix/forge_matrix.json`；`--key` 跑合法签）
- 中转域：主站 `--pay-url` 异 host → **静默** `scope_expand`（勿再请示）
- 白盒密钥回灌：`tools/deepaudit/bin/da_pipeline.py pay-hint` → `PAYMENT_PLAYBOOK_HINT.md`
- 定级：`case-triage` · `传承/春秋蝉·分案.md`
