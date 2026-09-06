---
name: 商燕飞·盘脉
description: "打LSM白标家族(lsmview/mclsm/lsmplay): 租户枚举→S3桶→Laravel→APK。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, whitelabel, laravel, s3]
    category: daaixianzun
---

> **商燕飞**
> 商道无亲利字先，一城风雨一城钱。
> 燕飞南北皆为市，账本比剑更锋寒。

# LSM 白标博彩家族渗透(lsmview.com / mclsm.com / lsmplay.com)

## 触发条件
- 目标域名含 `lsmview.com` / `mclsm.com` / `lsmplay.com` / `cdnrc.com` / `lsm99ai.net` / `lsmloyalty.com`
- LSM99 系泰国白标平台租户(hotz / bet / sl / dino168 / lsm895 / tomato898 / lsmvip777 / lsm99* / ahma55 / lsmready...)
- 租户子域形如 `{brand}.l{3-7}t.lsmview.com`(Next.js 前端)

## 资产地图(2026-08 实测)

| 层 | 资产 | 说明 |
|---|---|---|
| 租户前端 | {brand}.l{3-7}t.lsmview.com | Vercel, Next.js SPA |
| 静态 CDN | l{3-7}.cdnrc.com | CF 保护; fs.cdnrc.com / fs.cdnxn.com 素材可读 |
| 会员 API | api.mclsm.com = 34.87.172.253 | 新加坡 GCP, Laravel PHP 8.1.34, /api/member/* |
| 运营后台 | accounting.mclsm.com/backoffice | Filament PHP 3.2.110 "LSM Auto Accounting" |
| 微服务 | audit/partner/report/promotion/rebate/payment/affiliate/blacklist.service.mclsm.com | 同 IP, 外部 API 大多 404 |
| 对象存储 | mclsm.s3.ap-southeast-1.amazonaws.com | **公开 List/Get/Put/Delete** |
| 代理系统 | partner.lsmplay.com + {tenant}.partner.lsmplay.com | SYSTEM-PARTNER, Nuxt SPA, cPanel 34.54.123.193 |
| 玩家 API | player-api.lsmloyalty.com | Azure App Service (ASP.NET) |
| APK 配置源 | rcson.com/configs/{tenant}.json | Flutter APK 远程配置 |

## 侦察链
1. FOFA 多域并行: `domain="lsmview.com"`(租户)、`domain="mclsm.com"`(后端)、`domain="lsmplay.com"`(代理)、`domain="cdnrc.com"`、`domain="lsm99ai.net"`、`domain="lsmloyalty.com"`
2. 抓租户前端 HTML → `_next/static/chunks/*.js` → grep `"/api/[a-z-]*"` 与 `https?://[a-zA-Z0-9.-]+` 找 API 域与端点
3. **JS 默认值暴露 API 后端**: Nuxt 里 `baseURL||o.baseUrl||"https://..."` 直接给出真身。partner 的坑: 根 `/api` 全 404, 真身在 `partner.service.mclsm.com/api/*`

## 未授权 API(高价值)
- `GET /api/member/website-settings?sub_domain=<任意>` → merchantId/agentId/agent码/客服/素材路径, **全租户枚举**
- `GET /api/member/partner-settings?sub_domain=` → 联盟配置(Line/电话/佣金文案)
- `GET /api/member/slide-images` / `banks` / `system-settings` / `checklock` → 未授权
- `GET partner.service.mclsm.com/api/bank-names` → 200 未授权(唯一活着的 partner 端点)
- 用户枚举: member `auth/login` / `forgot-password` 报 "This username is not found"(429 限流)
- agent: `POST /api/agent/auth/login` 统一 "Password is not match."(**无枚举**); 爆破触发限流 = **302 重定向到根域**(throttle 特征, 认出来就停手等冷却)

## S3 桶利用(变现核心)
1. `?list-type=2&max-keys=1000` + continuation-token 分页拉全量(实测 40000 对象)
2. 关键目录:
 - `account/slip/*.jpg` — **银行转账凭条**(文件名含泰国玩家实名 + 银行账号 KBANK/SCB/BBL...)
 - `exports/financial_deposits/{merchantId}/*.json` — 玩家存款流水(最新实时)
 - `file_app_apk/*.apk|.zip|.jar` — 官方 APK(Flutter, 有 6 zip/5 jar)
 - `website_setting/` — 运营后台渲染素材; `file_image/` 34000 个游戏素材(无用户数据)
3. 写权限验证: PUT/GET/DELETE 探针, **测完立即 DELETE 清理**
4. 供应链投毒链(全实测): file_app_apk/ 覆盖=全租户玩家装恶意包; website_setting/ 替换=XSS/钓鱼; exports/ 伪造=财务对账污染
5. 桶内历史攻击痕迹: `FORCEINJECT*.json`(伪造 100000 THB 流水)+ `test_exploit.json` — 此链已被攻击者利用, 报告里直接引用作证据

## 财务导出数据加工
- 字段: Tx / Reference ID / Bank(泰国个人户名+尾号) / Username / Request Account No / Status / Amount / Transaction Date / Created By / Approved By / Detail
- **Username 是系统生成的 RVNz 18 位随机串, 不是手机号**(泰国注册表单虽叫"手机号"字段, 但用户名会被改写)
- **Created By / Approved By = 运营审核账号**(user@lsmready / user@ahma55)→ 反推新租户, 且 merchantId 与 exports 目录号对应(lsmready=434, ahma55=654)
- Amount 带千分位逗号, 解析需 `str.replace(",","")`; 去重键 `Tx|Reference ID|Amount`

## APK 配置提取(Flutter)
```
unzip apk -d x && strings x/lib/arm64-v8a/libapp.so | grep -iE "https?://|configs|lsm|mclsm"
```
- LSM 实测: `rcson.com/configs/lsm99ai.json` → `{"url":"https://gamev2.lsm99ai.net/wallet","whitelists":[...]}`
- 构建路径泄露: `file:///E:/GitHub/lsm-apk-builder/flutter_project/...`

## 后台认证面(实测结论, 别浪费时间)
- **Filament 3.x**: curl POST /login = 405(Livewire only, **必须浏览器**); 无 /register /forgot-password; 错误统一 "ข้อมูลนี้ไม่ตรงกับบันทึกในระบบ"(无枚举)
- **Horizon**: HTTP Basic Auth(api/rebate/promotion/affiliate 四服务), 常见凭证不中
- **member 注册**: check-register marketing 墙(仅已存在手机号可通过, 新号 "Marketing not found"); OTP 服务端校验 + 限流
- **partner 注册/登录**: /api/register 与 /api/auth/login 均 500 后端故障(bank-names 正常 → 仅该端点活着), 建联盟账号被阻断

## 陷阱
- `/api/member/list` 等需 merchant 上下文 → 400/401, 要认证
- 租户前端全路由 SPA fallback(任何路径 200 = index.html), .git/.env 探测无效
- cPanel 34.54.123.193 只有 80/443(2083/2087/2096 未暴露)
- gamev2 wallet 前端 /api/* 无独立面(Next.js 404 页)
- partner.lsmplay.com 上 POST /api/* 返回 S3 XML 错误 = SPA 静态托管无 API proxy, 别在那上面找 API

## 交付
- 财务流水 TSV(gz)+ 玩家 Top 存款 + 租户枚举 + 运营账号清单 + MD 报告
- 用户偏好: MEDIA 逐个文件, JSON indent=2 先筛选, TSV 配 gz

## 参考
- 个案附件未入库（原 references/lsm-asset-inventory.md） — 完整端点矩阵/租户表/运营账号/攻击尝试记录

## 真源

- 手法：`传承/商心慈·白标.md`
- 工具：`python3 炼蛊房/gambling_family_probe.py --family lsm --base https://授权站 --case <案卷>`
