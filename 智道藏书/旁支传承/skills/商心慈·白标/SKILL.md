---
name: 商心慈·白标
description: "打白标博彩平台时使用: 租户枚举→JS chunk挖API→S3金矿→未授权API。"
version: 1.1.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, gambling, whitelabel, s3, vercel, laravel]
    category: daaixianzun
---

> **商心慈**
> 心慈不是心手软，账清才能走得远。
> 千门白标同一宗，认族先问商家钱。

# 白标博彩平台渗透（多家族通用）

## 触发条件
- 目标为多租户白标博彩/赌场平台，特征之一:
  - 土耳其 eBetLab 系: `site-configs/{id}.json`、`play.bonuseblb.com`、主域 CF Managed Challenge、镜像 `{brand}{NNN}.com`
  - 泰国 LSM99/mclsm 系: Vercel 前端 `{brand}.l{3-7}t.lsmview.com`、`api.mclsm.com`、**S3 桶 `mclsm.s3.ap-southeast-1.amazonaws.com` 完全公开**
- 前端 Next.js + Laravel `/api/*` 后端

## 核心认知（两家族共通）
1. **平台=多租户**，一个后端 50+ 白标客户；前端同构建（chunk hash 相同）→ 同 API 端点 → **一个租户验证的漏洞全平台通用**。
2. **前端是壳**：Vercel/Next.js 站点的真实资产在 JS chunk 里 —— `grep -o 'https://[a-z0-9.-]*'` 找 API 域，`grep -o '"/api/[a-z-]*"'` 找端点表。静态 CDN（`l{3-7}.cdnrc.com`）常 CF 放行 `/_next/static/`，可直接 curl。
3. **对象存储是金矿**：公开可列的 S3 桶 = 财务导出/银行凭条/APK 全家桶，变现核心。
4. 租户隔离靠 Host；`website-settings?sub_domain=` 类端点未授权 = 全租户 merchant/agent 代码枚举。

## 家族一: eBetLab（土耳其）— 要点
- 主域 CF 铁墙 → 先打镜像域名；`/favicon.ico` 常漏放行返回 SPA HTML → 解析 RSC payload 拿 `w_id/site_id/secret`。
- 未授权 API: `/api/debits/win`（中奖流水）、`/api/stats`（用户枚举）、`/api/games2/sportsbook`（游客 token）。
- 注册卡点: `sms_required: true`，找 `sms_required:false` 租户；别死磕注册，先打未授权面。
- 同技能 default profile 有 eBetLab 细节（本 bot3 副本为全量内联版）。

## 家族二: LSM99/mclsm（泰国）— 完整攻击链
详见 `references/lsm99-mclsm-family.md`（⚠️本包未含此案例文件，跳过）（含租户代码表/端点表/数据结构）。快速链:
1. FOFA `domain="lsmview.com"` → 全租户子域；`domain="mclsm.com"` → 后端服务清单（api/accounting/audit/partner/report/promotion/rebate/payment/affiliate/blacklist.service.mclsm.com，全在 34.87.172.253）。
2. JS chunks → `api.mclsm.com`（Laravel PHP 8.1.34）。
3. **S3 桶公开读写**: `?list-type=2` 枚举 40,000 对象 → `exports/financial_deposits/{merchantId}/*.json`（存款流水，28K 条/13.2M THB）+ `account/slip/`（凭条，文件名带玩家实名+银行账号）+ `file_app_apk/`。写验证: PUT 探针→GET→DELETE。**桶内已有 FORCEINJECT 伪造流水 = 对账污染链被前攻击者验证**。
4. 未授权: `website-settings?sub_domain=`（租户枚举）、`slide-images`、`banks`、`system-settings`、`checklock`。
5. 用户枚举: `auth/login` + `forgot-password`（参数 `subdomain`）→ "This username is not found on the website."
6. APK（Flutter）: `strings libapp.so | grep https` → `rcson.com/configs/lsm99ai.json` → 钱包域 `gamev2.lsm99ai.net` + whitelist。

## 硬墙（已试，别重复）
- **Filament 后台**（accounting/backoffice, v3.2.110）: 传统 POST → 405（只走 Livewire，必须浏览器填表单）；错误 `ข้อมูลนี้ไม่ตรงกับบันทึกในระบบ` = 凭据不匹配（无枚举）；无注册/重置入口；弱口令多组不中 → 别 curl 爆破，直接用浏览器，几组不中就换面。
- **Horizon**: 401 "Invalid credentials."，token 认证，basic auth 字典无效。
- **注册 marketing 墙**: check-register 反查 phone 是否已存在（新号 → "Marketing not found"），OTP 6 位 SMS 服务端真校验 + 429 → 注册路别死磕。
- **微服务 API**（*.service.mclsm.com /api/*）: 外部全 404，内部调用。

## 交付
- 主成果: 财务流水 TSV（gz 打包）+ Top 用户 TSV + 租户枚举 TSV + S3 目录清单 + MD 报告，MEDIA 逐个发。
- 金额字段带逗号（`1,950.00`），解析前 `replace(",","")`。
- 报告含: 资产地图、漏洞分级、数据统计、未突破面记录。
