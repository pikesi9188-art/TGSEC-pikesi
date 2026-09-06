---
name: 酒虫·易付
description: "彩虹易支付/启易付四方支付后台渗透。触发: 支付管理中心、api.php?act=、admin_login.lock"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, epay, payment, daaixianzun]
    category: daaixianzun
---

> **酒虫**
> 青竹酒香诱酒虫，本命一开空窍通。
> 小虫不大能吞海，后来炼天从此中。

# 彩虹易支付 / 启易付 (四方支付) 后台渗透

## 触发条件
- 后台标题「支付管理中心」/「登录 - 支付管理中心」
- 前端 Vue3 + Element Plus (index-*.js 分包), 后端 ThinkPHP 风格 API
- 特征响应: `{"code":-4,"msg":"No Route"}` / `{"code":-5,"msg":"No Act!"}`
- 存在 `api.php`、`submit.php`、`runtime/admin_login.lock`
- 产品家族: 彩虹易支付 (epay)、启易付 (qyypay.cn 官方/OEM)、各类四方代付系统

## 指纹确认链
1. GET `/admin/` 看 HTML → 记录主入口 `index-*.js`
2. 下载**全部** JS 分包 (`index-[A-Za-z0-9_-]+.js`, 从主 index.js 里 grep `import("./...")` 拿清单), 然后 `grep -hoE 'url:"[^"]+"'` 全量 API 清单。主入口只有少量路由, API 全在分包里
3. JS 里写死的第三方域名 (`m.qyypay.cn` 等) → 产品源头, 搜官方站拿文档/版本
4. FOFA: `title="支付管理中心"` 找同源实例 (注意: 同源实例可能是老版本, API 路径不同, 只用于对比)

## 关键技巧
- **API 请求三件套必带**: UA + `Referer: https://<host>/admin/` + `X-Requested-With: XMLHttpRequest`, 否则要么返回 SPA HTML (nginx try_files 回退), 要么 nginx Forbidden
- **登录接口**: `POST /admin/auth/login` JSON `{username, password, enc}`
  - `enc=0` = 明文密码 (爆破直接用这个)
  - `enc=1` = RSA 加密 (先 `GET /admin/auth/getPublicKey` 取公钥, 前端 JSEncrypt 加密)
- **未授权接口**: `auth/getPublicKey`、`auth/checkLogin` (常可匿名访问)
- **商户端**: `/user/` 是独立 Vue3 SPA (`auth/reg` 注册 / `auth/sendcode` / `common/captcha`); nginx 可能 403 掉 API, 仅放行静态
- **支付 API**: `api.php?act=order|query|refund` — `act=refund` 报「未开启商户后台自助退款」= 功能存在
- **8080 端口**: 常暴露同系统 HTTP 版 (无 TLS), 与主站共享登录锁
- 路径注入: 直接 `/admin/<controller>/<action>`, `index.php` 前缀会被 nginx 重写回 SPA, 别走那条

## 锁定机制 (admin_login.lock) — 爆破必读
- 失败提示: `"用户名或密码错误，你还可以尝试N次"` (N = 剩余次数)
- 5 次失败 → **全局锁** (所有用户名都禁, 基于真实 IP):
  `"多次登录失败，暂时禁止登录。可删除 runtime/admin_login.lock 文件解除限制"`
- `X-Forwarded-For` / `X-Real-IP` **不绕过** (按真实 IP)
- 锁定期约 10-30 分钟, 窗口制, 到期自动解除
- 实测: 计数按 IP 窗口波动, 非严格递减; 慢速爆破 (1.2s+ 间隔) 可大幅降低触发概率

## 常见坑
- 商户 ID `pid` 从 1 开始枚举不存在 → 用随机大 ID, 不能靠 pid 爆破拿商户
- 登录/查询参数化良好 (pid、username 均无 SQLi 迹象), 别浪费次数在注入上
- ThinkPHP 老 RCE (`s=/index/think\app/invokefunction`) 被 nginx 重写拦截, 无效
- 敏感文件 (.git/.env/runtime/config.php) 全部 403 或 SPA 回退
- `runtime/` 目录 nginx 403 保护, 直接访问锁文件无效

## 范围铁律 (用户明令)
- **.cn 域名 + 腾讯 EdgeOne CDN + 同域资产全中国 IP → 判定中国主体 → 立即停手换目标**
- EdgeOne 识别: 响应头 `eo-log-uuid` / `eo-cache-status`, DNS `*.eo.dnse3.com`, 非 443 端口返回 `Server: Lego Server`
- 动手前先查 IP 归属 (ip-api.com), 同域资产一并查; 有中国 IP 资产 = 别碰整个目标

## references
- `references/niuniuapi-probe.md`（⚠️本包未含此案例文件，跳过） — niuniuapi.qihongmy.cn 完整探测记录 (API 面/锁定行为/同源实例)
