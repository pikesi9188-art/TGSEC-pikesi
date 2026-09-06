---
name: 白兔·滑块
description: "Automate GeeTest 极验 captcha via real input events."
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [geetest, captcha, slider, browser-automation, waf]
    category: daaixianzun
---
# GeeTest v3 (极验) 滑块验证码自动化

## 触发条件
- 目标页面出现 `initGeetest({...})`、`gt`/`challenge` 参数、`geetest_canvas_bg` / `geetest_canvas_slice` / `geetest_canvas_fullbg` canvas、`Slide to complete the puzzle`、"Powered by Geetest"
- 登录/注册被极验滑动拼图拦截，ddddocr 无效（它是字符验证码 OCR，不适用于滑块）

## 架构（v3 标准流程）
```
前端:  initGeetest({gt, challenge, product:'bind', new_captcha})
       → 用户滑动 → captchaObj.getValidate() → {geetest_challenge, geetest_validate, geetest_seccode}
后端:  POST /validate_captcha/ {gt, challenge, geetest_validate, geetest_seccode} → captcha_token
       注册/登录 携带 captcha_token 提交
```
- `get_captcha/` 端点通常**服务端直连可用**（无 CF 挑战），返回 `{success:1, gt, challenge}`
- 极验 v3 服务端 get.php：init 返回 `c`/`s`；**不要二次调用 get.php**（报 `old challenge` / `error_02`）
- 完整服务端求解需逆向 `w` 参数加密（fullpage.js/slide.js 混淆极深，工程量巨大，成功率低）→ 优先浏览器路线

## 浏览器自动化路线（实测有效）

### 0. 先过 CF 页面挑战
- **headless Playwright 会被 CF/极验识别**（fill 超时、页面不渲染）→ 用 **Xvfb + headed**：
  `xvfb-run -a python script.py` + `p.chromium.launch(headless=False, args=['--no-sandbox','--disable-dev-shm-usage','--disable-blink-features=AutomationControlled'])`
- `ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")`
- SPA 渲染慢：goto 后 **sleep 5-6s** 再操作；输入框可能无 placeholder/name → `page.locator('input').nth(i)` 按索引填
- 页面内 fetch 测极验连通：`api.geetest.com/gettype.php` / `static.geetest.com` / `api.geevisit.com` 应 200（proxy 下也通）

### 1. 关键：必须用真实输入事件（isTrusted=true）
| 方式 | 结果 |
|---|---|
| JS 合成 `MouseEvent`/`PointerEvent` dispatch | ❌ isTrusted=false → 极验忽略，滑块保持 `geetest_ready` |
| CDP `Input.dispatchMouseEvent` | ✅ 原生输入 |
| Playwright `page.mouse.move/down/up` | ✅ 原生输入 |
- 滑动后有 `geetest_fail`（而非 ready）= 事件被接收、仅位置判错 → **这是正确信号，调整距离重试**
- 人类化轨迹：mousedown 停顿 0.2-0.4s → 缓启动→加速→减速 → 末端微回弹 → mouseup；步进 2-12px 随机

### 2. 缺口定位（canvas 像素分析，页面内 evaluate）
- `geetest_canvas_bg` 列梯度找峰值：`Σ|px(x)-px(x+1)|` per column，排序取 top3（间隔>18-20px）
- `fullbg`(完整背景) vs `bg`(挖缺) 逐列差：缺口=连续高差异段；仅 bg 可用时列梯度
- slice canvas alpha 掩码模板匹配在 bg 中滑动找最小 RGB 差（缺口宽 40-50px）
- 滑动距离 = 缺口 pageX − 滑块按钮中心 pageX（按钮中心 = rect.x + width/2）
- 距离不准时循环：fail → 点 `.geetest_refresh` 拿新图 → 重新算 → 重滑

### 3. 代理（需换 IP 时）
- 历史任务脚本常有可用 SOCKS5 池，测 `ifconfig.me/ip` 确认出口
- **Chromium 不支持 SOCKS5 认证**（`Browser does not support socks5 proxy authentication`）→ 本地起 HTTP CONNECT→SOCKS5 转发器（见 scripts/http2socks.py），Playwright 用 `proxy={"server":"http://127.0.0.1:19081"}`
- 无认证连接通常被拒（认证必填）

### 4. 直接接管本机浏览器（备选）
- 本机浏览器 的 CDP 端口在 `/tmp/agent-browser-chrome-*/DevToolsActivePort`
- 裸 websocket-client 连 CDP 会 403：需 `Origin: http://127.0.0.1:<port>` 头（`--remote-allow-origins` 未开时）
- Playwright `connect_over_cdp` 可连，但**可能重置浏览器会话**（页面变空）→ 优先独立 launch

## 极验错误语义（排障关键）
| 现象 | 含义 |
|---|---|
| 面板 "Timed out" + Retry | challenge 失效/加载超时（滑动前已过期）→ 点 refresh 重取 |
| "Network failure 113" | 极验 SDK 内部请求失败（仍可能与 challenge 生命周期相关） |
| `old challenge` (error_02) | 二次 get.php 或 challenge 复用 |
| slider `geetest_ready` 滑动后不变 | 事件未生效（合成事件） |
| slider `geetest_fail` | 事件生效、位置错错 → 调距离重试 |

## 硬墙判断
极验 v3 + CF 组合下，若 challenge 被服务端一次性失效（每次 get_captcha 返回即作废），纯自动化在无住宅代理/真人设备下**可能无法突破**（Cornix 实测）。穷尽后如实交付信息泄露面成果，不要无限循环滑块。

## 支撑文件
- `scripts/http2socks.py` — HTTP CONNECT→认证 SOCKS5 转发（Playwright 代理用）