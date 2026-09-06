---
name: 白兔·人机
description: "Automate reCAPTCHA v2/v3 via YOLO tiles or audio ASR."
version: 2.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [recaptcha, captcha, yolo, audio, vosk, browser-automation, asr, auth-wall]
    category: daaixianzun
---
# Google reCAPTCHA v2/v3 自动化绕过（bot2 profile 版）

## 触发条件
- 页面出现 `grecaptcha.execute('sitekey',{action:'...'})`、`recaptcha/api.js?render=`（v3）
- 自定义表单 `data-sitekey` + `data-callback=onCaptchaSolved` + 隐藏 `RecaptchaToken`/`RecaptchaV2Response`（v2 fallback）
- "Please confirm you are human." / "I'm not a robot" / 图块挑战
- **ddocr 只识别字符验证码，对 reCAPTCHA v3/v2 无效**

## 架构（常见组合）
```
grecaptcha.execute(sitekey,{action}) -> 填 RecaptchaToken -> 服务端 siteverify(secret, token)
   → 分数 < 阈值 → 服务端回渲染 v2（另一个 data-sitekey, RecaptchaFallback=true）
   → 用户点 checkbox → onCaptchaSolved(token) -> 隐藏 RecaptchaV2Response -> 提交整表单
```
- `RecaptchaFallback=true` 出现 = v3 分数不够、服务端切 v2 → 图像/音频挑战在 **bframe** iframe，anchor 只放 checkbox。
- 站点可能对注册/登录页做独立 IP 限流（见「限流」节）。

## 令牌 oracle（webhook/extension 类自建平台）
token 鉴权平台（crypto bot / webhook / TG bot）：token 即全站唯一凭据（读密钥/余额/下单），多面 oracle 可无感确认 token 有效性：
- webhook: `POST .../api/ExecuteTradeSignalClassic` body `{token}` → 无效 `400 "User not found. Token: <tok>"`（回显）
- Extension API: `GET /api/Extension/GetApiKeys/{token}` → 无效 `200 []`，有效返回密钥数组（token 放 URL 路径=绕过 cookie 认证）
- TG bot: 发 access-key → `"Access-Token invalid."`
- GUID v4 随机不可爆破（顺序/低熵候选实测全空）；**拿到任一有效 token = 全账户沦陷** → 作为「单点凭据认证模型」中危发现交付。
- 挖掘 token 型端点：从官方 Chrome 扩展挖（Web Store 搜产品名 → CRX → `clients2.google.com/service/update2/crx?x=id%3D{ID}%26uc` → unzip → grep `/api/`）。扩展后端常是 token-in-URL 免 cookie 的宝藏面。

## 主线

### 1. v3 优先 / v2 fallback
数据中心 IP + headless 几乎必触发 v2 → 别指望预热规避，直接按 v2 设计。`ctx.add_init_script` 隐藏 webdriver、常规 UA/viewport、先逛首页再随机表单（小幅提分）。headful+Xvfb（`xvfb-run -a python3`）也救不了数据中心 IP——v3 分数仍低。

### 2. 点 v2 checkbox（anchor iframe）
`for f in page.frames: if 'anchor' in f.url: await f.locator('.recaptcha-checkbox-border').first.click()`
点击后绿勾=过；否则 bframe 弹挑战。

### 3. 图像挑战（首选 YOLO ONNX，颜色启发式兜底）
- bframe tile：`td.rc-imageselect-tile` / `.rc-image-tile-target`；描述 `td.rc-imageselect-desc`
- **YOLO 物体检测**（onnxruntime CPU + yolo11n.onnx 10MB，COCO 80 类）：
  - 模型：`https://github.com/ultralytics/assets/releases/download/v8.4.0/yolo11n.onnx`（v8.3.0/v8.2.0 无 onnx 资产，v8.4.0 才有）
  - 每 tile `t.screenshot()` → letterbox 640 → 推理输出 (1,84,8400) → 目标类 conf≥0.3 即点
  - 任务词→COCO 类：cars→car(2), traffic light(s)→traffic light(9), bus(es)→bus(5), hydrant(s)→fire hydrant(10), motorcycles→motorcycle(3), bicycles→bicycle(1), trucks→truck(7), stop sign→stop sign(11)
  - 真实挑战已验证：cars/bus 检出可靠（conf 0.3-0.82）
  - 陷阱：reCAPTCHA 多轮全对才过，错 1 轮换图重问；每轮 3-4 次机会后转音频
- 颜色启发式兜底：HSV 掩码 blobs（cv2.findContours, min_area≈20, MORPH_CLOSE 5x5）
  - red hue(0-12,170-180) sat≥120; green(40-80); yellow(15-38) traffic lights=红 AND (绿或黄)；hydrant=红≥2；crosswalk=白带 5-55%
- 点`Verify` → 等 4s → 循环直到 `RecaptchaV2Response` 有值

### 4. 音频挑战（最通用）— Google Web Speech ASR 优先 + vosk 兜底
| 环节 | 动作 | 陷阱 |
|---|---|---|
| 切音频 | bframe `#recaptcha-audio-button`（aria-label "Get an audio challenge"）| 切换后 **bframe 会导航**——旧 frame 引用失效，必须重新 `page.frames` 获取（曾因未重取而空转）|
| 拿 MP3 | bframe `a.rc-audiochallenge-tdownload-link` href（google recaptcha payload/audio.mp3?p=...）| URL 会话绑定有限时；找不到就**轮询 20s**（`count()` 先行，别让 get_attribute 空等 30s 默认超时挂死）|
| 下载 | `ctx.request.get(href)` 拿 bytes | ❌ `page.evaluate(fetch)` 跨域 CORS 失败；用带浏览器 cookie 的 `ctx.request` |
| 转写 | **优先 `speech_recognition` Google 引擎**（`pip install SpeechRecognition`，精度远高于 vosk，实测近完美转写句子）；兜底 vosk KaldiRecognizer(16000) + 数字语法 | reCAPTCHA 音频=数字+音乐底噪；vosk small 会出乱码（"notable on your"）|
| 填 | `input#audio-response`，数字词映射 {one:1...}；无数字回退纯字母 | norm 后提交 |
| 验证 | `#recaptcha-verify-button` 循环等 token | 每轮等 5s，可 2-3 轮 |
- vosk `Model('vosk-model-small-en-us-0.15')`（alphacephei 40MB）+ ffmpeg 16k mono
- 成功后在隐藏字段有 token，点表单提交钮即可；若按钮超时用 fetch 直提表单（FormData 含 RecaptchaV2Response）

### 5. 限流（注册页 429）——重点
- 读 `Retry-After: 900` = 15min 锁窗；按真实连接 IP 键控。**XFF/X-Real-IP 客户端伪造不是真绕过**（曾误判——一串 200 只是窗口残留额度，随后全部 429）。
- 别高频轮询表单页（每个 429 重置 900s）→ **静默满 15 min 再一次性成功**。
- mail.tm 取确认邮件：POST/accounts → POST/token → GET/messages → 取 confirm link → goto（Identity 确认后常自动登录）。

## 硬墙判断（重要）
- 图块物体（car/starbucks 等）无视觉 = 自动识别墙 → 转音频。音频 ASR 仍有精度墙。
- **Google 封 IP**：连续失败多次后 bframe 内出现 "Try again later / your computer or network may be sending automated queries" → Google 不再提供可解挑战，**该出口 IP 的自动化注册彻底死亡**（数小时-天级解封）。穷尽 + 无住宅代理时立即转人工：请求用户注册测试号给 cookie/token，别无限重试浪费限流窗口。
- 交付视角：拿不到账号时，把「token=全站权限单点凭据 + 各面 oracle + 免 cookie 的 token-in-URL 扩展 API」作为可利用路径交付（证明任意 token 泄露即全盘沦陷），并诚实标注未达目标。

## 支撑文件
- `references/tv-hub-2026-08.md`（⚠️本包未含此案例文件，跳过） — TV-Hub 实战案例（token oracle 三面、Extension API 端点、YOLO/ASR 实测参数）
