---
name: 白兔·认纹
description: >-
 授权目标上的图形验证码 OCR（ddddocr）与旁路分流。滑块/点选/GeeTest 走 captcha_auto.py，
 不要本 Skill。GVA 领奖验证码墙可先 OCR 再接 ginvue 探针。
---

# 图形验证码 OCR（Cursor Skill）

> 旧名 `captcha-ocr-bypass` 已重定向到本卡，勿再展开旧正文。

## 何时用

- 简单数字/字母图被挡在登录或发奖接口前
- 用户明确要自动化过 captcha（非短信接码）

## 真源（按序）

1. `炼蛊房/captcha_auto.py`
2. `传承/白兔·认纹.md`
3. 旁路优先：Redis `captcha_codes`（若依）、业务禁用验证码、人工 `--confirm`
4. 滑块/极验 → `python3 炼蛊房/captcha_auto.py solve --url … --case …`
5. CF/Turnstile → `scrapling` / `cf_session`，**不是** ddddocr
6. **CapMonster 云打码**（reCAPTCHA v2/v3、hCaptcha、Turnstile、FunCaptcha）：`python3 炼蛊房/capmonster_solver.py <type> <url> <sitekey>`
   - 需 `CAPMONSTER_API_KEY` 环境变量
   - 支持：text / recaptcha / recaptcha_v3 / hcaptcha / funcaptcha / turnstile / slide（本地 ddddocr）

## 强制步骤

1. 确认 host 在 `授权范围`。
2. 未装依赖：`python3 炼蛊房/captcha_auto.py doctor`
3. `python3 炼蛊房/captcha_auto.py ocr doctor`
4. 识别：
 - 本地图：`captcha_auto.py ocr file --path <图> --case <案卷>`
 - 授权 URL：`captcha_auto.py ocr url --url <验证码URL> --case <案卷>`
5. 证据：`案卷/<案卷>/案卷/captcha_ocr/`
6. 识别失败 → 试 `--beta`；仍失败 → 人工码或旁路，勿死磕

## 不要做

- 对未授权域拉验证码图
- 把滑块/行为验证当成 OCR 题硬解
- 默认自动化刷生产登录（高噪声先问）
