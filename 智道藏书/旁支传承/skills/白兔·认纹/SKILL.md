---
name: 白兔·认纹
description: "登录遇图形验证码时使用: ddddocr 全自动识别验证码; 🔴禁止登录爆破(仅配合逻辑洞/默认凭据单次验证)。"
version: 1.0.0
license: MIT
platforms: [linux, macos, windows]
metadata:
    tags: [pentest, captcha, ocr, ddddocr, brute-force, login]
    category: ctf-pentest
---
> ⚠️ 🔴 红线(用户硬性要求): 禁止密码爆破——字典/批量尝试/凭据喷洒/签名密钥MD5穷举全部禁止。登录类仅走逻辑洞: 默认凭据单次验证、密码重置、JWT篡改、越权、验证码OCR识别。
# 登录图形验证码自动化破解 (ddddocr)

Use when a login form (or any protected flow) has a **graphical captcha** that blocks automation:
- Java `com.wf.captcha` SpecCaptcha (4-char alphanumeric, 105x38) — the geshanzsq/RuoYi-family default
- Any simple letter/digit captcha, base64-in-JSON or image endpoint
- User manually reading captchas is slow; batch images expire before they can be read

## 1. ddddocr — 安装与识别
```bash
uv pip install --python python3 ddddocr
```
```python
import ddddocr
ocr = ddddocr.DdddOcr(show_ad=False)
code = ocr.classification(img_bytes)   # img_bytes = raw png/jpg bytes
```
- **实测识别率 100%** on SpecCaptcha 4-char codes (wp3f/aytm/kusg/pp3h/jq4p all correct) — no training needed
- Validate against 2-3 user-read samples before trusting
- Thread-safety: ddddocr instance is NOT thread-safe → guard with a lock or one instance per thread

## 2. Captcha behavior fingerprint (before designing the attack)
| Observation | Conclusion | Strategy |
|---|---|---|
| Same uuid+code twice → "验证码已失效" | **one-time** (consumed on ANY attempt, even wrong password) | 1 captcha per password |
| Same code reusable after wrong password | reusable (deleted only on success) | 1 captcha → many passwords |
| Empty code → "不能为空", wrong code → other msg | global non-empty check first | no bypass via missing code |
| Code is `Integer` in JSON | array/object/string payloads rejected by Jackson | send integer |

Common storage: Redis `captcha_codes:{uuid}` with short TTL (geshanzsq = 2 min). Batch-fetching 5 images and asking the user to read them **always expires** (user takes >TTL) — never do this. Single-image+user rounds work but are ~1 password/round.

## 3. One-time captcha → full auto brute pipeline
- 6-8 threads; each: get captcha → OCR (locked) → login attempt → 0.15-0.5s sleep
- Per-attempt parse: '不正确'/'密码错误' = captcha passed, password wrong → next word; '已失效' = race → retry same word (≤3x); code==200/token → FOUND
- Throughput ~1.5s/password at 6-8 threads; 3000 words ≈ 1-2h worst case
- If "操作频繁"/429 → drop to 2-3 threads

## 4. Dictionary & stop-loss
- First pass: CN admin weak passwords: base words (admin/root/test/geshanzsq/renren/品牌名/guanli) × patterns (123/123456/888/666/520/1314/2022-2026/!/@/@123), pure digits, birthdays 1970-2005 × common MD, keyboard walks, Admin/P@ssw0rd variants — ~1500-3500 words
- **3000+ words fail → password is strong/custom. STOP.** Pivot, don't expand dictionaries forever
- Try framework seed users too — defaults often survive even when admin's is changed (geshanzsq/123456 worked while admin/* failed)
- Open-source framework? Pull the SQL seed, crack bcrypt hashes with `bcrypt.checkpw` + same dictionary — reveals unchanged defaults

## 5. Pitfalls
- **Do NOT loop the user through captcha reading** — they will say "这么搞你搞到明年也破不开". OCR first; user only for one-shot last-resort
- Captcha TTL 60s-2min: fetch→use within TTL, don't prefetch long in advance
- If login also needs SMS/email code (not image): pair with mail.tm API (`api.mail.tm` /domains → /accounts → /token → /messages) for fully automated email-code receipt

## References
- `references/geshanzsq-blog-admin.md` — geshanzsq-blog-admin framework full fingerprint (auth flow, unauth endpoints, security config, DB defaults)
- `references/feitou-ruoyi-admin-family.md` — 飞投/RuoYi GA(TOTP)锁后台家族: 68台测绘, GA绕过穷尽清单(全失败), druid ruoyi/123456, 共享DB ftgames, 周边系统清单
