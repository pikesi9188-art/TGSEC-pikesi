# captcha-ocr — 图形验证码 OCR

授权范围内用 `ddddocr` 识别简单数字/字母验证码。  
**滑块 / 点选 / GeeTest / Turnstile 不走本工具**（见 Playbook 分流）。

```bash
bash tools/captcha-ocr/install.sh
python3 tools/captcha-ocr/ocr_solve.py doctor
python3 tools/captcha-ocr/ocr_solve.py file --path captcha.png --case <案卷>
python3 tools/captcha-ocr/ocr_solve.py url  --url https://授权站/captcha --case <案卷>
```

证据：`案卷/<案卷>/测绘/captcha_ocr/`
