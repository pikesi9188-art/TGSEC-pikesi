#!/usr/bin/env bash
# 图形验证码 OCR 依赖（ddddocr）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-python3}"
echo "[*] pip install -r tools/captcha-ocr/requirements.txt"
"$PY" -m pip install -r "$ROOT/tools/captcha-ocr/requirements.txt"
"$PY" - <<'PY'
import ddddocr
print("[ok] ddddocr", getattr(ddddocr, "__version__", "?"))
PY
