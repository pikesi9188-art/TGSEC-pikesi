#!/usr/bin/env bash
# pwntools（避开源码编 unicorn；Python 3.14 + 无 cmake 时用轮子）
set -euo pipefail
PY="${PYTHON:-python3}"
"$PY" -m pip install --only-binary=:all: 'pwntools==4.15.0' || \
  "$PY" -m pip install --only-binary=unicorn 'pwntools==4.15.0'
"$PY" - <<'PY'
import pwn
print("[ok] pwntools", getattr(pwn, "__version__", "?"))
PY
