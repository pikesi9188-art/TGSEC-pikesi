#!/usr/bin/env bash
# 安装 chisel / frp 到 tools/arsenal/bin（darwin arm64/amd64）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/tools/arsenal/bin"
mkdir -p "$BIN"
ARCH="$(uname -m)"
GOARCH="arm64"
[[ "$ARCH" == "x86_64" ]] && GOARCH="amd64"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

have_bin() { [[ -x "$BIN/$1" ]]; }

install_chisel() {
  if have_bin chisel; then echo "[skip] chisel"; return 0; fi
  echo "[*] 下载 jpillora/chisel ..."
  local api url
  api="https://api.github.com/repos/jpillora/chisel/releases/latest"
  url="$(curl -fsSL "$api" | /usr/bin/python3 -c "
import json,sys
j=json.load(sys.stdin)
for a in j.get('assets') or []:
  n=a['name'].lower()
  if 'darwin' in n and '${GOARCH}' in n and n.endswith('.gz') and '.tar.' not in n:
    print(a['browser_download_url']); break
")"
  if [[ -z "$url" ]]; then echo "[!] chisel 资产未找到"; return 1; fi
  # 官方资产是单文件 gzip（非 tar.gz）
  curl -fsSL -o "$TMP/chisel.gz" "$url"
  gunzip -c "$TMP/chisel.gz" > "$BIN/chisel"
  chmod +x "$BIN/chisel"
  "$BIN/chisel" --help >/dev/null 2>&1 || true
  echo "[ok] $BIN/chisel"
}

install_frp() {
  if have_bin frpc && have_bin frps; then echo "[skip] frp"; return 0; fi
  echo "[*] 下载 fatedier/frp ..."
  local api url
  api="https://api.github.com/repos/fatedier/frp/releases/latest"
  url="$(curl -fsSL "$api" | /usr/bin/python3 -c "
import json,sys
j=json.load(sys.stdin)
want='darwin_${GOARCH}'
for a in j.get('assets') or []:
  n=a['name']
  if want in n and n.endswith('.tar.gz'):
    print(a['browser_download_url']); break
")"
  if [[ -z "$url" ]]; then echo "[!] frp 资产未找到"; return 1; fi
  curl -fsSL -o "$TMP/frp.tgz" "$url"
  tar -xzf "$TMP/frp.tgz" -C "$TMP"
  local dir
  dir="$(find "$TMP" -maxdepth 1 -type d -name 'frp_*' | head -1)"
  cp "$dir/frpc" "$BIN/frpc"
  cp "$dir/frps" "$BIN/frps"
  chmod +x "$BIN/frpc" "$BIN/frps"
  echo "[ok] $BIN/frpc $BIN/frps"
}

install_chisel || true
install_frp || true
echo "[*] doctor:"
python3 "$ROOT/tools/tunnel-kit/tunnel_plan.py" doctor
echo "[hint] ligolo-ng / proxychains4 按需 brew/自装；见 templates/ligolo_notes.md"
