#!/usr/bin/env bash
# 拉取/更新 AutoCVE 上游（默认钉扎 v1.0.5）
# 用法: bash tools/autocve/bin/install_upstream.sh [--tag v1.0.5] [--main]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UP="$ROOT/upstream"
TAG="v1.0.5"
REF=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --main) TAG=""; REF="main"; shift ;;
    *) echo "unknown: $1"; exit 2 ;;
  esac
done
URL="https://github.com/larlarua/AutoCVE.git"
if [[ -d "$UP/.git" ]]; then
  echo "[*] updating $UP"
  git -C "$UP" fetch --depth 1 origin "${REF:-$TAG}"
  git -C "$UP" checkout -f "${REF:-FETCH_HEAD}"
else
  echo "[*] cloning $URL @ ${REF:-$TAG}"
  if [[ -n "$REF" ]]; then
    git clone --depth 1 --branch "$REF" "$URL" "$UP"
  else
    git clone --depth 1 --branch "$TAG" "$URL" "$UP"
  fi
fi
echo "[ok] upstream -> $UP"
git -C "$UP" log -1 --oneline
echo "[next] bash tools/autocve/bin/ac_start.sh"
echo "       或: python3 tools/autocve/bin/ac_pipeline.py status"
