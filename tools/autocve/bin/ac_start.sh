#!/usr/bin/env bash
# 启动 AutoCVE 全栈（需 Docker）
# 用法:
#   bash tools/autocve/bin/ac_start.sh           # 源码 compose（需已 install_upstream）
#   bash tools/autocve/bin/ac_start.sh --prod    # 官方预构建 compose（可不克隆）
#   bash tools/autocve/bin/ac_start.sh --cn      # 国内镜像
#   bash tools/autocve/bin/ac_start.sh --stop
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UP="$ROOT/upstream"
ENGINE="$(cd "$ROOT/../.." && pwd)"
PIN="v1.0.5"
if [[ -f "$ENGINE/tools/docker/bin/env.sh" ]]; then
  # shellcheck source=/dev/null
  source "$ENGINE/tools/docker/bin/env.sh"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] 未检测到 docker。AutoCVE UI/Agent 需要 Docker Desktop。"
  echo "    安装: bash $ENGINE/tools/docker/bin/install_docker_desktop.sh"
  echo "    启动: bash $ENGINE/tools/docker/bin/docker_up.sh"
  echo "    可先落知识: python3 $ROOT/bin/ac_pipeline.py knowledge --case <案卷>"
  exit 2
fi

MODE="${1:-}"
case "$MODE" in
  --stop)
    if [[ -d "$UP" ]]; then
      (cd "$UP" && docker compose down || true)
      (cd "$UP" && docker compose -f docker-compose.prod.yml down || true)
    fi
    echo "[+] 已请求停止"
    exit 0
    ;;
  --prod)
    curl -fsSL "https://raw.githubusercontent.com/larlarua/AutoCVE/${PIN}/docker-compose.prod.yml" \
      | docker compose -f - up -d
    ;;
  --cn)
    if [[ ! -d "$UP" ]]; then
      bash "$ROOT/bin/install_upstream.sh" --tag "$PIN"
    fi
    cd "$UP"
    docker compose -f docker-compose.prod.cn.yml up -d
    ;;
  *)
    if [[ ! -d "$UP" ]]; then
      bash "$ROOT/bin/install_upstream.sh" --tag "$PIN"
    fi
    cd "$UP"
    if [[ -f backend/env.example && ! -f backend/.env ]]; then
      cp backend/env.example backend/.env
      echo "[!] 已生成 upstream/backend/.env，请配置 LLM（可 Ollama）"
    fi
    docker compose up -d --build
    ;;
esac

echo
echo "[+] AutoCVE"
echo "    UI:      http://localhost:3000"
echo "    API:     http://localhost:8000"
echo "    Swagger: http://localhost:8000/docs"
echo "    案卷同步: python3 $ENGINE/tools/autocve/bin/ac_pipeline.py sync --case <案卷> --user demo@example.com --password '***'"
