#!/usr/bin/env bash
# start_mcp.sh — 启动 Scrapling MCP server（JSON-RPC stdio）
# 优先使用本地安装的 scrapling-mcp，回退到 Docker。
# Cursor 通过 .cursor/mcp.json 自动调用。
set -euo pipefail

# 优先本地 binary
for CANDIDATE in \
    "/Library/Frameworks/Python.framework/Versions/3.14/bin/scrapling-mcp" \
    "$(command -v scrapling-mcp 2>/dev/null || true)" \
    "$HOME/.local/bin/scrapling-mcp" \
    "/usr/local/bin/scrapling-mcp" \
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/scrapling-mcp" \
    "/Library/Frameworks/Python.framework/Versions/3.11/bin/scrapling-mcp" \
    "/Library/Frameworks/Python.framework/Versions/3.10/bin/scrapling-mcp"; do
  if [[ -n "$CANDIDATE" && -x "$CANDIDATE" ]]; then
    exec "$CANDIDATE"
  fi
done

# 回退 Docker（公开镜像，无需认证）
if command -v docker &>/dev/null; then
  exec docker run -i --rm pyd4vinci/scrapling mcp
fi

echo "[Scrapling-MCP] 未找到 scrapling-mcp。请先运行:" >&2
echo "  pip install 'scrapling[all]' && scrapling install" >&2
echo "  或: docker pull pyd4vinci/scrapling" >&2
exit 1
