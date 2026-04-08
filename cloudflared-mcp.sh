#!/bin/zsh
set -euo pipefail
exec /usr/local/bin/cloudflared tunnel --url http://127.0.0.1:8787 --no-autoupdate --logfile /Users/jarvis/.openclaw/logs/cloudflared-mcp.log
