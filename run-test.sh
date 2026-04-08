#!/bin/zsh
set -euo pipefail
cd /Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server
set -a
source .env
set +a
node server.js >/tmp/mcp-server-test.log 2>&1 &
PID=$!
trap 'kill "$PID" >/dev/null 2>&1 || true' EXIT
sleep 3
echo HEALTH
curl -sS http://127.0.0.1:8787/healthz
echo
echo METADATA
curl -sS http://127.0.0.1:8787/.well-known/oauth-authorization-server
echo
