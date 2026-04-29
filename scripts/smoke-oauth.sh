#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${MCP_BASE_URL:-http://127.0.0.1:8787}"
ENV_FILE="${ENV_FILE:-.env}"
STATE_FILE="${STATE_FILE:-.oauth-state.json}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*"; }

json_get() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); cur=data
for part in sys.argv[1].split("."):
    cur=cur[part]
print(cur)' "$1"
}

form_encode() {
  python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
}

status_code() {
  local token="$1"
  curl -s -o "$WORK_DIR/mcp-body.json" -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    -H "Accept: application/json, text/event-stream" \
    -H "Content-Type: application/json" \
    --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke-oauth","version":"0.1"}}}' \
    "$BASE_URL/mcp"
}

if [[ ! -f "$STATE_FILE" ]]; then
  fail "state file not found: $STATE_FILE"
fi

API_KEY="${MCP_API_KEY:-}"
if [[ -z "$API_KEY" && -f "$ENV_FILE" ]]; then
  API_KEY="$(python3 - <<'PY'
from pathlib import Path
for line in Path('.env').read_text().splitlines():
    line=line.strip()
    if line.startswith('MCP_API_KEY='):
        print(line.split('=',1)[1].strip().strip('"').strip("'"))
        break
PY
)"
fi
[[ -n "$API_KEY" ]] || fail "MCP_API_KEY not set and not found in $ENV_FILE"

# Read current state to prove the script can inspect persisted OAuth data without using production tokens.
python3 - <<'PY' "$STATE_FILE" > "$WORK_DIR/state-summary.txt"
import json,sys
state=json.load(open(sys.argv[1]))
print(len(state.get('accessTokens', [])), len(state.get('refreshTokens', [])), len(state.get('registeredClients', [])))
PY
pass "read OAuth state summary: $(cat "$WORK_DIR/state-summary.txt")"

VERIFIER="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
CHALLENGE="$(python3 - <<'PY' "$VERIFIER"
import base64,hashlib,sys
print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).decode().rstrip('='))
PY
)"
REDIRECT_URI="http://127.0.0.1/callback"

REGISTER_BODY='{"redirect_uris":["'"$REDIRECT_URI"'"],"token_endpoint_auth_method":"none","client_name":"OAuth Smoke Test"}'
curl -s -X POST "$BASE_URL/register" -H "Content-Type: application/json" --data-binary "$REGISTER_BODY" > "$WORK_DIR/register.json"
CLIENT_ID="$(json_get client_id < "$WORK_DIR/register.json")"
[[ -n "$CLIENT_ID" ]] || fail "register did not return client_id"
pass "authorize/register created disposable smoke client"

AUTH_BODY="client_id=$(form_encode "$CLIENT_ID")&redirect_uri=$(form_encode "$REDIRECT_URI")&state=smoke&code_challenge=$(form_encode "$CHALLENGE")&code_challenge_method=S256&api_key=$(form_encode "$API_KEY")"
curl -s -D "$WORK_DIR/authorize.headers" -o /dev/null -X POST "$BASE_URL/authorize" -H "Content-Type: application/x-www-form-urlencoded" --data "$AUTH_BODY"
LOCATION="$(grep -i '^location:' "$WORK_DIR/authorize.headers" | tail -1 | sed -E 's/^[Ll]ocation:[[:space:]]*//; s/\r$//')"
CODE="$(python3 - <<'PY' "$LOCATION"
from urllib.parse import urlparse, parse_qs
import sys
print(parse_qs(urlparse(sys.argv[1]).query).get('code', [''])[0])
PY
)"
[[ -n "$CODE" ]] || fail "authorize did not return code"

TOKEN_BODY="grant_type=authorization_code&client_id=$(form_encode "$CLIENT_ID")&code=$(form_encode "$CODE")&redirect_uri=$(form_encode "$REDIRECT_URI")&code_verifier=$(form_encode "$VERIFIER")"
curl -s -X POST "$BASE_URL/token" -H "Content-Type: application/x-www-form-urlencoded" --data "$TOKEN_BODY" > "$WORK_DIR/token.json"
ACCESS_TOKEN="$(json_get access_token < "$WORK_DIR/token.json")"
REFRESH_TOKEN="$(json_get refresh_token < "$WORK_DIR/token.json")"
[[ -n "$ACCESS_TOKEN" && -n "$REFRESH_TOKEN" ]] || fail "authorization_code token exchange failed"

CODE1="$(status_code "$ACCESS_TOKEN")"
[[ "$CODE1" == "200" ]] || fail "step 1 /mcp with current access token expected 200, got $CODE1"
pass "step 1 current access token works"

skip "step 2 expiry simulation — not needed; refresh endpoint is exercised directly with disposable smoke tokens"

REFRESH_BODY="grant_type=refresh_token&client_id=$(form_encode "$CLIENT_ID")&refresh_token=$(form_encode "$REFRESH_TOKEN")"
curl -s -w '\n%{http_code}' -X POST "$BASE_URL/token" -H "Content-Type: application/x-www-form-urlencoded" --data "$REFRESH_BODY" > "$WORK_DIR/refresh.out"
REFRESH_STATUS="$(tail -n1 "$WORK_DIR/refresh.out")"
sed '$d' "$WORK_DIR/refresh.out" > "$WORK_DIR/refresh.json"
[[ "$REFRESH_STATUS" == "200" ]] || fail "step 3 refresh expected 200, got $REFRESH_STATUS: $(cat "$WORK_DIR/refresh.json")"
NEW_ACCESS_TOKEN="$(json_get access_token < "$WORK_DIR/refresh.json")"
NEW_REFRESH_TOKEN="$(json_get refresh_token < "$WORK_DIR/refresh.json")"
[[ "$NEW_ACCESS_TOKEN" != "$ACCESS_TOKEN" && "$NEW_REFRESH_TOKEN" != "$REFRESH_TOKEN" ]] || fail "step 3 tokens were not rotated"
pass "step 3 refresh returned rotated access and refresh tokens"

curl -s -w '\n%{http_code}' -X POST "$BASE_URL/token" -H "Content-Type: application/x-www-form-urlencoded" --data "$REFRESH_BODY" > "$WORK_DIR/old-refresh.out"
OLD_REFRESH_STATUS="$(tail -n1 "$WORK_DIR/old-refresh.out")"
sed '$d' "$WORK_DIR/old-refresh.out" > "$WORK_DIR/old-refresh.json"
OLD_REFRESH_ERROR="$(python3 - <<'PY' "$WORK_DIR/old-refresh.json"
import json,sys
try: print(json.load(open(sys.argv[1])).get('error',''))
except Exception: print('')
PY
)"
[[ "$OLD_REFRESH_STATUS" == "400" && "$OLD_REFRESH_ERROR" == "invalid_grant" ]] || fail "step 4 old refresh expected 400 invalid_grant, got $OLD_REFRESH_STATUS $(cat "$WORK_DIR/old-refresh.json")"
pass "step 4 old refresh token is invalid_grant"

CODE5="$(status_code "$NEW_ACCESS_TOKEN")"
[[ "$CODE5" == "200" ]] || fail "step 5 /mcp with new access token expected 200, got $CODE5"
pass "step 5 new access token works"

OLD_ACCESS_STATUS="$(status_code "$ACCESS_TOKEN")"
[[ "$OLD_ACCESS_STATUS" == "401" ]] || fail "old access token expected 401 after refresh, got $OLD_ACCESS_STATUS"
pass "old access token invalidated after refresh"

echo "PASS: OAuth smoke test complete"
