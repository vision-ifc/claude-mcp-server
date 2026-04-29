# claude-mcp-server

## OAuth Smoke Test

Run the OAuth smoke test against a local MCP server:

```bash
bash scripts/smoke-oauth.sh
```

Optional environment variables:

- `MCP_BASE_URL` — defaults to `http://127.0.0.1:8787`
- `MCP_API_KEY` — defaults to the value in `.env`
- `STATE_FILE` — defaults to `.oauth-state.json`

The script creates a disposable dynamic OAuth client, performs authorize → token → MCP access → refresh, verifies refresh-token rotation, verifies the old refresh token returns `invalid_grant`, verifies the new access token works, and verifies the old access token no longer works. It never logs full tokens.

Step 2 expiry simulation is intentionally skipped because forcing expiry in the live state file would mutate production OAuth state; the refresh flow is exercised directly with disposable smoke tokens instead.
