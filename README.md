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

## Error Handling

MCP tool execution errors are returned as tool results with `isError: true`, not JSON-RPC protocol errors, per the [MCP tools error-handling spec](https://modelcontextprotocol.io/specification/draft/server/tools#error-handling).

`dispatch_agent` failures use one of these structured shapes:

- Shape A — `{ ok: false, jobId, error }`: embedded agent or wrapper fallback failed with readable context.
- Shape B — `{ ok: false, jobId, error, gateway }`: gateway-backed failure with the gateway identifier included.
- Shape C — `{ ok: false, error, request_id }`: top-level MCP wrapper failure that still preserves readable context instead of returning a protocol-level `Error occurred during tool execution` response.

Error strings are passed through from the underlying CLI/gateway and scrubbed for bearer tokens, JWT-shaped values, OAuth credentials, and full `/Users/jarvis/` home paths.
