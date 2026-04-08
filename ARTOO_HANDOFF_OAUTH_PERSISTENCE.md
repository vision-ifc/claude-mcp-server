Task for Artoo:

Fix OAuth token persistence — Claude re-authorizes on every query.

Root cause:
1. OAuth access tokens are stored only in-memory (`accessTokens` Map), so they disappear on server restart.
2. Claude may dynamic-register a new client per session, so registered clients also need persistence.
3. There is also an MCP transport issue: duplicate SSE/session handling logs `Conflict: Only one SSE stream is allowed per session`.

Required fixes:
1. Persist access tokens and registered clients to disk
   - Use: `/Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server/.oauth-state.json`
   - Save on every mutation
   - Reload on startup
2. Increase token TTL
   - Change `OAUTH_ACCESS_TOKEN_TTL_SECONDS` in `.env` from `3600` to `2592000`
3. Fix duplicate SSE/session conflicts
   - `/mcp` handler should track active SSE/session usage by `Mcp-Session-Id`
   - Reject or close duplicate streams gracefully instead of leaving Claude in a broken reconnect loop

Files:
- `/Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server/server.js`
- `/Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server/.env`

Context:
- OAuth currently works, but Claude re-prompts for API key too often
- `dispatch_agent` was recently updated to poll local OpenClaw session JSONL for the final assistant reply after `sessions.send`
- MCP server is being used behind `https://jarvis.ifcroofing.com/mcp`
