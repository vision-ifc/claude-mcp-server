# Claude → Jarvis/OpenClaw MCP Server

MCP server for Claude ↔ OpenClaw, with OAuth 2.1 + PKCE support for claude.ai custom connectors.

## Public URL

- Base: `https://jarviss-macbook-pro-1.tail26d735.ts.net:8787`
- MCP: `https://jarviss-macbook-pro-1.tail26d735.ts.net:8787/mcp`

## OAuth endpoints

- Metadata: `/.well-known/oauth-authorization-server`
- Authorize: `/authorize`
- Token: `/token`
- Register: `/register`

## OAuth notes

- PKCE `S256` supported
- `MCP_API_KEY` is used as the approval password on the authorize page
- Static confidential client is configured via `OAUTH_CLIENT_ID` + `OAUTH_CLIENT_SECRET`
- Dynamic client registration is also supported

## Existing tools preserved

- `dispatch_agent`
- `check_status`
- `query_linear`
- `send_slack`
- `/healthz`

## launchd

Installed plist:

- `/Users/jarvis/Library/LaunchAgents/com.jarvis.mcp-server.plist`

Logs:

- `/Users/jarvis/.openclaw/logs/mcp-server.log`
