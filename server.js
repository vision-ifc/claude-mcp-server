import { randomBytes, randomUUID, createHash } from "node:crypto";
import http from "node:http";
import { hostname } from "node:os";
import { appendFileSync, readFileSync, existsSync, writeFileSync, readdirSync, renameSync } from "node:fs";
import { spawn, execFile } from "node:child_process";
import { LinearClient } from "@linear/sdk";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const PORT = Number(process.env.MCP_PORT || 8787);
const HOST = process.env.MCP_HOST || "127.0.0.1";
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || `http://${HOST}:${PORT}`).replace(/\/$/, "");
const API_KEY = process.env.MCP_API_KEY || "";
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const OAUTH_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.OAUTH_ACCESS_TOKEN_TTL_SECONDS || 2592000);
const OPENCLAW_BASE_URL = (process.env.OPENCLAW_BASE_URL || "ws://127.0.0.1:18789").replace(/\/$/, "");
const OPENCLAW_TOKEN = process.env.OPENCLAW_TOKEN || "";
const DEFAULT_AGENT_ID = process.env.DEFAULT_AGENT_ID || "artoo";
const LINEAR_API_KEY = process.env.LINEAR_API_KEY || "";
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN || "";
const SLACK_DEFAULT_CHANNEL = process.env.SLACK_DEFAULT_CHANNEL || "";
const OPENCLAW_PORT = Number(new URL(OPENCLAW_BASE_URL.replace(/^ws/, "http")).port || 18789);
const LOG_FILE = "/Users/jarvis/.openclaw/logs/mcp-server.log";
const OPENCLAW_AGENTS_DIR = "/Users/jarvis/.openclaw/agents";
const OAUTH_STATE_FILE = "/Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server/.oauth-state.json";
const AGENT_STATUS_DIR = "/Users/jarvis/.openclaw/workspace-yoda/agent-status";
const AGENT_COMPLETIONS_FILE = "/Users/jarvis/.openclaw/workspace-yoda/logs/agent-completions.json";
const TASKS_FILE = "/Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server/.tasks.json";
const TASK_TTL_MS = Number(process.env.MCP_TASK_TTL_MS || 24 * 60 * 60 * 1000);
const TASK_POLL_INTERVAL_MS = Number(process.env.MCP_TASK_POLL_INTERVAL_MS || 2000);
const OPENCLAW_CONFIG_FILE = "/Users/jarvis/.openclaw/openclaw.json";
const JARVIS_STATUS_LOGS = {
  gateway: "/Users/jarvis/.openclaw/logs/gateway.log",
  mcpServer: "/Users/jarvis/.openclaw/logs/mcp-server.log",
  sshTunnel: "/Users/jarvis/.openclaw/logs/mcp-tunnel.log"
};

if (!API_KEY || !OPENCLAW_TOKEN || !OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) process.exit(1);

const linear = LINEAR_API_KEY ? new LinearClient({ apiKey: LINEAR_API_KEY }) : null;
const jobs = new Map();
const authCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();
const registeredClients = new Map();
const transports = new Map();
const servers = new Map();
const activeSseBySession = new Map();

function logLine(message) { const line = `[${new Date().toISOString()}] ${message}`; console.log(line); try { appendFileSync(LOG_FILE, `${line}\n`); } catch {} }
function nowSeconds() { return Math.floor(Date.now() / 1000); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function corsHeaders(extra = {}) { return { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-key, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID", "Access-Control-Expose-Headers": "Mcp-Session-Id, WWW-Authenticate, MCP-Protocol-Version", ...extra }; }
function jsonResponse(res, status, body, headers = {}) { res.writeHead(status, { "Content-Type": "application/json", ...corsHeaders(headers) }); res.end(JSON.stringify(body)); }
function htmlResponse(res, status, html) { res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", ...corsHeaders() }); res.end(html); }
function parseBody(req) { return new Promise((resolve, reject) => { let data = ""; req.on("data", c => data += c); req.on("end", () => resolve(data)); req.on("error", reject); }); }
function parseForm(bodyText) { return Object.fromEntries(new URLSearchParams(bodyText)); }
function sha256Base64Url(input) { return createHash("sha256").update(input).digest("base64url"); }
function randomToken(size = 32) { return randomBytes(size).toString("base64url"); }
function isValidRedirectUri(uri) { try { const parsed = new URL(uri); return parsed.protocol === "https:" || parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1"; } catch { return false; } }
function getBearerToken(req) { const auth = req.headers.authorization || ""; if (auth.startsWith("Bearer ")) return auth.slice(7); return req.headers["x-api-key"] || ""; }

function saveOauthState() {
  const state = {
    registeredClients: Array.from(registeredClients.entries()),
    accessTokens: Array.from(accessTokens.entries()),
    refreshTokens: Array.from(refreshTokens.entries())
  };
  writeFileSync(OAUTH_STATE_FILE, JSON.stringify(state, null, 2));
}

function loadOauthState() {
  if (!existsSync(OAUTH_STATE_FILE)) return;
  try {
    const state = JSON.parse(readFileSync(OAUTH_STATE_FILE, "utf8"));
    for (const [k, v] of state.registeredClients || []) registeredClients.set(k, v);
    for (const [k, v] of state.accessTokens || []) if (v?.expiresAt > nowSeconds()) accessTokens.set(k, v);
    for (const [k, v] of state.refreshTokens || []) if (v?.expiresAt > nowSeconds()) refreshTokens.set(k, v);
  } catch (e) {
    logLine(`OAuth state load error: ${e.message}`);
  }
}

registeredClients.set(OAUTH_CLIENT_ID, { client_id: OAUTH_CLIENT_ID, client_secret: OAUTH_CLIENT_SECRET, redirect_uris: [], token_endpoint_auth_method: "client_secret_post", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], client_name: "Jarvis Claude Connector" });
loadOauthState();

function validateAccessToken(token) { if (!token) return false; if (token === API_KEY) return true; const stored = accessTokens.get(token); if (!stored) return false; if (stored.expiresAt <= nowSeconds()) { accessTokens.delete(token); saveOauthState(); return false; } return true; }
function issueAccessToken(clientId) { const accessToken = randomToken(32); const refreshToken = randomToken(32); const expiresAt = nowSeconds() + OAUTH_ACCESS_TOKEN_TTL_SECONDS; accessTokens.set(accessToken, { accessToken, clientId, expiresAt }); refreshTokens.set(refreshToken, { clientId, expiresAt: nowSeconds() + 30 * 24 * 3600 }); saveOauthState(); return { access_token: accessToken, token_type: "Bearer", expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS, refresh_token: refreshToken, scope: "mcp" }; }
function recordJob(job) { const full = { ...job, updatedAt: new Date().toISOString() }; jobs.set(job.id, full); return full; }
function getSessionIdForKey(sessionKey) { const agentId = sessionKey.split(":")[1]; const p = `${OPENCLAW_AGENTS_DIR}/${agentId}/sessions/sessions.json`; if (!existsSync(p)) return null; const data = JSON.parse(readFileSync(p, "utf8")); return data?.[sessionKey]?.sessionId || null; }
function getLatestAssistantReply(sessionKey) { const sessionId = getSessionIdForKey(sessionKey); if (!sessionId) return null; const p = `${OPENCLAW_AGENTS_DIR}/${sessionKey.split(":")[1]}/sessions/${sessionId}.jsonl`; if (!existsSync(p)) return null; const raw = readFileSync(p, "utf8").trim(); if (!raw) return null; const lines = raw.split(/\r?\n/).reverse(); for (const line of lines) { try { const obj = JSON.parse(line); const msg = obj.message; if (msg?.role === "assistant" && Array.isArray(msg.content)) { const parts = msg.content.filter(c => c?.type === "text" && typeof c.text === "string").map(c => c.text.trim()).filter(Boolean); if (parts.length) return parts.join("\n"); } } catch {} } return null; }
function readJsonFile(file, fallback) { try { if (!existsSync(file)) return fallback; return JSON.parse(readFileSync(file, "utf8")); } catch { return fallback; } }
function listAgentStatuses() { if (!existsSync(AGENT_STATUS_DIR)) return []; return readdirSync(AGENT_STATUS_DIR).filter(name => name.endsWith('.json')).map(name => readJsonFile(`${AGENT_STATUS_DIR}/${name}`, null)).filter(Boolean); }
function getCompletions(agent) { const completions = readJsonFile(AGENT_COMPLETIONS_FILE, []); const filtered = agent ? completions.filter(entry => entry?.agent === agent) : completions; return filtered.sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime()); }

function redactJarvisStatusString(value, extraSecrets = []) {
  let out = String(value || "");
  for (const secret of extraSecrets.filter(Boolean)) out = out.split(secret).join("[REDACTED:credential]");
  return out
    .replace(/sk-ant-[A-Za-z0-9_-]+/g, "[REDACTED:anthropic-key]")
    .replace(/sk-proj-[A-Za-z0-9_-]+/g, "[REDACTED:openai-key]")
    .replace(/sk-[A-Za-z0-9_-]{40,}/g, "[REDACTED:openai-key]")
    .replace(/xoxb-[A-Za-z0-9_-]+/g, "[REDACTED:slack-token]")
    .replace(/xapp-[A-Za-z0-9_-]+/g, "[REDACTED:slack-token]")
    .replace(/[0-9]{8,12}:[A-Za-z0-9_-]{30,}/g, "[REDACTED:telegram-token]")
    .replace(/bearer\s+[A-Za-z0-9._-]+/gi, "[REDACTED:bearer]")
    .replace(/(secret|password|token|api[_-]?key)["':=\s]+["']?[A-Za-z0-9_/+\-=.]{12,}["']?/gi, "[REDACTED:credential]");
}

function runReadOnlyCommand(command, args, timeoutMs = 2000) {
  const commandResult = new Promise(resolve => {
    const child = execFile(command, args, { timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (error, stdout) => {
      resolve(error ? null : stdout);
    });
    child.on("error", () => resolve(null));
  });
  return Promise.race([commandResult, new Promise(resolve => setTimeout(() => resolve(null), timeoutMs))]);
}

function stripJsoncComments(raw) {
  let out = "", inStr = false, esc = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (esc) { out += c; esc = false; continue; }
    if (c === "\\" && inStr) { out += c; esc = true; continue; }
    if (c === '"') { inStr = !inStr; out += c; continue; }
    if (!inStr && c === "/" && raw[i + 1] === "/") {
      while (i < raw.length && raw[i] !== "\n") i++;
      continue;
    }
    out += c;
  }
  return out;
}

function parseOpenClawConfig() {
  try {
    const raw = readFileSync(OPENCLAW_CONFIG_FILE, "utf8");
    const cleaned = stripJsoncComments(raw).replace(/,(\s*[}\]])/g, "$1");
    return JSON.parse(cleaned);
  } catch { return null; }
}

function getConfigValue(config, path) {
  return path.split(".").reduce((obj, key) => obj?.[key], config);
}

function parseLaunchctlList(raw) {
  if (!raw) return [];
  return raw.trim().split(/\r?\n/).slice(1).map(line => {
    const parts = line.trim().split(/\s+/);
    const label = parts.slice(2).join(" ");
    return { pid: parts[0] === "-" ? null : Number(parts[0]), status: Number(parts[1]), label };
  }).filter(service => /openclaw|jarvis|com\.openclaw/i.test(service.label));
}

function parseLsof(raw) {
  if (!raw) return null;
  const line = raw.trim().split(/\r?\n/)[1];
  if (!line) return null;
  const parts = line.trim().split(/\s+/);
  const pid = Number(parts[1]);
  return Number.isFinite(pid) ? { pid, command: parts[0] || null, alive: true } : null;
}

function parsePs(raw, extraSecrets) {
  if (!raw) return null;
  const line = raw.trim().split(/\r?\n/)[0];
  if (!line) return null;
  const parts = line.trim().split(/\s+/);
  const pid = Number(parts[0]);
  if (!Number.isFinite(pid)) return null;
  const cpu = Number(parts[1]);
  const mem = Number(parts[2]);
  const started = parts.slice(3, 8).join(" ");
  const command = parts.slice(8).join(" ");
  return { pid, cpu: Number.isFinite(cpu) ? cpu : null, mem: Number.isFinite(mem) ? mem : null, command: redactJarvisStatusString(command, extraSecrets), started };
}

function agentSessionSummary(agent) {
  const sessions = readJsonFile(`${OPENCLAW_AGENTS_DIR}/${agent}/sessions/sessions.json`, null);
  if (!sessions) return null;
  const preferred = sessions[`agent:${agent}:main`] || Object.values(sessions)[0];
  if (!preferred) return null;
  return {
    sessionId: preferred.sessionId || null,
    sessionStartedAt: preferred.startedAt ? new Date(preferred.startedAt).toISOString() : (preferred.createdAt || null),
    lastUpdated: preferred.updatedAt ? new Date(preferred.updatedAt).toISOString() : (preferred.lastUpdated || null)
  };
}

async function collectJarvisStatusCore({ include_logs = false, log_lines = 50 } = {}) {
  const config = parseOpenClawConfig();
  const gatewayToken = config?.gateway?.authToken || config?.gateway?.token || config?.authToken || config?.token || "";
  const launchdRaw = await runReadOnlyCommand("launchctl", ["list"]);
  const services = parseLaunchctlList(launchdRaw);
  const portEntries = await Promise.all([18789, 18820, 8787, 19876].map(async port => [String(port), parseLsof(await runReadOnlyCommand("lsof", ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN"]))]));
  const ports = Object.fromEntries(portEntries);
  const trackedPids = Array.from(new Set(Object.values(ports).map(port => port?.pid).filter(Number.isFinite)));
  const processes = (await Promise.all(trackedPids.map(async pid => parsePs(await runReadOnlyCommand("ps", ["-p", String(pid), "-o", "pid=,pcpu=,pmem=,lstart=,command="]), [gatewayToken])))).filter(Boolean);
  const hasService = label => services.some(service => service.label.includes(label) && service.status === 0);
  const health = {
    mainGatewayUp: !!ports["18789"]?.alive && hasService("ai.openclaw.gateway"),
    codingGatewayUp: !!ports["18820"]?.alive && hasService("ai.openclaw.coding"),
    mcpServerUp: !!ports["8787"]?.alive,
    sshTunnelUp: !!ports["19876"]?.alive && hasService("com.jarvis.mcp-tunnel"),
    overallOk: false
  };
  health.overallOk = health.mainGatewayUp && health.codingGatewayUp && health.mcpServerUp && health.sshTunnelUp;
  const snapshot = {
    timestamp: new Date().toISOString(),
    hostname: hostname(),
    health,
    launchd: { services },
    ports,
    processes,
    configs: {
      "session.reset": getConfigValue(config, "session.reset") ?? null,
      "session.resetTriggers": getConfigValue(config, "session.resetTriggers") ?? null,
      "gateway.bind": getConfigValue(config, "gateway.bind") ?? null,
      "gateway.port": getConfigValue(config, "gateway.port") ?? null
    },
    agents: {
      artoo: agentSessionSummary("artoo"),
      threepo: agentSessionSummary("threepo")
    }
  };
  if (include_logs) {
    snapshot.logs = Object.fromEntries(await Promise.all(Object.entries(JARVIS_STATUS_LOGS).map(async ([name, path]) => {
      const raw = await runReadOnlyCommand("tail", ["-n", String(log_lines), path]);
      return [name, raw ? raw.split(/\r?\n/).filter(Boolean).map(line => redactJarvisStatusString(line, [gatewayToken])) : null];
    })));
  }
  return snapshot;
}

async function collectJarvisStatus(options = {}) {
  const includeLogs = !!options.include_logs;
  const logLines = Math.min(Math.max(Number(options.log_lines ?? 50), 0), 200);
  const timeoutMs = includeLogs && logLines === 200 ? 30000 : 10000;
  const timeoutSnapshot = new Promise(resolve => setTimeout(() => resolve({ timestamp: new Date().toISOString(), hostname: hostname(), health: { mainGatewayUp: false, codingGatewayUp: false, mcpServerUp: false, sshTunnelUp: false, overallOk: false }, launchd: { services: [] }, ports: { "18789": null, "18820": null, "8787": null, "19876": null }, processes: [], configs: { "session.reset": null, "session.resetTriggers": null, "gateway.bind": null, "gateway.port": null }, agents: { artoo: null, threepo: null }, error: "jarvis_status collection timed out" }), timeoutMs));
  return Promise.race([collectJarvisStatusCore({ include_logs: includeLogs, log_lines: logLines }), timeoutSnapshot]);
}
async function waitForAgentReply(sessionKey, previousReply, timeoutMs) { const started = Date.now(); while (Date.now() - started < timeoutMs) { const reply = getLatestAssistantReply(sessionKey); if (reply && reply !== previousReply) return reply; await sleep(2000); } return null; }

function requireMcpAuth(req, res) { const token = getBearerToken(req); if (!validateAccessToken(token)) { res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`, ...corsHeaders() }); res.end(JSON.stringify({ error: "unauthorized" })); return false; } return true; }
function runGatewayCall(method, params = {}, expectFinal = false, timeoutMs = 30000) { return new Promise((resolve, reject) => { const args = ["gateway", "call", method, "--timeout", String(timeoutMs), "--params", JSON.stringify(params), "--token", OPENCLAW_TOKEN, "--url", `ws://127.0.0.1:${OPENCLAW_PORT}`]; if (expectFinal) args.splice(3, 0, "--expect-final"); const child = spawn("openclaw", args, { stdio: ["ignore", "pipe", "pipe"] }); let stdout = "", stderr = ""; child.stdout.on("data", d => stdout += d.toString()); child.stderr.on("data", d => stderr += d.toString()); child.on("error", reject); child.on("close", code => code !== 0 ? reject(new Error(stderr.trim() || stdout.trim() || `gateway call failed (${code})`)) : resolve((stdout || stderr).trim())); }); }

function buildServer() {
  const server = new McpServer({ name: "jarvis-openclaw-mcp", version: "0.5.0" });
  server.tool("dispatch_agent", "Dispatch a task to an OpenClaw agent/sub-agent.", { agentId: z.string().default(DEFAULT_AGENT_ID), task: z.string().min(1), sessionKey: z.string().optional(), waitForReply: z.boolean().default(true), timeoutMs: z.number().int().positive().max(120000).default(120000) }, async ({ agentId, task, sessionKey, waitForReply, timeoutMs }) => {
    const jobId = randomUUID();
    const key = sessionKey || `agent:${agentId}:main`;
    const previousReply = getLatestAssistantReply(key);
    const params = { key, message: task };
    recordJob({ id: jobId, type: "dispatch_agent", status: "running", request: params });
    try {
      const raw = await runGatewayCall("sessions.send", params, false, Math.min(timeoutMs, 10000));
      const reply = waitForReply ? await waitForAgentReply(key, previousReply, timeoutMs) : null;
      const job = recordJob({ id: jobId, type: "dispatch_agent", status: reply || !waitForReply ? "completed" : "started", request: params, raw, reply });
      return { content: [{ type: "text", text: JSON.stringify({ ok: true, jobId, sessionKey: key, reply, raw: job.raw }, null, 2) }] };
    } catch (error) {
      recordJob({ id: jobId, type: "dispatch_agent", status: "failed", request: params, error: error.message });
      return { content: [{ type: "text", text: JSON.stringify({ ok: false, jobId, error: error.message }, null, 2) }], isError: true };
    }
  });
  server.tool("check_status", "Check status of a previous MCP job or an OpenClaw session.", { jobId: z.string().optional(), sessionKey: z.string().optional() }, async ({ jobId, sessionKey }) => {
    if (jobId) { const job = jobs.get(jobId); if (!job) return { content: [{ type: "text", text: JSON.stringify({ ok: false, error: "job not found" }, null, 2) }], isError: true }; return { content: [{ type: "text", text: JSON.stringify({ ok: true, job }, null, 2) }] }; }
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, sessionKey, jobs: Array.from(jobs.values()).slice(-20) }, null, 2) }] };
  });
  server.tool("query_linear", "Search Linear issues or fetch a specific issue.", { query: z.string().optional(), issueId: z.string().optional(), limit: z.number().int().positive().max(20).default(5) }, async ({ query, issueId, limit }) => {
    if (!linear) return { content: [{ type: "text", text: JSON.stringify({ ok: false, error: "LINEAR_API_KEY not configured" }, null, 2) }], isError: true };
    try {
      if (issueId) { const issue = await linear.issue(issueId); return { content: [{ type: "text", text: JSON.stringify({ ok: true, issue }, null, 2) }] }; }
      const results = await linear.searchIssues(query || "", { limit });
      const issues = results.nodes.map(issue => ({ id: issue.id, identifier: issue.identifier, title: issue.title, state: issue.state?.name, url: issue.url }));
      return { content: [{ type: "text", text: JSON.stringify({ ok: true, issues }, null, 2) }] };
    } catch (error) { return { content: [{ type: "text", text: JSON.stringify({ ok: false, error: error.message }, null, 2) }], isError: true }; }
  });
  server.tool("send_slack", "Send a Slack message to a channel or DM.", { channel: z.string().optional(), text: z.string().min(1) }, async ({ channel, text }) => {
    if (!SLACK_BOT_TOKEN) return { content: [{ type: "text", text: JSON.stringify({ ok: false, error: "SLACK_BOT_TOKEN not configured" }, null, 2) }], isError: true };
    const target = channel || SLACK_DEFAULT_CHANNEL;
    if (!target) return { content: [{ type: "text", text: JSON.stringify({ ok: false, error: "channel required" }, null, 2) }], isError: true };
    try {
      const response = await fetch("https://slack.com/api/chat.postMessage", { method: "POST", headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}`, "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify({ channel: target, text }) });
      const result = await response.json(); if (!result.ok) throw new Error(result.error || "Slack API error");
      return { content: [{ type: "text", text: JSON.stringify({ ok: true, result }, null, 2) }] };
    } catch (error) { return { content: [{ type: "text", text: JSON.stringify({ ok: false, error: error.message }, null, 2) }], isError: true }; }
  });
  server.tool("list_agents", "List tracked agents with session keys and current status.", {}, async () => {
    const agents = listAgentStatuses();
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, agents }, null, 2) }] };
  });
  server.tool("jarvis_status", "Returns a structured snapshot of Jarvis OpenClaw + MCP infrastructure state — launchd services, listening ports, running processes, recent logs (with secrets redacted), agent session metadata, and health roll-ups. Read-only; no mutations.", { include_logs: z.boolean().optional().default(false), log_lines: z.number().int().min(0).max(200).optional().default(50) }, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }, async ({ include_logs, log_lines }, extra) => {
    const snapshot = await collectJarvisStatus({ include_logs, log_lines });
    return { content: [{ type: "text", text: JSON.stringify(snapshot, null, 2) }], structuredContent: snapshot };
  });
  server.tool("get_completions", "Get recent agent completions, optionally filtered by agent.", { agent: z.string().optional() }, async ({ agent }) => {
    const completions = getCompletions(agent);
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, completions }, null, 2) }] };
  });
  server.tool("get_agent_output", "Get the latest assistant reply for an agent session.", { sessionKey: z.string() }, async ({ sessionKey }) => {
    const reply = getLatestAssistantReply(sessionKey);
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, sessionKey, reply }, null, 2) }] };
  });
  return server;
}

async function getTransport(req, parsedBody) {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && transports.has(sessionId)) return transports.get(sessionId);
  if (parsedBody && isInitializeRequest(parsedBody)) {
    const server = buildServer();
    let transport;
    transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), enableJsonResponse: true, onsessioninitialized: id => { transports.set(id, transport); servers.set(id, server); logLine(`MCP session initialized: ${id}`); }, onsessionclosed: id => { transports.delete(id); servers.delete(id); activeSseBySession.delete(id); logLine(`MCP session closed: ${id}`); } });
    transport.onerror = err => logLine(`MCP transport error: ${err.message}`);
    await server.connect(transport);
    return transport;
  }
  return null;
}

const app = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", PUBLIC_BASE_URL);
  const sessionId = req.headers["mcp-session-id"];
  logLine(`${req.method} ${url.pathname} from ${req.headers["x-forwarded-for"] || req.socket.remoteAddress} | UA: ${(req.headers["user-agent"] || "").slice(0, 120)}`);
  if (req.method === "OPTIONS") { res.writeHead(204, corsHeaders({ "Access-Control-Max-Age": "86400" })); return res.end(); }
  if (url.pathname === "/healthz") return jsonResponse(res, 200, { ok: true, service: "jarvis-openclaw-mcp", openclawPort: OPENCLAW_PORT, oauth: true });
  if (url.pathname === "/.well-known/oauth-protected-resource") return jsonResponse(res, 200, { resource: PUBLIC_BASE_URL, authorization_servers: [PUBLIC_BASE_URL], bearer_methods_supported: ["header"], scopes_supported: ["mcp"] });
  if (url.pathname === "/.well-known/oauth-authorization-server") return jsonResponse(res, 200, { issuer: PUBLIC_BASE_URL, authorization_endpoint: `${PUBLIC_BASE_URL}/authorize`, token_endpoint: `${PUBLIC_BASE_URL}/token`, registration_endpoint: `${PUBLIC_BASE_URL}/register`, response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"], code_challenge_methods_supported: ["S256"], scopes_supported: ["mcp"] });
  if (url.pathname === "/register" && req.method === "POST") { const body = JSON.parse((await parseBody(req)) || "{}"); const clientId = `mcp-${randomToken(12)}`; const clientSecret = randomToken(24); const record = { client_id: clientId, client_secret: clientSecret, client_id_issued_at: nowSeconds(), client_secret_expires_at: 0, redirect_uris: Array.isArray(body.redirect_uris) ? body.redirect_uris.filter(isValidRedirectUri) : [], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: body.token_endpoint_auth_method || "client_secret_post", client_name: body.client_name || "Dynamic MCP Client" }; registeredClients.set(clientId, record); saveOauthState(); return jsonResponse(res, 201, record); }
  if (url.pathname === "/authorize" && req.method === "GET") { const clientId = url.searchParams.get("client_id") || ""; const redirectUri = url.searchParams.get("redirect_uri") || ""; const state = url.searchParams.get("state") || ""; const codeChallenge = url.searchParams.get("code_challenge") || ""; const codeChallengeMethod = url.searchParams.get("code_challenge_method") || ""; const responseType = url.searchParams.get("response_type") || ""; const client = registeredClients.get(clientId); if (!client || responseType !== "code" || !redirectUri || !isValidRedirectUri(redirectUri) || !codeChallenge || codeChallengeMethod !== "S256") return htmlResponse(res, 400, "<h1>Invalid OAuth request</h1>"); const TRUSTED_REDIRECT_ORIGINS = ["https://claude.ai"]; if (TRUSTED_REDIRECT_ORIGINS.some(o => redirectUri.startsWith(o))) { const code = randomToken(24); authCodes.set(code, { clientId, redirectUri, codeChallenge, expiresAt: nowSeconds() + 600 }); const redirect = new URL(redirectUri); redirect.searchParams.set("code", code); if (state) redirect.searchParams.set("state", state); res.writeHead(302, { Location: redirect.toString(), ...corsHeaders() }); return res.end(); } const form = `<!doctype html><html><body style="font-family:sans-serif;max-width:520px;margin:40px auto"><h1>Authorize Claude Connector</h1><p>Enter the MCP API key to approve access for <b>${client.client_name || clientId}</b>.</p><form method="POST" action="/authorize"><input type="hidden" name="client_id" value="${clientId}" /><input type="hidden" name="redirect_uri" value="${redirectUri}" /><input type="hidden" name="state" value="${state}" /><input type="hidden" name="code_challenge" value="${codeChallenge}" /><input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}" /><label>API key<br/><input type="password" name="api_key" style="width:100%;padding:8px" autofocus /></label><br/><br/><button type="submit">Approve</button></form></body></html>`; return htmlResponse(res, 200, form); }
  if (url.pathname === "/authorize" && req.method === "POST") { const form = parseForm(await parseBody(req)); logLine(`POST /authorize — client_id=${form.client_id}, redirect_uri=${form.redirect_uri}, api_key_provided=${!!form.api_key}, api_key_match=${form.api_key === API_KEY}`); const client = registeredClients.get(form.client_id || ""); if (!client || form.api_key !== API_KEY || !isValidRedirectUri(form.redirect_uri || "") || form.code_challenge_method !== "S256") return htmlResponse(res, 401, "<h1>Authorization failed</h1><p>Invalid API key or request.</p>"); const code = randomToken(24); authCodes.set(code, { clientId: form.client_id, redirectUri: form.redirect_uri, codeChallenge: form.code_challenge, expiresAt: nowSeconds() + 600 }); const redirect = new URL(form.redirect_uri); redirect.searchParams.set("code", code); if (form.state) redirect.searchParams.set("state", form.state); res.writeHead(302, { Location: redirect.toString(), ...corsHeaders() }); return res.end(); }
  if (url.pathname === "/token" && req.method === "POST") { const form = parseForm(await parseBody(req)); logLine(`POST /token — grant_type=${form.grant_type}, client_id=${form.client_id}, code_present=${!!form.code}, verifier_present=${!!form.code_verifier}`); const clientId = form.client_id || ""; const client = registeredClients.get(clientId); if (!client) return jsonResponse(res, 401, { error: "invalid_client" }); const basic = req.headers.authorization || ""; const basicMatch = basic.startsWith("Basic ") ? Buffer.from(basic.slice(6), "base64").toString("utf8").split(":") : []; const presentedSecret = form.client_secret || basicMatch[1] || ""; const authMethod = client.token_endpoint_auth_method || "client_secret_post"; if (authMethod !== "none" && presentedSecret !== client.client_secret) return jsonResponse(res, 401, { error: "invalid_client" }); if (form.grant_type === "authorization_code") { const code = authCodes.get(form.code || ""); if (!code || code.expiresAt <= nowSeconds() || code.clientId !== clientId || code.redirectUri !== form.redirect_uri) return jsonResponse(res, 400, { error: "invalid_grant" }); if (!form.code_verifier || sha256Base64Url(form.code_verifier) !== code.codeChallenge) return jsonResponse(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" }); authCodes.delete(form.code); return jsonResponse(res, 200, issueAccessToken(clientId), { "Cache-Control": "no-store" }); } if (form.grant_type === "refresh_token") { const refresh = refreshTokens.get(form.refresh_token || ""); if (!refresh || refresh.clientId !== clientId || refresh.expiresAt <= nowSeconds()) return jsonResponse(res, 400, { error: "invalid_grant" }); return jsonResponse(res, 200, issueAccessToken(clientId), { "Cache-Control": "no-store" }); } return jsonResponse(res, 400, { error: "unsupported_grant_type" }); }
  if (url.pathname !== "/mcp") return jsonResponse(res, 404, { error: "not found" });
  if (!requireMcpAuth(req, res)) return;
  try {
    if (req.method === "GET") {
      if (sessionId && activeSseBySession.get(sessionId)) { return jsonResponse(res, 409, { error: "sse_already_active" }); }
      if (sessionId) activeSseBySession.set(sessionId, true);
      res.on("close", () => { if (sessionId) activeSseBySession.delete(sessionId); });
      const transport = sessionId ? transports.get(sessionId) : null;
      if (!transport) return jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: No valid session ID provided" }, id: null });
      await transport.handleRequest(req, res); return;
    }
    if (req.method === "DELETE") {
      if (sessionId) activeSseBySession.delete(sessionId);
      const transport = sessionId ? transports.get(sessionId) : null;
      if (!transport) return jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: No valid session ID provided" }, id: null });
      await transport.handleRequest(req, res); return;
    }
    if (req.method === "POST") { const bodyText = await parseBody(req); const body = bodyText ? JSON.parse(bodyText) : {}; logLine(`POST /mcp body: ${JSON.stringify(body).slice(0, 2000)}`); const transport = await getTransport(req, body); if (!transport) return jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: No valid session ID provided" }, id: null }); await transport.handleRequest(req, res, body); return; }
    return jsonResponse(res, 405, { error: "method not allowed" }, { Allow: "GET, POST, DELETE, OPTIONS" });
  } catch (error) {
    logLine(`MCP handler error: ${error.stack || error.message}`);
    if (sessionId) activeSseBySession.delete(sessionId);
    return jsonResponse(res, 500, { error: error.message });
  }
});

app.listen(PORT, HOST, () => { logLine(`MCP server listening on ${PUBLIC_BASE_URL}/mcp`); });
