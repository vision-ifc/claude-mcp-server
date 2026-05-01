import { randomBytes, randomUUID, createHash } from "node:crypto";
import http from "node:http";
import { hostname, homedir, userInfo } from "node:os";
import { appendFileSync, readFileSync, existsSync, writeFileSync, readdirSync, renameSync, openSync, fstatSync, readSync, closeSync } from "node:fs";
import { spawn, execFile, execFileSync } from "node:child_process";
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
const OPENCLAW_CODING_BASE_URL = (process.env.OPENCLAW_CODING_BASE_URL || "").replace(/\/$/, "");
const OPENCLAW_CODING_TOKEN = process.env.OPENCLAW_CODING_TOKEN || "";
const DEFAULT_AGENT_ID = process.env.DEFAULT_AGENT_ID || "artoo";
const LINEAR_API_KEY = process.env.LINEAR_API_KEY || "";
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN || "";
const SLACK_DEFAULT_CHANNEL = process.env.SLACK_DEFAULT_CHANNEL || "";
const OPENCLAW_PORT = Number(new URL(OPENCLAW_BASE_URL.replace(/^ws/, "http")).port || 18789);
const OPENCLAW_CODING_PORT = OPENCLAW_CODING_BASE_URL ? Number(new URL(OPENCLAW_CODING_BASE_URL.replace(/^ws/, "http")).port || 18820) : 0;

// Agents that should be routed through the coding gateway (port 18820)
const CODING_GATEWAY_AGENTS = new Set(["artoo"]);
const LOG_FILE = "/Users/jarvis/.openclaw/logs/mcp-server.log";
const OPENCLAW_AGENTS_DIR = "/Users/jarvis/.openclaw/agents";
const OAUTH_STATE_FILE = "/Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server/.oauth-state.json";
const AGENT_STATUS_DIR = "/Users/jarvis/.openclaw/workspace-yoda/agent-status";
const AGENT_COMPLETIONS_FILE = "/Users/jarvis/.openclaw/workspace-yoda/logs/agent-completions.json";
const TASKS_FILE = "/Users/jarvis/.openclaw/workspace-yoda/claude-mcp-server/.tasks.json";
const TASK_TTL_MS = Number(process.env.MCP_TASK_TTL_MS || 24 * 60 * 60 * 1000);
const TASK_POLL_INTERVAL_MS = Number(process.env.MCP_TASK_POLL_INTERVAL_MS || 2000);

function tailReadFile(filePath, maxBytes = 262144) {
  const fd = openSync(filePath, "r");
  try {
    const stat = fstatSync(fd);
    if (stat.size <= maxBytes) {
      const full = Buffer.alloc(stat.size);
      readSync(fd, full, 0, stat.size, 0);
      return full.toString("utf8");
    }
    const buf = Buffer.alloc(maxBytes);
    readSync(fd, buf, 0, maxBytes, stat.size - maxBytes);
    let text = buf.toString("utf8");
    const firstNewline = text.indexOf("\n");
    if (firstNewline > 0 && firstNewline < text.length - 1) {
      text = text.slice(firstNewline + 1);
    }
    return text;
  } finally {
    closeSync(fd);
  }
}
const OPENCLAW_CONFIG_FILE = "/Users/jarvis/.openclaw/openclaw.json";
const JARVIS_STATUS_LOGS = {
  gateway: "/Users/jarvis/.openclaw/logs/gateway.log",
  mcpServer: "/Users/jarvis/.openclaw/logs/mcp-server.log",
  sshTunnel: "/Users/jarvis/.openclaw/logs/mcp-tunnel.log"
};
const ALLOWED_SERVICES = {
  "com.jarvis.mcp-server": "~/Library/LaunchAgents/com.jarvis.mcp-server.plist",
  "ai.openclaw.gateway": "~/Library/LaunchAgents/ai.openclaw.gateway.plist",
  "ai.openclaw.coding": "~/Library/LaunchAgents/ai.openclaw.coding.plist",
  "com.jarvis.mcp-tunnel": "~/Library/LaunchAgents/com.jarvis.mcp-tunnel.plist",
  "com.openclaw.yoda-dedup": "~/Library/LaunchAgents/com.openclaw.yoda-dedup.plist",
  "com.openclaw.caffeinate": "~/Library/LaunchAgents/com.openclaw.caffeinate.plist"
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
const authContextsBySession = new Map();
const clientSupportsTasksBySession = new Map();
const activeSseBySession = new Map();
const activeTaskChildren = new Map();
let taskState = { tasks: [] };

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

function getAuthContextForToken(token) { if (!token) return null; if (token === API_KEY) return { type: "api-key", clientId: "static-api-key" }; const stored = accessTokens.get(token); if (!stored) return null; if (stored.expiresAt <= nowSeconds()) { accessTokens.delete(token); saveOauthState(); return null; } return { type: "oauth", clientId: stored.clientId || "unknown-oauth-client" }; }
function getAuthContext(req) { return getAuthContextForToken(getBearerToken(req)); }
function validateAccessToken(token) { return !!getAuthContextForToken(token); }
function issueAccessToken(clientId) { const accessToken = randomToken(32); const refreshToken = randomToken(32); const expiresAt = nowSeconds() + OAUTH_ACCESS_TOKEN_TTL_SECONDS; accessTokens.set(accessToken, { accessToken, clientId, expiresAt }); refreshTokens.set(refreshToken, { clientId, expiresAt: nowSeconds() + 30 * 24 * 3600 }); saveOauthState(); return { access_token: accessToken, token_type: "Bearer", expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS, refresh_token: refreshToken, scope: "mcp" }; }
function recordJob(job) { const full = { ...job, updatedAt: new Date().toISOString() }; jobs.set(job.id, full); return full; }
function getSessionIdForKey(sessionKey) { const agentId = sessionKey.split(":")[1]; const p = `${OPENCLAW_AGENTS_DIR}/${agentId}/sessions/sessions.json`; if (!existsSync(p)) return null; const data = JSON.parse(readFileSync(p, "utf8")); return data?.[sessionKey]?.sessionId || null; }
function getLatestAssistantReply(sessionKey) { const sessionId = getSessionIdForKey(sessionKey); if (!sessionId) return null; const p = `${OPENCLAW_AGENTS_DIR}/${sessionKey.split(":")[1]}/sessions/${sessionId}.jsonl`; if (!existsSync(p)) return null; const raw = readFileSync(p, "utf8").trim(); if (!raw) return null; const lines = raw.split(/\r?\n/).reverse(); for (const line of lines) { try { const obj = JSON.parse(line); const msg = obj.message; if (msg?.role === "assistant" && Array.isArray(msg.content)) { const parts = msg.content.filter(c => c?.type === "text" && typeof c.text === "string").map(c => c.text.trim()).filter(Boolean); if (parts.length) return parts.join("\n"); } } catch {} } return null; }
function readJsonFile(file, fallback) { try { if (!existsSync(file)) return fallback; return JSON.parse(readFileSync(file, "utf8")); } catch { return fallback; } }
function isoOrNull(value) { if (!value) return null; const time = typeof value === "number" ? value : Date.parse(value); return Number.isFinite(time) ? new Date(time).toISOString() : null; }
function readLatestAssistantText(sessionKey) {
  const agentId = sessionKey?.split(":")?.[1];
  if (!agentId) return { ok: true, sessionKey, sessionId: null, sessionLastUpdated: null, reply: null, reason: "no_active_session" };
  const sessionsPath = `${OPENCLAW_AGENTS_DIR}/${agentId}/sessions/sessions.json`;
  const sessions = readJsonFile(sessionsPath, null);
  const entry = sessions?.[sessionKey];
  const sessionId = entry?.sessionId || null;
  const sessionLastUpdated = isoOrNull(entry?.updatedAt || entry?.lastUpdated || entry?.endedAt || entry?.startedAt);
  if (!sessionId) return { ok: true, sessionKey, sessionId: null, sessionLastUpdated, reply: null, reason: "no_active_session" };
  const canonicalTranscriptPath = `${OPENCLAW_AGENTS_DIR}/${agentId}/sessions/${sessionId}.jsonl`;
  const transcriptPath = existsSync(canonicalTranscriptPath) ? canonicalTranscriptPath : entry?.sessionFile;
  if (!transcriptPath || !existsSync(transcriptPath)) return { ok: true, sessionKey, sessionId, sessionLastUpdated, reply: null, reason: "no_transcript" };
  const raw = tailReadFile(transcriptPath, 262144);
  const lines = raw.split(/\r?\n/).filter(line => line.trim());
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const obj = JSON.parse(lines[i]);
      const msg = obj.message;
      if (msg?.role !== "assistant" || !Array.isArray(msg.content)) continue;
      const parts = msg.content.filter(part => part?.type === "text" && typeof part.text === "string" && part.text.trim()).map(part => part.text.trim());
      if (parts.length) return { ok: true, sessionKey, sessionId, sessionLastUpdated, reply: redactSecrets(parts.join("\n")) };
    } catch {}
  }
  return { ok: true, sessionKey, sessionId, sessionLastUpdated, reply: null, reason: "no_new_reply" };
}
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
function redactSecrets(value, extraSecrets = []) { return redactJarvisStatusString(value, extraSecrets); }

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

function parsePgrep(raw) {
  if (!raw) return null;
  const line = raw.trim().split(/\r?\n/)[0];
  if (!line) return null;
  const parts = line.trim().split(/\s+/);
  const pid = Number(parts[0]);
  return Number.isFinite(pid) ? { pid, command: parts.slice(1).join(" ") || null, alive: true } : null;
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
  const portEntries = await Promise.all([18789, 18820, 8787].map(async port => [String(port), parseLsof(await runReadOnlyCommand("lsof", ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN"]))]));
  const ports = Object.fromEntries(portEntries);
  const sshTunnelProcess = parsePgrep(await runReadOnlyCommand("pgrep", ["-fl", "autossh.*-R[[:space:]]19876:127\\.0\\.0\\.1:8787"]));
  const trackedPids = Array.from(new Set([...Object.values(ports).map(port => port?.pid), sshTunnelProcess?.pid].filter(Number.isFinite)));
  const processes = (await Promise.all(trackedPids.map(async pid => parsePs(await runReadOnlyCommand("ps", ["-p", String(pid), "-o", "pid=,pcpu=,pmem=,lstart=,command="]), [gatewayToken])))).filter(Boolean);
  const hasService = label => services.some(service => service.label.includes(label) && service.status === 0);
  const health = {
    mainGatewayUp: !!ports["18789"]?.alive && hasService("ai.openclaw.gateway"),
    codingGatewayUp: !!ports["18820"]?.alive && hasService("ai.openclaw.coding"),
    mcpServerUp: !!ports["8787"]?.alive,
    sshTunnelUp: !!sshTunnelProcess?.alive && hasService("com.jarvis.mcp-tunnel"),
    overallOk: false
  };
  health.overallOk = health.mainGatewayUp && health.codingGatewayUp && health.mcpServerUp && health.sshTunnelUp;
  const snapshot = {
    timestamp: new Date().toISOString(),
    hostname: hostname(),
    health,
    launchd: { services },
    ports,
    tunnel: { remotePort: 19876, target: "127.0.0.1:8787", process: sshTunnelProcess },
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
  const timeoutSnapshot = new Promise(resolve => setTimeout(() => resolve({ timestamp: new Date().toISOString(), hostname: hostname(), health: { mainGatewayUp: false, codingGatewayUp: false, mcpServerUp: false, sshTunnelUp: false, overallOk: false }, launchd: { services: [] }, ports: { "18789": null, "18820": null, "8787": null }, tunnel: { remotePort: 19876, target: "127.0.0.1:8787", process: null }, processes: [], configs: { "session.reset": null, "session.resetTriggers": null, "gateway.bind": null, "gateway.port": null }, agents: { artoo: null, threepo: null }, error: "jarvis_status collection timed out" }), timeoutMs));
  return Promise.race([collectJarvisStatusCore({ include_logs: includeLogs, log_lines: logLines }), timeoutSnapshot]);
}

function expandAllowedServicePath(plistPath) {
  return plistPath.startsWith("~/") ? `${homedir()}/${plistPath.slice(2)}` : plistPath;
}

function launchctlDomain() { return `gui/${userInfo().uid}`; }

function runLaunchctl(args) {
  try {
    const stdout = execFileSync("launchctl", args, { encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024 });
    return { ok: true, code: 0, stdout, stderr: "" };
  } catch (error) {
    return { ok: false, code: error.status ?? 1, stdout: error.stdout?.toString?.() || "", stderr: error.stderr?.toString?.() || error.message || "" };
  }
}

function getServicePid(serviceLabel) {
  try {
    const raw = execFileSync("launchctl", ["list"], { encoding: "utf8", timeout: 2000, maxBuffer: 1024 * 1024 });
    const line = raw.split(/\r?\n/).find(row => row.trim().endsWith(`\t${serviceLabel}`) || row.trim().endsWith(` ${serviceLabel}`));
    if (!line) return null;
    const pid = line.trim().split(/\s+/)[0];
    return pid === "-" ? null : Number(pid);
  } catch { return null; }
}

function bootoutBootstrapService(service, plistPath, oldPid) {
  runLaunchctl(["bootout", launchctlDomain(), plistPath]);
  const boot = runLaunchctl(["bootstrap", launchctlDomain(), plistPath]);
  const newPid = getServicePid(service);
  if (!boot.ok) return { ok: false, status: "failed", method: "bootout-bootstrap", service, oldPid, newPid, error: boot.stderr || boot.stdout || "bootstrap failed" };
  return { ok: true, status: "restarted", method: "bootout-bootstrap", service, oldPid, newPid };
}

function restartServiceImpl(service, mode = "kickstart") {
  const configuredPath = ALLOWED_SERVICES[service];
  if (!configuredPath) return { ok: false, error: "service not in allowlist", service };
  const plistPath = expandAllowedServicePath(configuredPath);
  const oldPid = getServicePid(service);
  if (service === "com.jarvis.mcp-server") {
    const helper = spawn("/bin/sh", ["-c", `sleep 2 && launchctl bootout ${launchctlDomain()} ${plistPath} 2>/dev/null; sleep 3 && launchctl bootstrap ${launchctlDomain()} ${plistPath}`], { detached: true, stdio: "ignore" });
    helper.unref();
    return { ok: true, status: "self_restart_initiated", service, helperPid: helper.pid, plistPath };
  }
  if (mode === "bootout-bootstrap") return bootoutBootstrapService(service, plistPath, oldPid);
  const kick = runLaunchctl(["kickstart", "-k", `${launchctlDomain()}/${service}`]);
  const newPid = getServicePid(service);
  if (kick.ok) return { ok: true, status: "restarted", method: "kickstart", service, oldPid, newPid };
  const err = `${kick.stderr}
${kick.stdout}`;
  if (/Could not find service|service not loaded/i.test(err)) return bootoutBootstrapService(service, plistPath, oldPid);
  return { ok: false, status: "failed", method: "kickstart", service, oldPid, newPid, error: kick.stderr || kick.stdout || "kickstart failed" };
}
async function waitForAgentReply(sessionKey, previousReply, timeoutMs) { const started = Date.now(); while (Date.now() - started < timeoutMs) { const reply = getLatestAssistantReply(sessionKey); if (reply && reply !== previousReply) return reply; await sleep(2000); } return null; }
function updateAgentStatus(agentId, status, task) {
  try {
    spawn("bash", ["/Users/jarvis/.openclaw/workspace-yoda/scripts/update-agent-status.sh", "--agent", agentId, "--status", status, "--task", task], { stdio: "ignore", detached: true }).unref();
  } catch {}
}


function loadTasks() {
  try {
    if (!existsSync(TASKS_FILE)) { taskState = { tasks: [] }; return; }
    const loaded = JSON.parse(readFileSync(TASKS_FILE, "utf8"));
    taskState = { tasks: Array.isArray(loaded?.tasks) ? loaded.tasks : [] };
    const now = Date.now();
    let changed = false;
    taskState.tasks = taskState.tasks.filter(task => {
      const created = Date.parse(task.createdAt || 0);
      return !Number.isFinite(created) || !task.ttl || now - created <= task.ttl;
    }).map(task => {
      if (task.status === "working" && !task.completedAt) {
        changed = true;
        return { ...task, status: "failed", statusMessage: "MCP server restarted before task completed.", error: "MCP server restarted before task completed.", completedAt: new Date().toISOString(), updatedAt: new Date().toISOString(), childPid: null };
      }
      return task;
    });
    if (changed) persistTasks();
  } catch (e) {
    logLine(`Task state load error: ${e.message}`);
    taskState = { tasks: [] };
  }
}
function persistTasks() {
  const tmp = `${TASKS_FILE}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(taskState, null, 2));
  renameSync(tmp, TASKS_FILE);
}
function publicTask(task) {
  if (!task) return null;
  return {
    taskId: task.taskId,
    status: task.status,
    statusMessage: task.statusMessage,
    createdAt: task.createdAt,
    lastUpdatedAt: task.updatedAt,
    ttl: task.ttl,
    pollInterval: task.pollInterval
  };
}
function assertTaskAccess(task, authContext) {
  return task && task.clientId === (authContext?.clientId || "anonymous");
}
function getTask(taskId) { return taskState.tasks.find(task => task.taskId === taskId) || null; }
function listTasks(filter = {}) {
  const limit = Math.min(Math.max(Number(filter.limit || 20), 1), 100);
  const visible = taskState.tasks
    .filter(task => !filter.clientId || task.clientId === filter.clientId)
    .filter(task => !filter.status || task.status === filter.status)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  const start = filter.cursor ? Math.max(visible.findIndex(task => task.taskId === filter.cursor) + 1, 0) : 0;
  const page = visible.slice(start, start + limit);
  return { tasks: page.map(publicTask), nextCursor: start + limit < visible.length ? page[page.length - 1]?.taskId : undefined };
}
function createTask({ agentId, sessionKey, request, authContext, ttl }) {
  const now = new Date().toISOString();
  const task = {
    taskId: randomUUID(),
    sessionKey,
    agentId,
    request,
    status: "working",
    statusMessage: "The operation is now in progress.",
    createdAt: now,
    updatedAt: now,
    completedAt: null,
    result: null,
    error: null,
    childPid: null,
    clientId: authContext?.clientId || "anonymous",
    authType: authContext?.type || "unknown",
    ttl: Math.min(Number(ttl || TASK_TTL_MS), TASK_TTL_MS),
    pollInterval: TASK_POLL_INTERVAL_MS
  };
  taskState.tasks.push(task);
  persistTasks();
  return task;
}
function updateTask(taskId, patch) {
  const task = getTask(taskId);
  if (!task) return null;
  Object.assign(task, patch, { updatedAt: new Date().toISOString() });
  persistTasks();
  return task;
}
function markRunning(taskId, childPid) { return updateTask(taskId, { status: "working", statusMessage: "The operation is now in progress.", childPid: childPid || null }); }
function markCompleted(taskId, result) { activeTaskChildren.delete(taskId); return updateTask(taskId, { status: "completed", statusMessage: "Task completed successfully.", result, error: null, completedAt: new Date().toISOString(), childPid: null }); }
function markFailed(taskId, error, result) { activeTaskChildren.delete(taskId); return updateTask(taskId, { status: "failed", statusMessage: error?.message || String(error), result: result || null, error: error?.message || String(error), completedAt: new Date().toISOString(), childPid: null }); }
function markCancelled(taskId) { activeTaskChildren.delete(taskId); return updateTask(taskId, { status: "cancelled", statusMessage: "The task was cancelled by request.", completedAt: new Date().toISOString(), childPid: null }); }
function cancelTask(taskId) {
  const task = getTask(taskId);
  if (!task) return null;
  const child = activeTaskChildren.get(taskId);
  if (child) { try { child.kill("SIGKILL"); } catch {} }
  return markCancelled(taskId);
}
function isTaskAugmentedCall(body) {
  if (body?.method !== "tools/call" || body?.params?.name !== "dispatch_agent") return false;
  return !!getTaskParams(body);
}
function getTaskParams(body) {
  return body?.params?.task || body?.params?._meta?.["modelcontextprotocol.io/task"] || body?.params?._meta?.["io.modelcontextprotocol/task"] || body?._meta?.["modelcontextprotocol.io/task"] || body?._meta?.["io.modelcontextprotocol/task"] || null;
}
const DISPATCH_AGENT_TASK_WRAP_THRESHOLD_MS = 50000;
const LONG_RUNNING_DISPATCH_REQUIRES_TASKS_MESSAGE = "Long-running dispatch (timeoutMs > 50000) requires client-side SEP-1686 task support. Your client did not advertise this capability during initialize. Use timeoutMs <= 50000 for synchronous dispatch.";
const TASK_TOOL_REQUIRES_TASKS_MESSAGE = "This tasks_* tool requires client-side SEP-1686 task support. Your client did not advertise this capability during initialize.";
function clientSupportsTasks(capabilities = {}) {
  return !!(capabilities?.tasks || capabilities?.experimental?.tasks || capabilities?.extensions?.["io.modelcontextprotocol/tasks"] || capabilities?.extensions?.["modelcontextprotocol.io/tasks"]);
}
function sessionSupportsTasks(sessionId) {
  return !!(sessionId && clientSupportsTasksBySession.get(sessionId));
}
function isLongDispatchAgentCall(body) {
  if (body?.method !== "tools/call" || body?.params?.name !== "dispatch_agent" || getTaskParams(body)) return false;
  const timeoutMs = Number(body.params?.arguments?.timeoutMs || 30000);
  return Number.isFinite(timeoutMs) && timeoutMs > DISPATCH_AGENT_TASK_WRAP_THRESHOLD_MS;
}
function shouldAutoWrapDispatchAgent(body, sessionId) {
  if (!isLongDispatchAgentCall(body) || !sessionSupportsTasks(sessionId)) return false;
  // Threshold is 50000ms (not the original 120000ms) because Claude.ai has a hardcoded ~60s client-side timeout — see anthropics/claude-code#22542. 50s gives 10s margin.
  return true;
}
function callToolResultFromDispatch(result, taskId) {
  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    isError: !result.ok || undefined,
    _meta: { "io.modelcontextprotocol/related-task": { taskId } }
  };
}
function runEmbeddedAgentForTask(taskRecord, timeoutMs = 60000) {
  const timeoutSec = Math.max(30, Math.ceil(timeoutMs / 1000));
  const { agentId, request } = taskRecord;
  return new Promise((resolve, reject) => {
    const args = ["agent", "--agent", agentId, "-m", request.task, "--json", "--timeout", String(timeoutSec)];
    const child = spawn("openclaw", args, { stdio: ["ignore", "pipe", "pipe"] });
    let settled = false;
    const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(killer); fn(value); };
    const killer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch {}
      finish(reject, new Error(`embedded agent killed after ${timeoutMs + 2000}ms`));
    }, timeoutMs + 2000);
    activeTaskChildren.set(taskRecord.taskId, child);
    markRunning(taskRecord.taskId, child.pid);
    let stdout = "", stderr = "";
    child.stdout.on("data", d => stdout += d.toString());
    child.stderr.on("data", d => stderr += d.toString());
    child.on("error", err => finish(reject, err));
    child.on("close", (code, signal) => {
      if (getTask(taskRecord.taskId)?.status === "cancelled") return finish(resolve, { cancelled: true });
      if (signal || code !== 0) return finish(reject, new Error(stderr.trim() || `embedded agent exited with ${signal || code}`));
      const startIdx = stdout.indexOf('{');
      const endIdx = stdout.lastIndexOf('}');
      if (startIdx < 0 || endIdx < 0) return finish(reject, new Error(stderr.trim() || "embedded agent failed: no JSON output"));
      const jsonStr = stdout.substring(startIdx, endIdx + 1);
      try {
        const parsed = JSON.parse(jsonStr);
        const reply = parsed?.payloads?.[0]?.text || parsed?.meta?.finalAssistantVisibleText || null;
        finish(resolve, { raw: jsonStr, reply });
      } catch (e) {
        finish(reject, new Error("embedded agent JSON parse failed: " + e.message));
      }
    });
  });
}
function startDispatchTask({ args, authContext, taskParams }) {
  const agentId = args.agentId || DEFAULT_AGENT_ID;
  const sessionKey = args.sessionKey || `agent:${agentId}:main`;
  const taskRecord = createTask({ agentId, sessionKey, request: { ...args, agentId, sessionKey }, authContext, ttl: taskParams?.ttl });
  runEmbeddedAgentForTask(taskRecord, args.timeoutMs || 30000).then(fb => {
    if (fb?.cancelled) return;
    const result = { ok: true, taskId: taskRecord.taskId, sessionKey, reply: fb.reply, raw: fb.raw };
    markCompleted(taskRecord.taskId, callToolResultFromDispatch(result, taskRecord.taskId));
  }).catch(error => {
    const result = callToolResultFromDispatch({ ok: false, taskId: taskRecord.taskId, error: error.message }, taskRecord.taskId);
    markFailed(taskRecord.taskId, error, result);
  });
  return taskRecord;
}
function taskCreateResult(task) {
  return { taskId: task.taskId, status: task.status, task: publicTask(task), _meta: { "io.modelcontextprotocol/model-immediate-response": `Task ${task.taskId} accepted. Poll tasks/get, then tasks/result when complete.` } };
}
async function handleTaskRpc(body, authContext, sessionId) {
  const params = body.params || {};
  if (isLongDispatchAgentCall(body) && !sessionSupportsTasks(sessionId)) {
    return { error: { code: -32602, message: LONG_RUNNING_DISPATCH_REQUIRES_TASKS_MESSAGE }, jsonrpc: "2.0", id: body.id ?? null };
  }
  if (isTaskAugmentedCall(body) || shouldAutoWrapDispatchAgent(body, sessionId)) {
    const args = params.arguments || {};
    const taskParams = getTaskParams(body) || { ttl: args.timeoutMs };
    const task = startDispatchTask({ args, authContext, taskParams });
    return { result: taskCreateResult(task), jsonrpc: "2.0", id: body.id ?? null };
  }
  if (body.method === "tasks/get") {
    const task = getTask(params.taskId);
    if (!assertTaskAccess(task, authContext)) return { error: { code: -32602, message: "Task not found" }, jsonrpc: "2.0", id: body.id ?? null };
    return { result: publicTask(task), jsonrpc: "2.0", id: body.id ?? null };
  }
  if (body.method === "tasks/list") {
    return { result: listTasks({ cursor: params.cursor, limit: params.limit, status: params.status, clientId: authContext?.clientId || "anonymous" }), jsonrpc: "2.0", id: body.id ?? null };
  }
  if (body.method === "tasks/cancel") {
    const task = getTask(params.taskId);
    if (!assertTaskAccess(task, authContext)) return { error: { code: -32602, message: "Task not found" }, jsonrpc: "2.0", id: body.id ?? null };
    if (["completed", "failed", "cancelled"].includes(task.status)) return { error: { code: -32602, message: `Cannot cancel task in terminal status '${task.status}'` }, jsonrpc: "2.0", id: body.id ?? null };
    return { result: publicTask(cancelTask(params.taskId)), jsonrpc: "2.0", id: body.id ?? null };
  }
  if (body.method === "tasks/result") {
    const task = getTask(params.taskId);
    if (!assertTaskAccess(task, authContext)) return { error: { code: -32602, message: "Task not found" }, jsonrpc: "2.0", id: body.id ?? null };
    if (!["completed", "failed", "cancelled"].includes(task.status)) return { error: { code: -32001, message: `Task is not complete (status: ${task.status})` }, jsonrpc: "2.0", id: body.id ?? null };
    if (task.status === "cancelled") return { result: { content: [{ type: "text", text: JSON.stringify({ ok: false, taskId: task.taskId, status: "cancelled" }, null, 2) }], isError: true, _meta: { "io.modelcontextprotocol/related-task": { taskId: task.taskId } } }, jsonrpc: "2.0", id: body.id ?? null };
    return { result: task.result, jsonrpc: "2.0", id: body.id ?? null };
  }
  return null;
}
loadTasks();

function requireMcpAuth(req, res) { const token = getBearerToken(req); if (!validateAccessToken(token)) { res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`, ...corsHeaders() }); res.end(JSON.stringify({ error: "unauthorized" })); return false; } return true; }
function runGatewayCall(method, params = {}, expectFinal = false, timeoutMs = 30000, { useCoding = false } = {}) {
  const port = useCoding && OPENCLAW_CODING_PORT ? OPENCLAW_CODING_PORT : OPENCLAW_PORT;
  const token = useCoding && OPENCLAW_CODING_TOKEN ? OPENCLAW_CODING_TOKEN : OPENCLAW_TOKEN;
  return new Promise((resolve, reject) => {
    const args = ["gateway", "call", method, "--timeout", String(timeoutMs), "--params", JSON.stringify(params), "--token", token, "--url", `ws://127.0.0.1:${port}`];
    if (expectFinal) args.splice(3, 0, "--expect-final");
    const child = spawn("openclaw", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "", settled = false;
    const finish = (fn, val) => { if (settled) return; settled = true; clearTimeout(killer); fn(val); };
    const killer = setTimeout(() => { try { child.kill("SIGKILL"); } catch {} finish(reject, new Error(`gateway call killed after ${timeoutMs + 2000}ms (openclaw CLI ignored --timeout)`)); }, timeoutMs + 2000);
    child.stdout.on("data", d => stdout += d.toString());
    child.stderr.on("data", d => stderr += d.toString());
    child.on("error", err => finish(reject, err));
    child.on("close", code => code !== 0 ? finish(reject, new Error(stderr.trim() || stdout.trim() || `gateway call failed (${code})`)) : finish(resolve, (stdout || stderr).trim()));
  });
}

function runEmbeddedAgent(agentId, task, timeoutMs = 60000) {
  const timeoutSec = Math.max(30, Math.ceil(timeoutMs / 1000));
  return new Promise((resolve, reject) => {
    const args = ["agent", "--agent", agentId, "-m", task, "--json", "--timeout", String(timeoutSec)];
    const child = spawn("openclaw", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "", settled = false;
    const finish = (fn, val) => { if (settled) return; settled = true; clearTimeout(killer); fn(val); };
    const killer = setTimeout(() => { try { child.kill("SIGKILL"); } catch {} finish(reject, new Error(`embedded agent killed after ${timeoutMs + 2000}ms`)); }, timeoutMs + 2000);
    child.stdout.on("data", d => stdout += d.toString());
    child.stderr.on("data", d => stderr += d.toString());
    child.on("error", err => finish(reject, err));
    child.on("close", () => {
      const startIdx = stdout.indexOf('{');
      const endIdx = stdout.lastIndexOf('}');
      if (startIdx < 0 || endIdx < 0) return finish(reject, new Error(stderr.trim() || "embedded agent failed: no JSON output"));
      const jsonStr = stdout.substring(startIdx, endIdx + 1);
      try {
        const result = JSON.parse(jsonStr);
        const reply = (result && result.payloads && result.payloads[0] && result.payloads[0].text) || (result && result.meta && result.meta.finalAssistantVisibleText) || null;
        finish(resolve, { raw: jsonStr, reply });
      } catch (e) {
        finish(reject, new Error("embedded agent JSON parse failed: " + e.message));
      }
    });
  });
}

async function dispatchAgentDirect({ agentId = DEFAULT_AGENT_ID, task, sessionKey, waitForReply = true, timeoutMs = 30000 }) {
  const jobId = randomUUID();
  const key = sessionKey || `agent:${agentId}:main`;
  const previousReply = getLatestAssistantReply(key);
  const params = { key, message: task };
  recordJob({ id: jobId, type: "dispatch_agent", status: "running", request: params });
  const taskMatch = task.match(/\b(IFC-\d+)\b/);
  const taskLabel = taskMatch ? taskMatch[1] : "(no-ticket)";
  updateAgentStatus(agentId, "working", taskLabel);
  try {
    let raw, reply = null;
    try {
      // Gateway send only confirms delivery. Keep this short to avoid known openclaw CLI timeout bugs (#59470/#31489).
      raw = await runGatewayCall("sessions.send", params, false, Math.min(timeoutMs, 10000));
      if (!raw.includes("messageSeq")) throw new Error(`gateway response missing messageSeq: ${raw}`);
    } catch (gatewayError) {
      throw new Error(`dispatch_agent message delivery failed via openclaw gateway call (see openclaw#59470): ${gatewayError.message}`);
    }
    reply = waitForReply ? await waitForAgentReply(key, previousReply, timeoutMs) : null;
    const job = recordJob({ id: jobId, type: "dispatch_agent", status: reply || !waitForReply ? "completed" : "started", request: params, raw, reply });
    updateAgentStatus(agentId, "idle", taskLabel);
    return { ok: true, jobId, sessionKey: key, reply, raw: job.raw };
  } catch (error) {
    recordJob({ id: jobId, type: "dispatch_agent", status: "failed", request: params, error: error.message });
    updateAgentStatus(agentId, "idle", taskLabel);
    return { ok: false, jobId, error: error.message };
  }
}

async function directToolCall(name, args = {}) {
  if (name === "list_agents") return { ok: true, agents: listAgentStatuses() };
  if (name === "get_completions") return { ok: true, completions: getCompletions(args.agent) };
  if (name === "get_agent_output") return readLatestAssistantText(args.sessionKey);
  if (name === "jarvis_restart_service") return restartServiceImpl(args.service, args.mode || "kickstart");
  if (name === "dispatch_agent") return dispatchAgentDirect(args);
  return { ok: false, error: `unknown tool: ${name}` };
}

function taskToolResult(result) {
  if (result?.content) return result;
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
}

function getAuthContextFromToolExtra(extra = {}) {
  if (extra.sessionId && authContextsBySession.has(extra.sessionId)) return authContextsBySession.get(extra.sessionId);
  const token = extra.requestInfo?.headers?.authorization?.startsWith("Bearer ") ? extra.requestInfo.headers.authorization.slice(7) : extra.requestInfo?.headers?.["x-api-key"] || "";
  return getAuthContextForToken(token) || { type: "mcp-tool", clientId: "anonymous" };
}

async function callTaskRpcTool(method, params = {}, extra = {}) {
  if (!sessionSupportsTasks(extra.sessionId)) return { content: [{ type: "text", text: TASK_TOOL_REQUIRES_TASKS_MESSAGE }], isError: true };
  const response = await handleTaskRpc({ jsonrpc: "2.0", id: "tool", method, params }, getAuthContextFromToolExtra(extra), extra.sessionId);
  if (response?.error) return { content: [{ type: "text", text: JSON.stringify(response.error, null, 2) }], isError: true };
  return taskToolResult(response.result);
}

function buildServer() {
  const server = new McpServer({ name: "jarvis-openclaw-mcp", version: "0.5.0" });
  server.server.registerCapabilities({ tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } } });
  server.tool("dispatch_agent", `Dispatches a task to an OpenClaw agent (Artoo, ThreePo, etc.). Returns immediately by default with a structured shape ({ok, jobId, ...}); poll get_agent_output to retrieve the agent reply when it lands.

Default behavior is fire-and-forget + poll, which is the recommended pattern for any task expected to take longer than a few seconds. Set waitForReply: true ONLY for tasks expected to complete in under 10 seconds (e.g., smoke tests, PING/PONG health checks). Long-running synchronous calls (60s+) will trigger claude.ai web hardcoded ~60s MCP transport timeout and return an opaque error.

See docs/yoda/dispatch-agent-pattern.md in plat-docs for full rationale and examples.`, { agentId: z.string().default(DEFAULT_AGENT_ID), task: z.string().min(1), sessionKey: z.string().optional(), waitForReply: z.boolean().default(false), timeoutMs: z.number().int().positive().max(120000).default(45000) }, { taskHint: "optional" }, async ({ agentId, task, sessionKey, waitForReply, timeoutMs }) => {
    const result = await dispatchAgentDirect({ agentId, task, sessionKey, waitForReply, timeoutMs });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], isError: !result.ok || undefined };
  });
  server.tool("tasks_get", "Get metadata for a SEP-1686 task by taskId.", { taskId: z.string().min(1) }, async ({ taskId }, extra) => callTaskRpcTool("tasks/get", { taskId }, extra));
  server.tool("tasks_list", "List SEP-1686 tasks visible to this client.", { cursor: z.string().optional() }, async ({ cursor }, extra) => callTaskRpcTool("tasks/list", { cursor }, extra));
  server.tool("tasks_cancel", "Cancel a running SEP-1686 task by taskId.", { taskId: z.string().min(1) }, async ({ taskId }, extra) => callTaskRpcTool("tasks/cancel", { taskId }, extra));
  server.tool("tasks_result", "Return the result for a completed SEP-1686 task by taskId.", { taskId: z.string().min(1) }, async ({ taskId }, extra) => callTaskRpcTool("tasks/result", { taskId }, extra));
  server.tool("dispatch_coding", "Dispatch a coding task directly to the coding gateway (port 18820). Use for direct exec/tool calls on the coding runtime, not for agent session messages.", { method: z.string().default("sessions.send"), params: z.string().describe("JSON-encoded params object").default("{}"), timeoutMs: z.number().int().positive().max(120000).default(30000) }, async ({ method, params: paramsStr, timeoutMs }) => {
    const params = JSON.parse(paramsStr);
    if (!OPENCLAW_CODING_PORT) return { content: [{ type: "text", text: JSON.stringify({ ok: false, error: "Coding gateway not configured" }, null, 2) }], isError: true };
    const jobId = randomUUID();
    recordJob({ id: jobId, type: "dispatch_coding", status: "running", request: { method, params } });
    try {
      const raw = await runGatewayCall(method, params, false, timeoutMs, { useCoding: true });
      recordJob({ id: jobId, type: "dispatch_coding", status: "completed", request: { method, params }, raw });
      return { content: [{ type: "text", text: JSON.stringify({ ok: true, jobId, gateway: "coding:18820", raw }, null, 2) }] };
    } catch (error) {
      recordJob({ id: jobId, type: "dispatch_coding", status: "failed", request: { method, params }, error: error.message });
      return { content: [{ type: "text", text: JSON.stringify({ ok: false, jobId, error: error.message, gateway: "coding:18820" }, null, 2) }], isError: true };
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
  server.tool("jarvis_restart_service", "Restart a Jarvis-supervised LaunchAgent (kickstart preferred; bootout+bootstrap fallback). Allowlist enforced.", { service: z.enum(["com.jarvis.mcp-server", "ai.openclaw.gateway", "ai.openclaw.coding", "com.jarvis.mcp-tunnel", "com.openclaw.yoda-dedup", "com.openclaw.caffeinate"]), mode: z.enum(["kickstart", "bootout-bootstrap"]).optional() }, { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false }, async ({ service, mode }) => {
    const result = restartServiceImpl(service, mode || "kickstart");
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });
  server.tool("get_completions", "Get recent agent completions, optionally filtered by agent.", { agent: z.string().optional() }, async ({ agent }) => {
    const completions = getCompletions(agent);
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, completions }, null, 2) }] };
  });
  server.tool("get_agent_output", "Get the latest assistant reply for an agent session.", { sessionKey: z.string() }, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }, async ({ sessionKey }) => {
    const result = readLatestAssistantText(sessionKey);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });
  return server;
}

async function getTransport(req, parsedBody) {
  const sessionId = req.headers["mcp-session-id"];
  if (sessionId && transports.has(sessionId)) return transports.get(sessionId);
  if (parsedBody && isInitializeRequest(parsedBody)) {
    const server = buildServer();
    const authContext = getAuthContext(req);
    const supportsTasks = clientSupportsTasks(parsedBody.params?.capabilities);
    let transport;
    transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), enableJsonResponse: true, onsessioninitialized: id => { transports.set(id, transport); servers.set(id, server); authContextsBySession.set(id, authContext); clientSupportsTasksBySession.set(id, supportsTasks); logLine(`MCP session initialized: ${id}`); }, onsessionclosed: id => { transports.delete(id); servers.delete(id); authContextsBySession.delete(id); clientSupportsTasksBySession.delete(id); activeSseBySession.delete(id); logLine(`MCP session closed: ${id}`); } });
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
  if (url.pathname === "/healthz") return jsonResponse(res, 200, { ok: true, service: "jarvis-openclaw-mcp", openclawPort: OPENCLAW_PORT, codingPort: OPENCLAW_CODING_PORT || null, codingAgents: Array.from(CODING_GATEWAY_AGENTS), oauth: true });
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
    if (req.method === "POST") { const bodyText = await parseBody(req); const body = bodyText ? JSON.parse(bodyText) : {}; logLine(`POST /mcp body: ${JSON.stringify(body).slice(0, 2000)}`); const authContext = getAuthContext(req); const taskRpc = await handleTaskRpc(body, authContext, sessionId); if (taskRpc) return jsonResponse(res, taskRpc.error ? 400 : 200, taskRpc); if (!sessionId && body?.method === "tools/call") { const result = await directToolCall(body.params?.name, body.params?.arguments || {}); return jsonResponse(res, 200, { result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] }, jsonrpc: "2.0", id: body.id ?? null }); } const transport = await getTransport(req, body); if (!transport) return jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: No valid session ID provided" }, id: null }); await transport.handleRequest(req, res, body); return; }
    return jsonResponse(res, 405, { error: "method not allowed" }, { Allow: "GET, POST, DELETE, OPTIONS" });
  } catch (error) {
    logLine(`MCP handler error: ${error.stack || error.message}`);
    if (sessionId) activeSseBySession.delete(sessionId);
    return jsonResponse(res, 500, { error: error.message });
  }
});

app.listen(PORT, HOST, () => { logLine(`MCP server listening on ${PUBLIC_BASE_URL}/mcp`); });
