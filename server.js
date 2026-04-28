import { randomBytes, randomUUID, createHash } from "node:crypto";
import http from "node:http";
import { appendFileSync, readFileSync, existsSync, writeFileSync, readdirSync, renameSync } from "node:fs";
import { spawn } from "node:child_process";
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
function listAgentStatuses() { if (!existsSync(AGENT_STATUS_DIR)) return []; return readdirSync(AGENT_STATUS_DIR).filter(name => name.endsWith('.json')).map(name => readJsonFile(`${AGENT_STATUS_DIR}/${name}`, null)).filter(Boolean); }
function getCompletions(agent) { const completions = readJsonFile(AGENT_COMPLETIONS_FILE, []); const filtered = agent ? completions.filter(entry => entry?.agent === agent) : completions; return filtered.sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime()); }
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
function shouldAutoWrapDispatchAgent(body) {
  if (body?.method !== "tools/call" || body?.params?.name !== "dispatch_agent" || getTaskParams(body)) return false;
  const timeoutMs = Number(body.params?.arguments?.timeoutMs || 30000);
  return Number.isFinite(timeoutMs) && timeoutMs > 50000;
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
async function handleTaskRpc(body, authContext) {
  const params = body.params || {};
  if (isTaskAugmentedCall(body) || shouldAutoWrapDispatchAgent(body)) {
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
      raw = await runGatewayCall("sessions.send", params, false, Math.min(timeoutMs, 30000));
      reply = waitForReply ? await waitForAgentReply(key, previousReply, timeoutMs) : null;
    } catch (gatewayError) {
      if (waitForReply) {
        const fb = await runEmbeddedAgent(agentId, task, timeoutMs);
        raw = fb.raw;
        reply = fb.reply;
      } else {
        const fb = await runEmbeddedAgent(agentId, task, timeoutMs);
        raw = fb.raw;
        reply = null;
      }
    }
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
  if (name === "get_agent_output") return { ok: true, sessionKey: args.sessionKey, reply: getLatestAssistantReply(args.sessionKey) };
  if (name === "dispatch_agent") return dispatchAgentDirect(args);
  return { ok: false, error: `unknown tool: ${name}` };
}

function taskToolResult(result) {
  if (result?.content) return result;
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
}

async function callTaskRpcTool(method, params = {}) {
  const response = await handleTaskRpc({ jsonrpc: "2.0", id: "tool", method, params }, { type: "mcp-tool", clientId: "anonymous" });
  if (response?.error) return { content: [{ type: "text", text: JSON.stringify(response.error, null, 2) }], isError: true };
  return taskToolResult(response.result);
}

function buildServer() {
  const server = new McpServer({ name: "jarvis-openclaw-mcp", version: "0.5.0" });
  server.server.registerCapabilities({ tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } } });
  server.tool("dispatch_agent", "Dispatch a task to an OpenClaw agent/sub-agent. All session dispatches go through the main gateway (18789) where agent sessions live.", { agentId: z.string().default(DEFAULT_AGENT_ID), task: z.string().min(1), sessionKey: z.string().optional(), waitForReply: z.boolean().default(true), timeoutMs: z.number().int().positive().max(1800000).default(30000) }, { taskHint: "optional" }, async ({ agentId, task, sessionKey, waitForReply, timeoutMs }) => {
    if (timeoutMs > 50000) {
      const taskRecord = startDispatchTask({ args: { agentId, task, sessionKey, waitForReply, timeoutMs }, authContext: { type: "mcp-tool", clientId: "anonymous" }, taskParams: { ttl: timeoutMs } });
      return taskToolResult(taskCreateResult(taskRecord));
    }
    const result = await dispatchAgentDirect({ agentId, task, sessionKey, waitForReply, timeoutMs });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], isError: !result.ok || undefined };
  });
  server.tool("tasks_get", "Get metadata for a SEP-1686 task by taskId.", { taskId: z.string().min(1) }, async ({ taskId }) => callTaskRpcTool("tasks/get", { taskId }));
  server.tool("tasks_list", "List SEP-1686 tasks visible to this client.", { cursor: z.string().optional() }, async ({ cursor }) => callTaskRpcTool("tasks/list", { cursor }));
  server.tool("tasks_cancel", "Cancel a running SEP-1686 task by taskId.", { taskId: z.string().min(1) }, async ({ taskId }) => callTaskRpcTool("tasks/cancel", { taskId }));
  server.tool("tasks_result", "Return the result for a completed SEP-1686 task by taskId.", { taskId: z.string().min(1) }, async ({ taskId }) => callTaskRpcTool("tasks/result", { taskId }));
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
    if (req.method === "POST") { const bodyText = await parseBody(req); const body = bodyText ? JSON.parse(bodyText) : {}; logLine(`POST /mcp body: ${JSON.stringify(body).slice(0, 2000)}`); const authContext = getAuthContext(req); const taskRpc = await handleTaskRpc(body, authContext); if (taskRpc) return jsonResponse(res, taskRpc.error ? 400 : 200, taskRpc); if (!sessionId && body?.method === "tools/call") { const result = await directToolCall(body.params?.name, body.params?.arguments || {}); return jsonResponse(res, 200, { result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] }, jsonrpc: "2.0", id: body.id ?? null }); } const transport = await getTransport(req, body); if (!transport) return jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: No valid session ID provided" }, id: null }); await transport.handleRequest(req, res, body); return; }
    return jsonResponse(res, 405, { error: "method not allowed" }, { Allow: "GET, POST, DELETE, OPTIONS" });
  } catch (error) {
    logLine(`MCP handler error: ${error.stack || error.message}`);
    if (sessionId) activeSseBySession.delete(sessionId);
    return jsonResponse(res, 500, { error: error.message });
  }
});

app.listen(PORT, HOST, () => { logLine(`MCP server listening on ${PUBLIC_BASE_URL}/mcp`); });
