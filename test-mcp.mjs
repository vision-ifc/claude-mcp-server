const key = process.env.MCP_API_KEY;

const init = {
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: {
    name: 'dispatch_agent',
    arguments: {
      agentId: 'artoo',
      task: 'Ping from MCP verification. Reply with just PONG.',
      waitForReply: false,
      timeoutMs: 10000
    }
  }
};

const res = await fetch('http://127.0.0.1:8787/mcp', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    authorization: `Bearer ${key}`
  },
  body: JSON.stringify(init)
});

console.log(await res.text());
