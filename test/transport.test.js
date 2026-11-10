import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { mcpRouter } from "../src/routes/mcp.js";
import { handleJsonRpc } from "../src/jsonrpc.js";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { SECURITY } from "../src/config.js";

// These tests run tools, which write audit entries. Other test files check
// the shared audit log's exact contents in parallel, so use a file of our own.
SECURITY.auditLog = path.join(os.tmpdir(), "proxmox-mcp-test", `transport-${process.pid}.jsonl`);

// A real Express app with the MCP router, on a loopback port. Auth is off for
// these tests (they are about transport, not login), restored afterwards.
async function withApp(fn) {
  const previousAuth = SECURITY.authMode;
  SECURITY.authMode = "off";
  const app = express();
  app.use(mcpRouter);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    return await fn(base);
  } finally {
    server.close();
    SECURITY.authMode = previousAuth;
  }
}
const post = (base, body) =>
  fetch(`${base}/mcp`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

// ─── M9: no batches ─────────────────────────────────────────────────────────
test("a JSON-RPC batch is refused as an invalid request, without running any entry", async () => {
  await withApp(async (base) => {
    const ping = { jsonrpc: "2.0", id: 1, method: "ping" };
    for (const body of [[ping, ping], [ping], []]) {
      const response = await post(base, body);
      assert.equal(response.status, 400, JSON.stringify(body));
      const reply = await response.json();
      assert.equal(reply.error.code, -32600);
      assert.match(reply.error.message, /[Bb]atch/);
    }
  });
});

test("a single request still works", async () => {
  await withApp(async (base) => {
    const reply = await (await post(base, { jsonrpc: "2.0", id: 7, method: "ping" })).json();
    assert.deepEqual(reply, { jsonrpc: "2.0", id: 7, result: {} });
  });
});

// ─── L4: legacy SSE routes are gone ─────────────────────────────────────────
test("the legacy /sse and /messages routes no longer exist", async () => {
  await withApp(async (base) => {
    assert.equal((await fetch(`${base}/sse`)).status, 404);
    assert.equal((await fetch(`${base}/messages`, { method: "POST" })).status, 404);
  });
});

// ─── L9: logs never carry request or response body text ────────────────────
test("request logging names the method, tool and id, never body text", async () => {
  const lines = [];
  const realLog = console.log;
  console.log = (...args) => lines.push(args.join(" "));
  try {
    await withApp(async (base) => {
      await post(base, {
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: { name: "vm_ssh", arguments: { password: "hunter2-secret", ip: "not-an-ip", command: "uptime" } },
      });
    });
  } finally {
    console.log = realLog;
  }
  const output = lines.join("\n");
  assert.doesNotMatch(output, /hunter2-secret/);
  assert.doesNotMatch(output, /not-an-ip/);
  assert.match(output, /tools\/call/);
  assert.match(output, /vm_ssh/);
});

// ─── L6: notifications never get a response ─────────────────────────────────
test("a notification gets no response, even for an unknown method", async () => {
  assert.equal(await handleJsonRpc({ jsonrpc: "2.0", method: "notifications/whatever" }), null);
  assert.equal(await handleJsonRpc({ jsonrpc: "2.0", method: "ping" }), null);
  const reply = await handleJsonRpc({ jsonrpc: "2.0", id: 1, method: "nope" });
  assert.equal(reply.error.code, -32601, "a request with an id still gets Method not found");
});

// ─── L5: tool failures are tool results the model can read ─────────────────
test("a tool that fails while running returns isError, not a JSON-RPC error", async () => {
  // proxmox_api with a path that fails the safety check throws inside run().
  const reply = await handleJsonRpc({
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "proxmox_api", arguments: { method: "GET", path: "/../../etc" } },
  });
  assert.equal(reply.error, undefined);
  assert.equal(reply.result.isError, true);
  assert.match(reply.result.content[0].text, /Invalid Proxmox API path/);
});

test("a malformed JSON body is logged without quoting any of it", async () => {
  const lines = [];
  const realWarn = console.warn;
  console.warn = (...args) => lines.push(args.join(" "));
  try {
    await withApp(async (base) => {
      const response = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: '{"password": "hunter2-secret", oops',
      });
      assert.equal((await response.json()).error.code, -32700);
    });
  } finally {
    console.warn = realWarn;
  }
  assert.doesNotMatch(lines.join("\n"), /hunter2-secret/);
  assert.match(lines.join("\n"), /malformed JSON body/);
});

// ─── L8: nothing runs unrecorded ────────────────────────────────────────────
const failingToolCall = {
  jsonrpc: "2.0",
  id: 11,
  method: "tools/call",
  params: { name: "proxmox_api", arguments: { method: "GET", path: "/../../etc" } },
};

test("a started entry is written before the tool runs", async () => {
  fs.rmSync(SECURITY.auditLog, { force: true });
  await handleJsonRpc(failingToolCall);
  const outcomes = fs.readFileSync(SECURITY.auditLog, "utf8").trim().split("\n").map((line) => JSON.parse(line).outcome);
  assert.deepEqual(outcomes, ["started", "error"]);
});

test("AUDIT_REQUIRED=true refuses to run a tool when the audit log can't be written", async () => {
  const previous = { auditLog: SECURITY.auditLog, auditRequired: SECURITY.auditRequired };
  SECURITY.auditLog = os.tmpdir(); // a directory: every append fails
  try {
    SECURITY.auditRequired = "true";
    const refused = await handleJsonRpc(failingToolCall);
    assert.equal(refused.result.isError, true);
    assert.match(refused.result.content[0].text, /audit log can't be written/);
    SECURITY.auditRequired = "false";
    const ran = await handleJsonRpc(failingToolCall);
    assert.match(ran.result.content[0].text, /Tool failed: Invalid Proxmox API path/, "with false it runs anyway");
  } finally {
    Object.assign(SECURITY, previous);
  }
});

test("AUDIT_REQUIRED defaults to true", () => {
  assert.equal(SECURITY.auditRequired, "true");
});

test("an unknown tool is a JSON-RPC Invalid params error, not a tool result", async () => {
  const reply = await handleJsonRpc({
    jsonrpc: "2.0",
    id: 12,
    method: "tools/call",
    params: { name: "no_such_tool", arguments: {} },
  });
  assert.equal(reply.result, undefined);
  assert.equal(reply.error.code, -32602);
  assert.match(reply.error.message, /Unknown tool: no_such_tool/);
  for (const name of [undefined, "constructor", "__proto__"]) {
    const missing = await handleJsonRpc({ jsonrpc: "2.0", id: 13, method: "tools/call", params: { name } });
    assert.equal(missing.error?.code, -32602, String(name));
  }
});
