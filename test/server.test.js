import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { jsonRpcErrorHandler } from "../src/routes/middleware.js";

// ─── End-to-end: the real server.js as a child process ──────────────────────
// The other test files load modules in isolation, so nothing there runs
// Express itself: routing, body parsing, error handlers, the rate limiter or
// listen. A major Express update passed CI on that basis (fourth audit, D2).
// These tests start server.js with the throwaway settings from env.js and talk
// to it over HTTP on 127.0.0.1. The working directory is the temp dir, so a
// developer's .env can never be picked up.
const SERVER_JS = fileURLToPath(new URL("../server.js", import.meta.url));
const STARTUP_TIMEOUT_MS = 8000;

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer().once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function spawnServer(env) {
  const child = spawn(process.execPath, [SERVER_JS], {
    cwd: os.tmpdir(),
    env: { ...process.env, MCP_BIND_ADDRESS: "127.0.0.1", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));
  return { child, output: () => output };
}

// Runs the server until it exits on its own. Resolves with its exit code and output.
function runUntilExit(env) {
  const { child, output } = spawnServer(env);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`server did not exit within ${STARTUP_TIMEOUT_MS}ms:\n${output()}`));
    }, STARTUP_TIMEOUT_MS);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, output: output() });
    });
  });
}

// Starts the server and waits for its "running" line. The caller stops it.
async function startServer(env = {}) {
  const port = await freePort();
  const { child, output } = spawnServer({ MCP_PORT: String(port), ...env });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start:\n${output()}`)), STARTUP_TIMEOUT_MS);
    const check = () => {
      if (!/Proxmox MCP running/.test(output())) return;
      clearTimeout(timer);
      resolve();
    };
    child.stdout.on("data", check);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited with ${code}:\n${output()}`));
    });
  });
  const stop = () =>
    new Promise((resolve) => {
      child.removeAllListeners("exit");
      child.once("exit", resolve);
      child.kill("SIGTERM");
    });
  return { base: `http://127.0.0.1:${port}`, output, stop };
}

// Runs `fn` against a fresh server, always stopping it afterwards.
async function withServer(env, fn) {
  const server = await startServer(env);
  try {
    await fn(server);
  } finally {
    await server.stop();
  }
}

const postJson = (base, body, headers = {}) =>
  fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body,
  });

// ─── D1: a failed listen must fail ──────────────────────────────────────────
// Express 5 hands a listen error to the callback instead of throwing (checked
// with express 5.3.0: application.js registers the callback for "error").
test("D1: a port that is already in use exits non-zero and never says running", async () => {
  const blocker = net.createServer();
  await new Promise((resolve) => blocker.listen(0, "127.0.0.1", resolve));
  const { port } = blocker.address();
  try {
    const { code, output } = await runUntilExit({ MCP_PORT: String(port) });
    assert.notEqual(code, 0, output);
    assert.doesNotMatch(output, /Proxmox MCP running/);
    assert.match(output, /EADDRINUSE/);
    assert.match(output, new RegExp(String.raw`127\.0\.0\.1:${port}`));
  } finally {
    blocker.close();
  }
});

// ─── D2: the HTTP surface, over HTTP ────────────────────────────────────────
test("server: health, auth, parse errors, 404 and discovery with AUTH_MODE=enforce", async () => {
  await withServer({}, async ({ base }) => {
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: "ok", tools: 12 });

    const unauthenticated = await postJson(base, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }));
    assert.equal(unauthenticated.status, 401);
    assert.match(unauthenticated.headers.get("www-authenticate") ?? "", /^Bearer /);
    assert.match(unauthenticated.headers.get("www-authenticate") ?? "", /resource_metadata=/);

    const malformed = await postJson(base, "{not json");
    assert.equal(malformed.status, 400);
    assert.equal((await malformed.json()).error.code, -32700);

    const missing = await fetch(`${base}/no-such-path`);
    assert.equal(missing.status, 404);
    assert.deepEqual(await missing.json(), { error: "not_found" });

    const resource = await fetch(`${base}/.well-known/oauth-protected-resource`);
    assert.equal(resource.status, 200);
    assert.deepEqual(await resource.json(), {
      resource: "https://mcp.test",
      authorization_servers: ["https://auth.test"],
      scopes_supported: ["openid", "profile", "email", "offline_access"],
    });

    const preflight = await fetch(`${base}/mcp`, { method: "OPTIONS" });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), "*");
  });
});

test("server: batches are refused and a body-less POST is an invalid request", async () => {
  await withServer({ AUTH_MODE: "off", ALLOW_INSECURE_AUTH: "yes" }, async ({ base }) => {
    const batch = await postJson(base, JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "ping" }]));
    assert.equal(batch.status, 400);
    assert.equal((await batch.json()).error.code, -32600);

    // Express 5 leaves req.body undefined when no parser matched.
    const bodyless = await fetch(`${base}/mcp`, { method: "POST" });
    assert.equal((await bodyless.json()).error.code, -32600);

    const ping = await postJson(base, JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" }));
    assert.equal(ping.status, 200);
    assert.deepEqual(await ping.json(), { jsonrpc: "2.0", id: 7, result: {} });

    const notification = await postJson(base, JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
    assert.equal(notification.status, 202);
  });
});

test("server: the rate limiter answers 429 in the JSON error shape, and never limits /health", async () => {
  await withServer({ RATE_LIMIT_PER_MINUTE: "2" }, async ({ base, output }) => {
    const discovery = () => fetch(`${base}/.well-known/oauth-protected-resource`);
    assert.equal((await discovery()).status, 200);
    assert.equal((await discovery()).status, 200);
    const limited = await discovery();
    assert.equal(limited.status, 429);
    assert.deepEqual(await limited.json(), { error: "rate_limited" });
    assert.equal((await fetch(`${base}/health`)).status, 200);
    // express-rate-limit 8 reports configuration problems at runtime as
    // ERR_ERL_* warnings rather than failing; there must be none.
    assert.doesNotMatch(output(), /ERR_ERL_/);
  });
});

// ─── D2: error handler status codes ─────────────────────────────────────────
// Express 5's res.status() throws on a code that isn't an integer from 100 to
// 999, so an error carrying an odd status must not reach it unchecked.
test("error handlers answer 500 when an error carries an unusable status", () => {
  for (const status of [1000, 99, 4.5, "teapot", -1]) {
    let sent;
    const res = {
      headersSent: false,
      status(code) {
        if (!Number.isInteger(code) || code < 100 || code > 999) throw new RangeError(`invalid status ${code}`);
        sent = code;
        return this;
      },
      json() {
        return this;
      },
    };
    const error = Object.assign(new Error("odd"), { status });
    jsonRpcErrorHandler(error, { path: "/mcp" }, res, () => {});
    assert.equal(sent, 500, `status ${status}`);
  }
});

// ─── D4: the OAuth proxy forwards parameters unchanged ──────────────────────
// URLSearchParams(req.query) joins a repeated parameter with commas
// (resource=a&resource=b became resource=a%2Cb), and the extended body parser
// turned a[b]=c into a=[object Object]. RFC 8707 lets resource repeat.
const OAUTH_QUERY = "response_type=code&client_id=c1&resource=https%3A%2F%2Fa&resource=https%3A%2F%2Fb&a%5Bb%5D=c&state=s";

test("D4: /authorize forwards the query string exactly as sent", async () => {
  await withServer({}, async ({ base }) => {
    const response = await fetch(`${base}/authorize?${OAUTH_QUERY}`, { redirect: "manual" });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), `https://auth.test/application/o/authorize/?${OAUTH_QUERY}`);
  });
});

test("D4: /token forwards the form body exactly as sent", async () => {
  const received = [];
  const authentik = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      received.push({ path: req.url, type: req.headers["content-type"], body });
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ access_token: "t", token_type: "Bearer" }));
    });
  });
  await new Promise((resolve) => authentik.listen(0, "127.0.0.1", resolve));
  const authentikUrl = `http://127.0.0.1:${authentik.address().port}`;
  try {
    await withServer({ AUTHENTIK_URL: authentikUrl }, async ({ base }) => {
      const form = "grant_type=authorization_code&code=x&resource=https%3A%2F%2Fa&resource=https%3A%2F%2Fb&a%5Bb%5D=c";
      const response = await fetch(`${base}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form,
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { access_token: "t", token_type: "Bearer" });
      assert.deepEqual(received, [
        { path: "/application/o/token/", type: "application/x-www-form-urlencoded", body: form },
      ]);

      // OAuth token requests are form-encoded (RFC 6749 section 4.1.3);
      // anything else is refused here rather than re-encoded.
      const asJson = await fetch(`${base}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ grant_type: "authorization_code" }),
      });
      assert.equal(asJson.status, 400);
      assert.equal((await asJson.json()).error, "invalid_request");
      assert.equal(received.length, 1, "nothing else reached Authentik");
    });
  } finally {
    authentik.close();
  }
});
