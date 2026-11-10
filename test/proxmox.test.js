import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { assertSafeApiPath, proxmoxRequest, sendRequest } from "../src/proxmox.js";

test("assertSafeApiPath accepts the paths the tools build", () => {
  for (const path of [
    "/version",
    "/nodes/pve/qemu/100/status/current",
    "/cluster/resources?type=vm",
    "/access/users/root@pam",
    "/storage/local:iso",
    "/nodes/pve/lxc/101/firewall/rules/3",
    "/nodes/pve/storage/my.store-1/content",
  ]) {
    assert.doesNotThrow(() => assertSafeApiPath(path), path);
  }
});

test("assertSafeApiPath rejects paths that could leave /api2/json", () => {
  for (const path of [
    "",
    "nodes",
    "//evil.test/x",
    "/../etc",
    "/nodes/../../x",
    "/nodes/./x",
    "/%2e%2e/x",
    "/%2E%2E/x",
    "/nodes/a%2fb",
    "/nodes/a%5cb",
    "/nodes\\x",
    "/nodes/x#frag",
    "/nodes/x y",
    "/nodes/x\nHost: evil",
    "/nodes/%zz",
    undefined,
    42,
  ]) {
    assert.throws(() => assertSafeApiPath(path), /Invalid Proxmox API path/, String(path));
  }
});

test("proxmoxRequest refuses an unsafe path before sending anything", async () => {
  await assert.rejects(proxmoxRequest("GET", "/../x"), /Invalid Proxmox API path/);
});

// ─── M10: timeout and response size cap ─────────────────────────────────────
// A plain HTTP server on loopback stands in for Proxmox; sendRequest takes the
// request function, so no TLS or real host is involved.
async function withServer(handler, fn) {
  const server = http.createServer(handler);
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const url = new URL(`http://127.0.0.1:${server.address().port}/api2/json/version`);
  try {
    return await fn(url);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
}
const send = (url, limits) => sendRequest({ url, options: { method: "GET" }, payload: null }, { request: http.request, ...limits });

test("a Proxmox call that stalls fails after the timeout", async () => {
  await withServer(
    () => {}, // never answers
    async (url) => {
      const started = Date.now();
      await assert.rejects(send(url, { timeoutMs: 200 }), /did not answer within 0.2s/);
      assert.ok(Date.now() - started < 2000);
    },
  );
});

test("a Proxmox reply that trickles in past the deadline also fails", async () => {
  await withServer(
    (req, res) => {
      res.writeHead(200);
      const timer = setInterval(() => res.write("x"), 50);
      res.on("close", () => clearInterval(timer));
    },
    async (url) => {
      await assert.rejects(send(url, { timeoutMs: 300 }), /did not answer/);
    },
  );
});

test("a Proxmox reply over the size cap fails with advice to narrow the query", async () => {
  await withServer(
    (req, res) => res.end("x".repeat(5000)),
    async (url) => {
      await assert.rejects(send(url, { maxBytes: 1000 }), /larger than 1000 bytes.*Narrow the query/);
      assert.deepEqual(await send(url, { maxBytes: 5000 }), { status: 200, text: "x".repeat(5000) });
    },
  );
});
