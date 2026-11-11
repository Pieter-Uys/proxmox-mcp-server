import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { handleJsonRpc, negotiateProtocolVersion } from "../src/jsonrpc.js";
import { SECURITY } from "../src/config.js";

const initialize = (params) =>
  handleJsonRpc({ jsonrpc: "2.0", id: 1, method: "initialize", params });

test("initialize echoes a protocol version the server supports", async () => {
  for (const version of ["2025-03-26", "2024-11-05"]) {
    const response = await initialize({ protocolVersion: version });
    assert.equal(response.result.protocolVersion, version);
  }
});

test("initialize reports the package.json version", async () => {
  const { version } = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal((await initialize({})).result.serverInfo.version, version);
});

test("initialize answers with the newest supported version otherwise", async () => {
  for (const params of [{ protocolVersion: "2099-01-01" }, { protocolVersion: 5 }, {}, undefined]) {
    const response = await initialize(params);
    assert.equal(response.result.protocolVersion, "2025-03-26", JSON.stringify(params));
  }
  assert.equal(negotiateProtocolVersion("constructor"), "2025-03-26");
});

test("tools/list advertises annotations", async () => {
  const response = await handleJsonRpc({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  for (const tool of response.result.tools) {
    assert.equal(typeof tool.annotations?.readOnlyHint, "boolean", tool.name);
  }
});

// ─── Tool audit fields ──────────────────────────────────────────────────────
test("a malformed argument is reported as invalid and audited, not an internal error", async () => {
  const logFile = path.join(os.tmpdir(), "proxmox-mcp-test", `jsonrpc-invalid-${process.pid}.jsonl`);
  const previousLog = SECURITY.auditLog;
  SECURITY.auditLog = logFile;
  fs.rmSync(logFile, { force: true });
  try {
    const response = await handleJsonRpc({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "vm_ssh", arguments: { ip: { toString: null }, command: "uptime" } },
    });
    assert.equal(response.result.isError, true);
    assert.match(response.result.content[0].text, /Invalid arguments: ip must be of type string/);
    const [entry] = fs.readFileSync(logFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(entry.outcome, "invalid");
  } finally {
    SECURITY.auditLog = previousLog;
    fs.rmSync(logFile, { force: true });
  }
});

