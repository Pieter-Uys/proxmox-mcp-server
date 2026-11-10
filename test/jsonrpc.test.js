import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { handleJsonRpc, negotiateProtocolVersion, toolAuditFields } from "../src/jsonrpc.js";
import { CONFIG, SECURITY } from "../src/config.js";

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
test("a community script call is audited with the exact URL and ref it would run", async () => {
  // A file of its own: other test files write the shared audit log in parallel.
  const logFile = path.join(os.tmpdir(), "proxmox-mcp-test", `jsonrpc-${process.pid}.jsonl`);
  const previousLog = SECURITY.auditLog;
  const previousRef = CONFIG.communityScripts.ref;
  SECURITY.auditLog = logFile;
  CONFIG.communityScripts.ref = undefined; // this test is about the unpinned default
  fs.rmSync(logFile, { force: true });
  try {
    const response = await handleJsonRpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "run_community_script", arguments: { script: "pihole" } },
    });
    assert.equal(response.result.isError, true);
    assert.match(response.result.content[0].text, /ProxmoxVE\/main\/ct\/pihole\.sh/);
    const [entry] = fs.readFileSync(logFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(entry.outcome, "blocked");
    assert.equal(entry.scriptUrl, "https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/pihole.sh");
    assert.equal(entry.scriptRef, "main");
    assert.equal(entry.scriptPinned, false);
  } finally {
    SECURITY.auditLog = previousLog;
    CONFIG.communityScripts.ref = previousRef;
    fs.rmSync(logFile, { force: true });
  }
});

test("a malformed script argument is reported as invalid and audited, not an internal error", async () => {
  const logFile = path.join(os.tmpdir(), "proxmox-mcp-test", `jsonrpc-invalid-${process.pid}.jsonl`);
  const previousLog = SECURITY.auditLog;
  SECURITY.auditLog = logFile;
  fs.rmSync(logFile, { force: true });
  try {
    const response = await handleJsonRpc({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "run_community_script", arguments: { script: { toString: null } } },
    });
    assert.equal(response.result.isError, true);
    assert.match(response.result.content[0].text, /Invalid arguments: script must be of type string/);
    const [entry] = fs.readFileSync(logFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(entry.outcome, "invalid");
    assert.equal(entry.scriptUrl, undefined);
  } finally {
    SECURITY.auditLog = previousLog;
    fs.rmSync(logFile, { force: true });
  }
});

test("toolAuditFields is empty for tools without extra fields and for malformed arguments", () => {
  assert.deepEqual(toolAuditFields("get_status", { scope: "cluster" }), {});
  assert.deepEqual(toolAuditFields("no_such_tool", {}), {});
  assert.deepEqual(toolAuditFields("run_community_script", "not an object"), {});
});
