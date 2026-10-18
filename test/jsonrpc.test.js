import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { handleJsonRpc, negotiateProtocolVersion } from "../src/jsonrpc.js";

const initialize = (params) =>
  handleJsonRpc({ jsonrpc: "2.0", id: 1, method: "initialize", params });

test("initialize echoes a protocol version the server supports", async () => {
  for (const version of ["2025-03-26", "2024-11-05"]) {
    const response = await initialize({ protocolVersion: version });
    assert.equal(response.result.protocolVersion, version);
  }
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
