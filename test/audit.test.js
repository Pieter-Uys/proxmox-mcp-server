import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { redactSecrets, audit } from "../src/audit.js";
import { SECURITY } from "../src/config.js";

test("redacts secret-looking fields at any depth", () => {
  const input = {
    command: "uptime",
    password: "hunter2",
    nested: { apiToken: "abc", PrivateKey: "-----BEGIN", keep: "visible" },
    list: [{ secret: "x", ok: 1 }],
    token_id: "also redacted",
  };
  assert.deepEqual(redactSecrets(input), {
    command: "uptime",
    password: "[redacted]",
    nested: { apiToken: "[redacted]", PrivateKey: "[redacted]", keep: "visible" },
    list: [{ secret: "[redacted]", ok: 1 }],
    token_id: "[redacted]",
  });
});

test("passes through primitives, null and empty values", () => {
  assert.equal(redactSecrets("text"), "text");
  assert.equal(redactSecrets(5), 5);
  assert.equal(redactSecrets(null), null);
  assert.deepEqual(redactSecrets({}), {});
  assert.deepEqual(redactSecrets([]), []);
});

test("does not mutate its input", () => {
  const input = { password: "hunter2", nested: { secret: "x" } };
  redactSecrets(input);
  assert.deepEqual(input, { password: "hunter2", nested: { secret: "x" } });
});

test("writes one JSON object per line with a timestamp", () => {
  fs.rmSync(SECURITY.auditLog, { force: true });
  audit({ event: "tool_call", tool: "get_status", outcome: "ok" });
  audit({ event: "auth", outcome: "rejected" });
  const lines = fs.readFileSync(SECURITY.auditLog, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(lines.length, 2);
  assert.equal(lines[0].tool, "get_status");
  assert.equal(lines[1].outcome, "rejected");
  assert.ok(!Number.isNaN(Date.parse(lines[0].ts)));
});
