import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

// src/config.js reads the environment once at import and exits on bad
// settings, so each case loads it in a child process of its own.
const CONFIG_URL = new URL("../src/config.js", import.meta.url).href;

function loadConfig(env) {
  const script = `const { CONFIG } = await import(${JSON.stringify(CONFIG_URL)}); console.log(CONFIG.server.bindAddress);`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { ...process.env, AUTH_MODE: "", ALLOW_INSECURE_AUTH: "", MCP_BIND_ADDRESS: "", ...env },
    encoding: "utf8",
  });
  return { status: child.status, bindAddress: child.stdout.trim(), error: child.stderr };
}

test("enforce mode listens on all interfaces by default, or on MCP_BIND_ADDRESS", () => {
  assert.deepEqual(loadConfig({}).bindAddress, "0.0.0.0");
  assert.deepEqual(loadConfig({ MCP_BIND_ADDRESS: "10.0.0.2" }).bindAddress, "10.0.0.2");
});

test("AUTH_MODE=log or off refuses to start without ALLOW_INSECURE_AUTH=yes", () => {
  for (const mode of ["log", "off"]) {
    const result = loadConfig({ AUTH_MODE: mode });
    assert.equal(result.status, 1, mode);
    assert.match(result.error, /ALLOW_INSECURE_AUTH=yes/, mode);
    assert.equal(loadConfig({ AUTH_MODE: mode, ALLOW_INSECURE_AUTH: "true" }).status, 1, `${mode}: only "yes" counts`);
  }
});

test("insecure auth with the opt-in listens on loopback only", () => {
  assert.equal(loadConfig({ AUTH_MODE: "off", ALLOW_INSECURE_AUTH: "yes" }).bindAddress, "127.0.0.1");
  assert.equal(loadConfig({ AUTH_MODE: "log", ALLOW_INSECURE_AUTH: "yes", MCP_BIND_ADDRESS: "::1" }).bindAddress, "::1");
  const exposed = loadConfig({ AUTH_MODE: "off", ALLOW_INSECURE_AUTH: "yes", MCP_BIND_ADDRESS: "0.0.0.0" });
  assert.equal(exposed.status, 1);
  assert.match(exposed.error, /only listens on loopback/);
});

test("MCP_BIND_ADDRESS must be an IP address", () => {
  const result = loadConfig({ MCP_BIND_ADDRESS: "example.com" });
  assert.equal(result.status, 1);
  assert.match(result.error, /must be an IP address/);
});
