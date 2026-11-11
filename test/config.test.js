import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
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

// ─── Second audit R6: pins are required unless explicitly waived ────────────
const FINGERPRINT = "SHA256:" + "A".repeat(43);
const NO_WAIVERS = { ALLOW_UNPINNED_SSH_HOST: "", ALLOW_ANY_AUDIENCE: "", PROXMOX_SSH_HOST_KEY: "", AUTHENTIK_AUDIENCE: "" };

test("without PROXMOX_SSH_HOST_KEY the server refuses to start, and says how to get it", () => {
  const result = loadConfig({ ...NO_WAIVERS, AUTHENTIK_AUDIENCE: "client-id" });
  assert.equal(result.status, 1);
  assert.match(result.error, /PROXMOX_SSH_HOST_KEY/);
  assert.match(result.error, /ssh-keyscan .* \| ssh-keygen -lf -/);
  assert.match(result.error, /ALLOW_UNPINNED_SSH_HOST=yes/);
});

test("the host key is not required when shell tools are off", () => {
  assert.equal(loadConfig({ ...NO_WAIVERS, AUTHENTIK_AUDIENCE: "client-id", SHELL_MODE: "off" }).status, 0);
});

test("without AUTHENTIK_AUDIENCE the server refuses to start, and says where the client ID is", () => {
  const result = loadConfig({ ...NO_WAIVERS, PROXMOX_SSH_HOST_KEY: FINGERPRINT });
  assert.equal(result.status, 1);
  assert.match(result.error, /AUTHENTIK_AUDIENCE/);
  assert.match(result.error, /Client ID/);
  assert.match(result.error, /ALLOW_ANY_AUDIENCE=yes/);
});

test("the audience is not required when auth is off (local testing)", () => {
  const env = { ...NO_WAIVERS, PROXMOX_SSH_HOST_KEY: FINGERPRINT, AUTH_MODE: "off", ALLOW_INSECURE_AUTH: "yes" };
  assert.equal(loadConfig(env).status, 0);
});

test("the server starts with both values set, or with both waived", () => {
  assert.equal(loadConfig({ ...NO_WAIVERS, PROXMOX_SSH_HOST_KEY: FINGERPRINT, AUTHENTIK_AUDIENCE: "client-id" }).status, 0);
  assert.equal(loadConfig({ ...NO_WAIVERS, ALLOW_UNPINNED_SSH_HOST: "yes", ALLOW_ANY_AUDIENCE: "yes" }).status, 0);
  for (const waiver of ["true", "1", "YES "]) {
    assert.equal(loadConfig({ ...NO_WAIVERS, ALLOW_UNPINNED_SSH_HOST: waiver, ALLOW_ANY_AUDIENCE: "yes" }).status, 1, `only "yes" waives: ${waiver}`);
  }
});

test("the host key recovery command scans the configured SSH port", () => {
  const result = loadConfig({ ...NO_WAIVERS, AUTHENTIK_AUDIENCE: "client-id", PROXMOX_SSH_PORT: "2222" });
  assert.equal(result.status, 1);
  assert.match(result.error, /ssh-keyscan -p 2222 pve\.test \| ssh-keygen -lf -/);
});

test(".env.example leaves the pins blank, so its exemptions and waivers work as copied", () => {
  const example = fs.readFileSync(new URL("../.env.example", import.meta.url), "utf8");
  for (const name of ["PROXMOX_SSH_HOST_KEY", "AUTHENTIK_AUDIENCE"]) {
    const line = example.split("\n").find((text) => text.startsWith(`${name}=`));
    assert.equal(line, `${name}=`, `${name} should be blank, not a placeholder`);
  }
});
