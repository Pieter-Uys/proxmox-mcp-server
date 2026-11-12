// High-yield rig: drive real tool calls through the policy gate and assert on
// what actually reaches the (mock) backends.
//
// The in-process passes test the policy's DECISION. This tests the gap they
// can't see: whether the command string that reaches the host matches what was
// approved, whether command construction (ps env-wrapper, pct quoting, zfs
// build, API path building) can be subverted, and whether a blocked call ever
// touches a backend. The mock backends record the truth; the assertions read it.

import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { startMockSsh, startMockProxmox, ensureCert } from "./mocks.mjs";

const { cert: CERT, key: KEY } = ensureCert();

const ssh = await startMockSsh();
const api = await startMockProxmox(CERT, KEY);

// Point the server's config at the mocks, before importing any src/ module.
Object.assign(process.env, {
  PROXMOX_HOST: "127.0.0.1",
  PROXMOX_PORT: String(api.port),
  PROXMOX_CA_CERT: CERT,
  PROXMOX_TOKEN_ID: "mock@pam!mock",
  PROXMOX_TOKEN_SECRET: "mock-secret",
  PROXMOX_NODE: "pve",
  PROXMOX_SSH_HOST: "127.0.0.1",
  PROXMOX_SSH_PORT: String(ssh.port),
  PROXMOX_SSH_USER: "root",
  MCP_BASE_URL: "https://mcp.test",
  AUTHENTIK_URL: "https://auth.test",
  AUDIT_LOG: path.join(os.tmpdir(), "pmcp-rig", "audit.jsonl"),
  SHELL_MODE: "full",
  TOOL_MODE: "full",
  ALLOW_UNPINNED_SSH_HOST: "yes", // host-key pinning is unit-tested separately
  ALLOW_ANY_AUDIENCE: "yes",
});
delete process.env.PROXMOX_SSH_KEY;

const { handleJsonRpc } = await import("../../src/jsonrpc.js");

let id = 0;
const call = (name, args) =>
  handleJsonRpc({ jsonrpc: "2.0", id: ++id, method: "tools/call", params: { name, arguments: args } }, { user: "rig", ip: "127.0.0.1" });
// handleJsonRpc wraps a refusal as { result: { isError: true, content:[{text}] } }.
const isBlocked = (res) => res?.result?.isError === true;
const blockText = (res) => res?.result?.content?.[0]?.text ?? "";

const failures = [];
const expect = (cond, label) => {
  if (!cond) failures.push(label);
};
const lastSsh = () => ssh.commands.at(-1);
const lastApi = () => api.requests.at(-1);

// ── 1. A readonly command reaches the host byte-for-byte as written ──────────
// The policy checks a trimmed/split view; the host runs the raw string. Prove
// they match for an approved read.
ssh.commands.length = 0;
await call("host_shell", { command: "cat /var/log/syslog" });
expect(lastSsh() === "cat /var/log/syslog", `host_shell readonly: host got ${JSON.stringify(lastSsh())}`);

// ── 2. The ps env-wrapper actually reaches the host ──────────────────────────
// withSafePsEnvironment must prefix the env -u guard on the real command, or
// the ps BSD-mode environment dump defence is cosmetic.
ssh.commands.length = 0;
await call("host_shell", { command: "ps aux" });
expect(
  lastSsh() === "env -u PS_PERSONALITY -u CMD_ENV -u I_WANT_A_BROKEN_PS ps aux",
  `ps env-wrapper: host got ${JSON.stringify(lastSsh())}`,
);

// ── 3. lxc_shell quoting is injection-safe ───────────────────────────────────
// A single quote in an approved command must stay inside the quoted argument
// to pct exec, never break out of it.
ssh.commands.length = 0;
await call("lxc_shell", { vmid: 100, command: "grep pw /etc/app.conf", confirm: true });
const lxc = lastSsh() ?? "";
expect(lxc.startsWith("pct exec 100 -- bash -c "), `lxc_shell shape: ${JSON.stringify(lxc)}`);
expect(!/;|\|\||&&/.test(lxc.replace(/'[^']*'/g, "")), `lxc_shell: metachar outside quotes in ${JSON.stringify(lxc)}`);

// ── 4. A dataset name that could inject is rejected by validation ────────────
// The whole point of structured zfs_create: a crafted dataset must never reach
// the host at all.
ssh.commands.length = 0;
const evilZfs = await call("storage_config", { action: "zfs_create", dataset: "tank/data; zfs destroy -r rpool", confirm: true });
expect(isBlocked(evilZfs), "zfs_create inject: should be blocked by validation");
expect(ssh.commands.length === 0, `zfs_create inject: host received ${JSON.stringify(ssh.commands)}`);

// A legitimate zfs_create builds the exact expected command.
ssh.commands.length = 0;
await call("storage_config", { action: "zfs_create", dataset: "tank/data", properties: { compression: "lz4" }, parents: true, confirm: true });
expect(
  lastSsh() === "zfs create -p -o 'compression=lz4' 'tank/data'",
  `zfs_create build: host got ${JSON.stringify(lastSsh())}`,
);

// ── 5. proxmox_api path traversal never reaches the API ──────────────────────
api.requests.length = 0;
const traversal = await call("proxmox_api", { method: "GET", path: "/../../access/users" });
expect(isBlocked(traversal), "api traversal: should be blocked");
expect(api.requests.length === 0, `api traversal: API received ${JSON.stringify(api.requests)}`);

// An ordinary GET reaches the API under /api2/json unchanged.
api.requests.length = 0;
await call("proxmox_api", { method: "GET", path: "/nodes/pve/qemu/100/status/current" });
expect(lastApi()?.path === "/api2/json/nodes/pve/qemu/100/status/current", `api path: API got ${JSON.stringify(lastApi()?.path)}`);
expect(lastApi()?.method === "GET", `api method: ${lastApi()?.method}`);

// ── 6. A sensitive GET without confirm never reaches the API ─────────────────
api.requests.length = 0;
const agentRead = await call("proxmox_api", { method: "GET", path: "/nodes/pve/qemu/100/agent/file-read?file=/etc/shadow" });
expect(isBlocked(agentRead), "agent file-read: should be blocked without confirm");
expect(api.requests.length === 0, `agent file-read: API received ${JSON.stringify(api.requests)}`);

// ── 7. manage_vm delete: blocked without confirm, exact DELETE with it ───────
api.requests.length = 0;
const del = await call("manage_vm", { vmid: 100, action: "delete", type: "lxc" });
expect(isBlocked(del), "manage_vm delete: blocked without confirm");
expect(api.requests.length === 0, `manage_vm delete: API received ${JSON.stringify(api.requests)}`);

api.requests.length = 0;
await call("manage_vm", { vmid: 100, action: "delete", type: "lxc", confirm: true });
expect(lastApi()?.method === "DELETE" && lastApi()?.path === "/api2/json/nodes/pve/lxc/100", `manage_vm delete path: ${lastApi()?.method} ${lastApi()?.path}`);

// ── 8. A blocked shell command never reaches the host ────────────────────────
ssh.commands.length = 0;
const secret = await call("host_shell", { command: "cat /etc/shadow" });
expect(isBlocked(secret), "cat /etc/shadow: blocked");
expect(ssh.commands.length === 0, `cat /etc/shadow: host received ${JSON.stringify(ssh.commands)}`);
expect(/secrets|approval/i.test(blockText(secret)), "cat /etc/shadow: reason mentions secrets/approval");

// ─── Report ─────────────────────────────────────────────────────────────────
await ssh.close();
await api.close();
console.log(`\nBackend-truth rig: ${id} tool calls, ${8} assertions groups\n`);
if (failures.length) {
  console.log(`!!! ${failures.length} FAILURE(S):`);
  for (const f of failures) console.log(`  ${f}`);
} else {
  console.log("All backend-truth assertions held: approved commands reach the host as written, blocked ones never arrive.");
}
console.log("");
assert.equal(failures.length, 0, `${failures.length} backend-truth failure(s)`);
