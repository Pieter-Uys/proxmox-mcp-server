import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { TOOLS, TOOL_LIST, findTool } from "../src/tools.js";
import { getPolicyBlockReason } from "../src/policy.js";
import { validateArgs, checkRequiredWhen } from "../src/validate.js";

const blocked = (tool, args) => getPolicyBlockReason(TOOLS[tool], args) !== null;

test("exposes the 13 documented tools", () => {
  assert.deepEqual(TOOL_LIST.map((tool) => tool.name).sort(), [
    "backup_vm",
    "create_lxc",
    "firewall_rule",
    "get_status",
    "host_shell",
    "lxc_shell",
    "manage_vm",
    "network_config",
    "proxmox_api",
    "run_community_script",
    "set_boot_order",
    "storage_config",
    "vm_ssh",
  ]);
});

test("tools that can require confirmation advertise a boolean confirm argument", () => {
  for (const { name, inputSchema } of TOOL_LIST) {
    const canRequireConfirmation = Boolean(TOOLS[name].confirmationReason);
    assert.equal(
      inputSchema.properties.confirm?.type === "boolean",
      canRequireConfirmation,
      `${name}: confirm argument should be advertised exactly when confirmation can be required`,
    );
  }
});

test("every advertised tool declares all four annotation hints as booleans", () => {
  const hints = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];
  for (const { name, annotations } of TOOL_LIST) {
    assert.deepEqual(Object.keys(annotations ?? {}).sort(), [...hints].sort(), name);
    for (const hint of hints) {
      assert.equal(typeof annotations[hint], "boolean", `${name}.${hint}`);
    }
  }
});

test("annotations agree with each tool's policy", () => {
  for (const { name, annotations } of TOOL_LIST) {
    const tool = TOOLS[name];
    if (annotations.readOnlyHint) {
      assert.equal(annotations.destructiveHint, false, `${name}: read-only cannot be destructive`);
      assert.equal(tool.confirmationReason, undefined, `${name}: read-only tool cannot require confirmation`);
      assert.equal(tool.shellCommand, undefined, `${name}: read-only tool cannot run shell commands`);
    }
    // Anything that can require confirm: true or run a shell command must not claim to be read-only.
    if (tool.confirmationReason || tool.shellCommand) {
      assert.equal(annotations.readOnlyHint, false, `${name}: can change state, so not read-only`);
    }
  }
});

test("findTool does not resolve inherited object properties", () => {
  assert.ok(findTool("host_shell"));
  for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
    assert.equal(findTool(name), undefined, name);
  }
});

// ─── Which calls need confirm: true ─────────────────────────────────────────
test("proxmox_api: only GET runs without confirmation", () => {
  assert.equal(blocked("proxmox_api", { method: "GET", path: "/version" }), false);
  for (const method of ["POST", "PUT", "DELETE"]) {
    assert.equal(blocked("proxmox_api", { method, path: "/x" }), true, method);
    assert.equal(blocked("proxmox_api", { method, path: "/x", confirm: true }), false, `${method} + confirm`);
  }
});

test("manage_vm: stop and delete are destructive, start is not", () => {
  assert.equal(blocked("manage_vm", { vmid: 101, action: "start" }), false);
  assert.equal(blocked("manage_vm", { vmid: 101, action: "stop" }), true);
  assert.equal(blocked("manage_vm", { vmid: 101, action: "delete" }), true);
  assert.equal(blocked("manage_vm", { vmid: 101, action: "delete", confirm: true }), false);
});

test("firewall_rule: delete needs confirmation, list does not", () => {
  assert.equal(blocked("firewall_rule", { action: "list", level: "host" }), false);
  assert.equal(blocked("firewall_rule", { action: "delete", level: "host", pos: 1 }), true);
});

test("network_config: delete and apply need confirmation", () => {
  assert.equal(blocked("network_config", { action: "list" }), false);
  assert.equal(blocked("network_config", { action: "delete", iface: "vmbr1" }), true);
  assert.equal(blocked("network_config", { action: "apply" }), true);
});

test("storage_config: delete and zfs_create need confirmation", () => {
  assert.equal(blocked("storage_config", { action: "list" }), false);
  assert.equal(blocked("storage_config", { action: "zfs_list" }), false);
  assert.equal(blocked("storage_config", { action: "delete", storage: "nfs1" }), true);
  assert.equal(blocked("storage_config", { action: "zfs_create", zfsCommand: "create tank/x" }), true);
});

test("backup_vm: only mode stop needs confirmation", () => {
  assert.equal(blocked("backup_vm", { vmid: 101, mode: "snapshot" }), false);
  assert.equal(blocked("backup_vm", { vmid: 101, mode: "stop" }), true);
});

test("run_community_script always needs confirmation", () => {
  assert.equal(blocked("run_community_script", { script: "pihole" }), true);
  assert.equal(blocked("run_community_script", { script: "pihole", confirm: true }), false);
});

test("read-only tools never need confirmation", () => {
  assert.equal(blocked("get_status", { scope: "cluster" }), false);
});

// ─── Argument validation against the real schemas ───────────────────────────
const problems = (tool, args) => [
  ...validateArgs(TOOL_LIST.find((t) => t.name === tool).inputSchema, args),
  ...checkRequiredWhen(TOOLS[tool].requiredWhen, args),
];

test("rejects values that could break out of shell commands or API paths", () => {
  assert.ok(problems("manage_vm", { vmid: 101, action: "start", node: "pve; reboot" }).length);
  assert.ok(problems("manage_vm", { vmid: 101, action: "start", node: "../etc" }).length);
  assert.ok(problems("storage_config", { action: "update", storage: "../../etc" }).length);
  assert.ok(problems("storage_config", { action: "zfs_create", zfsCommand: "create tank/x; rm -rf /" }).length);
  assert.ok(problems("storage_config", { action: "zfs_create", zfsCommand: "create $(reboot)" }).length);
  assert.ok(problems("run_community_script", { script: "pihole; reboot" }).length);
  assert.ok(problems("run_community_script", { script: "../evil" }).length);
});

test("rejects out-of-range ids, unknown actions and unknown arguments", () => {
  assert.ok(problems("manage_vm", { vmid: 99, action: "start" }).length, "vmid below 100");
  assert.ok(problems("manage_vm", { vmid: 101.5, action: "start" }).length, "non-integer vmid");
  assert.ok(problems("manage_vm", { vmid: 101, action: "explode" }).length, "unknown action");
  assert.ok(problems("manage_vm", { vmid: 101, action: "start", sneaky: true }).length, "unknown argument");
  assert.ok(problems("proxmox_api", { method: "PATCH", path: "/x" }).length, "unknown method");
});

test("accepts well-formed calls", () => {
  assert.deepEqual(problems("manage_vm", { vmid: 101, action: "start", type: "lxc", node: "pve" }), []);
  assert.deepEqual(problems("proxmox_api", { method: "GET", path: "/version" }), []);
  assert.deepEqual(problems("storage_config", { action: "zfs_create", zfsCommand: "create tank/data" }), []);
});

test("requiredWhen: action-specific arguments are enforced", () => {
  assert.ok(problems("firewall_rule", { action: "delete", level: "host" }).some((p) => /pos/.test(p)));
  assert.ok(problems("firewall_rule", { action: "list", level: "vm" }).some((p) => /vmid/.test(p)));
  assert.ok(problems("network_config", { action: "update" }).some((p) => /iface/.test(p)));
  assert.ok(problems("storage_config", { action: "zfs_create" }).some((p) => /zfsCommand/.test(p)));
});
