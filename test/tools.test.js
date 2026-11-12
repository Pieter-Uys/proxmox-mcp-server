import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { TOOLS, TOOL_LIST, findTool, startupSetting, callTool } from "../src/tools.js";
import { getPolicyBlockReason } from "../src/policy.js";
import { CONFIG, SECURITY } from "../src/config.js";
import { parseCidrList } from "../src/cidr.js";
import { validateArgs, checkRequiredWhen } from "../src/validate.js";

const blocked = (tool, args) => getPolicyBlockReason(TOOLS[tool], args) !== null;

test("exposes the 12 documented tools", () => {
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
      assert.equal(annotations.destructiveHint, true, `${name}: can require confirmation, so advertise it as destructive`);
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

test("manage_vm: every action needs confirmation, including start", () => {
  for (const action of ["start", "stop", "restart", "shutdown", "delete"]) {
    assert.equal(blocked("manage_vm", { vmid: 101, action }), true, action);
    assert.equal(blocked("manage_vm", { vmid: 101, action, confirm: true }), false, `${action} + confirm`);
  }
  assert.match(getPolicyBlockReason(TOOLS.manage_vm, { vmid: 101, action: "delete" }), /destructive/);
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
  assert.equal(blocked("storage_config", { action: "zfs_create", dataset: "tank/x" }), true);
});

test("backup_vm: every mode needs confirmation, and stop says it shuts the guest down", () => {
  for (const mode of ["snapshot", "suspend", "stop", undefined]) {
    assert.equal(blocked("backup_vm", { vmid: 101, mode }), true, String(mode));
  }
  assert.match(getPolicyBlockReason(TOOLS.backup_vm, { vmid: 101, mode: "stop" }), /shuts the guest down/);
});

// ─── vm_ssh scope and password handling ─────────────────────────────────────
// Runs fn with SECURITY settings temporarily overridden, then restores them.
async function withSecurity(overrides, fn) {
  const previous = Object.fromEntries(Object.keys(overrides).map((key) => [key, SECURITY[key]]));
  Object.assign(SECURITY, overrides);
  try {
    return await fn();
  } finally {
    Object.assign(SECURITY, previous);
  }
}
const FINGERPRINT = "SHA256:" + "A".repeat(43);
const vmSshBlock = (args) => getPolicyBlockReason(TOOLS.vm_ssh, { command: "uptime", ...args });

test("vm_ssh: only literal IP addresses are accepted, never host names", () => {
  assert.equal(vmSshBlock({ ip: "10.0.0.5" }), null);
  assert.equal(vmSshBlock({ ip: "fd00::5" }), null);
  for (const ip of ["vm1.lan", "localhost", "pve.test", "10.0.0.5 ", "10.0.0.5;id", "fe80::1%eth0", ""]) {
    assert.match(vmSshBlock({ ip, confirm: true }), /literal IPv4 or IPv6 address/, ip);
  }
});

test("vm_ssh: VM_SSH_ALLOWED_CIDRS limits targets, and confirm can't override it", async () => {
  await withSecurity({ vmSshAllowedCidrs: parseCidrList("192.168.10.0/24,fd00::/8") }, () => {
    assert.equal(vmSshBlock({ ip: "192.168.10.20" }), null);
    assert.equal(vmSshBlock({ ip: "fd00::20" }), null);
    for (const ip of ["192.168.11.1", "10.0.0.5", "127.0.0.1", "169.254.169.254", "::1"]) {
      assert.match(vmSshBlock({ ip, confirm: true }), /outside VM_SSH_ALLOWED_CIDRS/, ip);
    }
  });
});

test("vm_ssh: IPv4-mapped IPv6 addresses are matched against IPv4 ranges", async () => {
  await withSecurity({ vmSshAllowedCidrs: parseCidrList("192.168.10.0/24") }, () => {
    assert.equal(vmSshBlock({ ip: "::ffff:192.168.10.20" }), null);
    // The mapped form can't be used to reach an address the IPv4 list leaves out.
    for (const ip of ["::ffff:10.0.0.5", "::ffff:127.0.0.1"]) {
      assert.match(vmSshBlock({ ip, confirm: true }), /outside VM_SSH_ALLOWED_CIDRS/, ip);
    }
  });
});

test("vm_ssh: the allowlist also applies in SHELL_MODE=readonly", async () => {
  await withSecurity({ shellMode: "readonly", vmSshAllowedCidrs: parseCidrList("192.168.10.0/24") }, () => {
    assert.match(vmSshBlock({ ip: "10.0.0.5" }), /outside VM_SSH_ALLOWED_CIDRS/);
  });
});

test("vm_ssh: by default only private ranges are reachable", () => {
  for (const ip of ["10.0.0.5", "172.16.4.2", "192.168.1.20", "fd00::5"]) {
    assert.equal(vmSshBlock({ ip }), null, ip);
  }
  for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2001:db8::1", "127.0.0.1", "169.254.169.254"]) {
    assert.match(vmSshBlock({ ip, confirm: true }), /outside VM_SSH_ALLOWED_CIDRS/, ip);
  }
});

test("vm_ssh: the password gate needs a real fingerprint, even when the schema is skipped", async () => {
  // run() re-checks vmSshRefusalReason for direct callTool use, which skips
  // schema validation, so the gate itself must reject empty or odd hostKeys.
  await withSecurity({ vmSshPasswordAuth: "on" }, async () => {
    for (const hostKey of ["", null, 0, false, "SHA256:short", ["SHA256:" + "A".repeat(43)]]) {
      assert.match(
        vmSshBlock({ ip: "10.0.0.5", password: "hunter2", hostKey, confirm: true }) ?? "",
        /only to a pinned host/,
        JSON.stringify(hostKey),
      );
      await assert.rejects(
        callTool("vm_ssh", { ip: "10.0.0.5", command: "uptime", password: "hunter2", hostKey }),
        /only to a pinned host/,
        JSON.stringify(hostKey),
      );
    }
  });
});

test("vm_ssh: hostKey must be an OpenSSH SHA256 fingerprint", () => {
  assert.deepEqual(problems("vm_ssh", { ip: "10.0.0.5", command: "uptime", hostKey: FINGERPRINT }), []);
  for (const hostKey of ["MD5:aa:bb", "SHA256:short", `${FINGERPRINT}; reboot`, "ssh-ed25519 AAAA"]) {
    assert.ok(problems("vm_ssh", { ip: "10.0.0.5", command: "uptime", hostKey }).length, hostKey);
  }
});

test("vm_ssh: a password is refused unless VM_SSH_PASSWORD_AUTH=on", async () => {
  await withSecurity({ vmSshPasswordAuth: "off" }, () => {
    assert.match(vmSshBlock({ ip: "10.0.0.5", password: "hunter2" }), /VM_SSH_PASSWORD_AUTH=off/);
    assert.match(vmSshBlock({ ip: "10.0.0.5", password: "", confirm: true }), /VM_SSH_PASSWORD_AUTH=off/);
    assert.equal(vmSshBlock({ ip: "10.0.0.5" }), null);
  });
  await withSecurity({ vmSshPasswordAuth: "on" }, () => {
    assert.equal(vmSshBlock({ ip: "10.0.0.5", password: "hunter2", hostKey: FINGERPRINT }), null);
    assert.match(vmSshBlock({ ip: "10.0.0.5", password: "hunter2", confirm: true }), /only to a pinned host/);
  });
});

test("vm_ssh: password auth is off by default", () => {
  assert.equal(SECURITY.vmSshPasswordAuth, "off");
});

test("vm_ssh: run() re-checks the limits, so a direct callTool can't skip them", async () => {
  await assert.rejects(callTool("vm_ssh", { ip: "vm1.lan", command: "uptime" }), /literal IPv4 or IPv6/);
  await assert.rejects(
    callTool("vm_ssh", { ip: "10.0.0.5", command: "uptime", password: "x" }),
    /VM_SSH_PASSWORD_AUTH=off/,
  );
});

// ─── One confirmation rule: every non-read action (audit M1) ───────────────
const NON_READ_CALLS = [
  ["manage_vm", { vmid: 101, action: "start" }],
  ["manage_vm", { vmid: 101, action: "restart" }],
  ["manage_vm", { vmid: 101, action: "shutdown" }],
  ["create_lxc", { vmid: 150, hostname: "ct", ostemplate: "local:vztmpl/debian.tar.zst" }],
  ["set_boot_order", { vmid: 101, order: 1 }],
  ["backup_vm", { vmid: 101 }],
  ["backup_vm", { vmid: 101, mode: "snapshot" }],
  ["firewall_rule", { action: "add", level: "cluster", rule: { type: "in", action: "DROP" } }],
  ["network_config", { action: "create", iface: "vmbr1" }],
  ["network_config", { action: "update", iface: "vmbr1", config: {} }],
  ["storage_config", { action: "add", storage: "nfs1", config: {} }],
  ["storage_config", { action: "update", storage: "nfs1", config: { disable: 1 } }],
];
const READ_CALLS = [
  ["get_status", { scope: "cluster" }],
  ["proxmox_api", { method: "GET", path: "/version" }],
  ["firewall_rule", { action: "list", level: "host" }],
  ["network_config", { action: "list" }],
  ["storage_config", { action: "list" }],
  ["storage_config", { action: "zfs_list" }],
  ["host_shell", { command: "uptime" }],
];

test("every call that is not a pure read needs confirm: true", () => {
  for (const [tool, args] of NON_READ_CALLS) {
    assert.equal(blocked(tool, args), true, `${tool} ${JSON.stringify(args)}`);
    assert.equal(blocked(tool, { ...args, confirm: true }), false, `${tool} with confirm`);
  }
});

test("pure reads still run without confirmation", () => {
  for (const [tool, args] of READ_CALLS) {
    assert.equal(blocked(tool, args), false, `${tool} ${JSON.stringify(args)}`);
  }
});

test("a tool advertised as destructive has at least one confirm-gated action", () => {
  for (const { name, annotations } of TOOL_LIST) {
    if (annotations.destructiveHint)
      assert.equal(typeof TOOLS[name].confirmationReason, "function", `${name} is destructive but never asks`);
  }
});

// ─── zfs_create builds only zfs create (audit M2) ───────────────────────────
test("zfs_create runs zfs create on the named dataset, every word quoted", () => {
  const command = TOOLS.storage_config.shellCommand({
    action: "zfs_create",
    dataset: "tank/data",
    properties: { compression: "lz4", "com.example:owner": "ops" },
    parents: true,
  });
  assert.equal(command, "zfs create -p -o 'compression=lz4' -o 'com.example:owner=ops' 'tank/data'");
  assert.equal(TOOLS.storage_config.shellCommand({ action: "zfs_create", dataset: "tank/x" }), "zfs create 'tank/x'");
});

test("zfs_create refuses anything that isn't a dataset name or a plain property", () => {
  for (const dataset of ["tank", "-r rpool/data", "rpool/data -r", "tank/../x", "tank//x", "/tank/x", "tank/x@snap"]) {
    assert.ok(problems("storage_config", { action: "zfs_create", dataset }).length, dataset);
  }
  for (const properties of [{ "-r": "x" }, { "a b": "x" }, { compression: "lz4 -o mountpoint=/" }, { compression: "" }, { quota: 5 }]) {
    const reason = getPolicyBlockReason(TOOLS.storage_config, { action: "zfs_create", dataset: "tank/x", properties, confirm: true });
    assert.match(reason ?? "", /ZFS property/, JSON.stringify(properties));
  }
});

// ─── TOOL_MODE=readonly (audit M3) ──────────────────────────────────────────
test("TOOL_MODE=readonly blocks every confirm-gated call, even with confirm: true", async () => {
  await withSecurity({ toolMode: "readonly" }, () => {
    for (const [tool, args] of [
      ...NON_READ_CALLS,
      ["manage_vm", { vmid: 101, action: "delete" }],
      ["proxmox_api", { method: "DELETE", path: "/nodes/pve/qemu/100" }],
      ["host_shell", { command: "reboot" }],
    ]) {
      assert.match(getPolicyBlockReason(TOOLS[tool], { ...args, confirm: true }) ?? "", /TOOL_MODE=readonly/, tool);
    }
    for (const [tool, args] of READ_CALLS) {
      assert.equal(getPolicyBlockReason(TOOLS[tool], args), null, tool);
    }
  });
});

test("TOOL_MODE defaults to full", () => {
  assert.equal(SECURITY.toolMode, "full");
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
  assert.ok(problems("storage_config", { action: "zfs_create", dataset: "tank/x; rm -rf /" }).length);
  assert.ok(problems("storage_config", { action: "zfs_create", dataset: "tank/$(reboot)" }).length);
  assert.ok(problems("storage_config", { action: "zfs_create", zfsCommand: "destroy -r rpool" }).length, "zfsCommand is gone");
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
  assert.deepEqual(problems("storage_config", { action: "zfs_create", dataset: "tank/data" }), []);
});

test("requiredWhen: action-specific arguments are enforced", () => {
  assert.ok(problems("firewall_rule", { action: "delete", level: "host" }).some((p) => /pos/.test(p)));
  assert.ok(problems("firewall_rule", { action: "list", level: "vm" }).some((p) => /vmid/.test(p)));
  assert.ok(problems("network_config", { action: "update" }).some((p) => /iface/.test(p)));
  assert.ok(problems("storage_config", { action: "zfs_create" }).some((p) => /dataset/.test(p)));
});

test("startupSetting builds the Proxmox startup value", () => {
  assert.equal(startupSetting({ order: 2 }), "order=2");
  assert.equal(startupSetting({ order: 0, upDelay: 30 }), "order=0,up=30");
  assert.equal(startupSetting({ order: 1, downDelay: 10 }), "order=1,down=10");
  assert.equal(startupSetting({ order: 3, upDelay: 30, downDelay: 10 }), "order=3,up=30,down=10");
  assert.equal(startupSetting({ order: 1, upDelay: 0, downDelay: 0 }), "order=1");
});

// ─── Second audit R4: GETs that read guest files or secrets ────────────────
const SENSITIVE_GETS = [
  "/nodes/pve/qemu/100/agent/file-read?file=/etc/shadow",
  "/nodes/pve/qemu/100/agent/get-users",
  "/nodes/pve/qemu/100/agent",
  "/nodes/pve/qemu/100/cloudinit/dump?type=user",
  "/nodes/pve/scan/nfs?server=10.0.0.9",
  "/nodes/pve/scan/iscsi?portal=10.0.0.9",
  "/nodes/pve/storage/local/file-restore/download?volume=x&filepath=/etc",
  "/nodes/pve/storage/local/file-restore/list?volume=x&filepath=/",
  "/nodes/pve/query-url-metadata?url=http://169.254.169.254/latest/meta-data/",
  // Encoded forms decode to the same path, as assertSafeApiPath decodes them.
  "/nodes/pve/qemu/100/%61gent/file-read?file=/etc/shadow",
  "/nodes/pve/qemu/100/cloudinit/%64ump",
];

test("proxmox_api: GETs that read guest files or secrets need confirm: true", () => {
  for (const path of SENSITIVE_GETS) {
    const reason = getPolicyBlockReason(TOOLS.proxmox_api, { method: "GET", path });
    assert.match(reason ?? "", /confirm: true/, path);
    assert.equal(getPolicyBlockReason(TOOLS.proxmox_api, { method: "GET", path, confirm: true }), null, path);
  }
  assert.match(
    getPolicyBlockReason(TOOLS.proxmox_api, { method: "GET", path: SENSITIVE_GETS[0] }),
    /guest agent/,
  );
});

test("proxmox_api: TOOL_MODE=readonly refuses the sensitive GETs", async () => {
  await withSecurity({ toolMode: "readonly" }, () => {
    for (const path of SENSITIVE_GETS) {
      assert.match(getPolicyBlockReason(TOOLS.proxmox_api, { method: "GET", path, confirm: true }) ?? "", /TOOL_MODE=readonly/, path);
    }
  });
});

test("proxmox_api: ordinary GETs still run without confirmation", () => {
  for (const path of [
    "/nodes/pve/qemu/100/status/current",
    "/cluster/resources",
    "/cluster/resources?type=vm",
    "/nodes/pve/qemu/100/config",
    "/nodes/pve/storage/local/content",
    "/version",
    "/nodes/pve/qemu/100/agentless-name", // a segment that only starts with "agent"
  ]) {
    assert.equal(getPolicyBlockReason(TOOLS.proxmox_api, { method: "GET", path }), null, path);
  }
});

// ─── Third audit N4 ─────────────────────────────────────────────────────────
// query-url-metadata (used by "Download from URL") makes the host request the
// URL the caller names, the same class as scan.
test("N4: query-url-metadata says the host will contact the URL", () => {
  const reason = getPolicyBlockReason(TOOLS.proxmox_api, {
    method: "GET",
    path: "/nodes/pve/query-url-metadata?url=http://10.0.0.1:8006/",
  });
  assert.match(reason ?? "", /contact the URL/);
});
