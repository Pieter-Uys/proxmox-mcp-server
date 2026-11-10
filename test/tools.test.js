import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { TOOLS, TOOL_LIST, findTool, startupSetting, callTool, communityScriptSource } from "../src/tools.js";
import { getPolicyBlockReason } from "../src/policy.js";
import { CONFIG, SECURITY } from "../src/config.js";
import { parseCidrList } from "../src/cidr.js";
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

test("vm_ssh: the allowlist also applies in SHELL_MODE=readonly", async () => {
  await withSecurity({ shellMode: "readonly", vmSshAllowedCidrs: parseCidrList("192.168.10.0/24") }, () => {
    assert.match(vmSshBlock({ ip: "10.0.0.5" }), /outside VM_SSH_ALLOWED_CIDRS/);
  });
});

test("vm_ssh: with no allowlist, any literal address is accepted (behaviour unchanged)", async () => {
  await withSecurity({ vmSshAllowedCidrs: null }, () => {
    assert.equal(vmSshBlock({ ip: "8.8.8.8" }), null);
  });
});

test("vm_ssh: a password is refused unless VM_SSH_PASSWORD_AUTH=on", async () => {
  await withSecurity({ vmSshPasswordAuth: "off" }, () => {
    assert.match(vmSshBlock({ ip: "10.0.0.5", password: "hunter2" }), /VM_SSH_PASSWORD_AUTH=off/);
    assert.match(vmSshBlock({ ip: "10.0.0.5", password: "", confirm: true }), /VM_SSH_PASSWORD_AUTH=off/);
    assert.equal(vmSshBlock({ ip: "10.0.0.5" }), null);
  });
  await withSecurity({ vmSshPasswordAuth: "on" }, () => {
    assert.equal(vmSshBlock({ ip: "10.0.0.5", password: "hunter2" }), null);
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

// ─── Community scripts: pinned ref ──────────────────────────────────────────
const SCRIPTS_BASE = "https://raw.githubusercontent.com/community-scripts/ProxmoxVE";

test("communityScriptSource uses main when no ref is pinned", () => {
  assert.deepEqual(communityScriptSource("pihole", undefined), {
    ref: "main",
    pinned: false,
    url: `${SCRIPTS_BASE}/main/ct/pihole.sh`,
  });
});

test("communityScriptSource uses the pinned commit or tag in place of main", () => {
  const sha = "0123456789abcdef0123456789abcdef01234567";
  assert.deepEqual(communityScriptSource("pihole", sha), {
    ref: sha,
    pinned: true,
    url: `${SCRIPTS_BASE}/${sha}/ct/pihole.sh`,
  });
  assert.equal(communityScriptSource("nextcloud", "v2024.11.01").url, `${SCRIPTS_BASE}/v2024.11.01/ct/nextcloud.sh`);
});

test("run_community_script: the command and confirmation name the exact URL and ref", async () => {
  const previous = CONFIG.communityScripts.ref;
  try {
    CONFIG.communityScripts.ref = undefined;
    const tool = TOOLS.run_community_script;
    assert.equal(tool.shellCommand({ script: "pihole" }), `bash -c "$(curl -fsSL ${SCRIPTS_BASE}/main/ct/pihole.sh)"`);
    const unpinned = getPolicyBlockReason(tool, { script: "pihole" });
    assert.match(unpinned, new RegExp(`${SCRIPTS_BASE}/main/ct/pihole\\.sh`));
    assert.match(unpinned, /unpinned branch.*COMMUNITY_SCRIPTS_REF/);
    assert.deepEqual(tool.auditFields({ script: "pihole" }), {
      scriptUrl: `${SCRIPTS_BASE}/main/ct/pihole.sh`,
      scriptRef: "main",
      scriptPinned: false,
    });

    CONFIG.communityScripts.ref = "v1.2.3";
    assert.equal(tool.shellCommand({ script: "pihole" }), `bash -c "$(curl -fsSL ${SCRIPTS_BASE}/v1.2.3/ct/pihole.sh)"`);
    const pinned = getPolicyBlockReason(tool, { script: "pihole" });
    assert.match(pinned, /v1\.2\.3\/ct\/pihole\.sh.*pinned to ref v1\.2\.3/);
    assert.equal(tool.auditFields({ script: "pihole" }).scriptPinned, true);
  } finally {
    CONFIG.communityScripts.ref = previous;
  }
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

test("startupSetting builds the Proxmox startup value", () => {
  assert.equal(startupSetting({ order: 2 }), "order=2");
  assert.equal(startupSetting({ order: 0, upDelay: 30 }), "order=0,up=30");
  assert.equal(startupSetting({ order: 1, downDelay: 10 }), "order=1,down=10");
  assert.equal(startupSetting({ order: 3, upDelay: 30, downDelay: 10 }), "order=3,up=30,down=10");
  assert.equal(startupSetting({ order: 1, upDelay: 0, downDelay: 0 }), "order=1");
});
