import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { isReadonlyCommand, getPolicyBlockReason } from "../src/policy.js";
import { SECURITY } from "../src/config.js";
import { TOOLS } from "../src/tools.js";

// Runs fn with SHELL_MODE temporarily set, then restores it.
async function withShellMode(mode, fn) {
  const previous = SECURITY.shellMode;
  SECURITY.shellMode = mode;
  try {
    return await fn();
  } finally {
    SECURITY.shellMode = previous;
  }
}

// ─── Read-only allowlist ────────────────────────────────────────────────────
const ALLOWED = [
  "ls -la /var/log",
  "cat /etc/os-release",
  "df -h",
  "free -m",
  "uptime",
  "hostname -f",
  "date -u",
  "date +%s",
  "find /var/log -name syslog",
  "journalctl -u pveproxy -n 50",
  "ss -tlnp",
  "sensors",
  "smartctl -a /dev/sda",
  "ip addr show",
  "ip a",
  "zfs list",
  "zpool status",
  "qm list",
  "pct config 101",
  "systemctl status pveproxy",
];

const REFUSED = {
  "chaining and separators": ["ls; rm -rf /", "ls && reboot", "ls | sh", "ls\nreboot"],
  "redirects": ["cat /etc/passwd > /tmp/x", "ls >> /tmp/x"],
  "substitution, quoting and globs": ["ls $(whoami)", "ls `whoami`", "cat 'file'", "ls *"],
  "state-changing forms of read commands": [
    "date -s 2020-01-01",
    "date 010112002020",
    "hostname evil",
    "find / -delete",
    "find / -exec rm {} +",
    "journalctl --vacuum-size=1M",
    "ss -K",
    "ss -tlnK",
    "ss --kill",
    "sensors -s",
    "smartctl -s on /dev/sda",
    "smartctl -t long /dev/sda",
    "ip link set eth0 down",
    "ip addr add 10.0.0.1/24 dev eth0",
  ],
  "write subcommands of allowed tools": [
    "zfs destroy tank/data",
    "zpool destroy tank",
    "qm stop 100",
    "pct destroy 101",
    "systemctl restart pveproxy",
  ],
  "commands not on the list": ["rm -rf /", "reboot", ""],
  "names that exist on Object.prototype": ["constructor", "toString", "__proto__"],
};

test("read-only allowlist accepts plain read commands", () => {
  for (const command of ALLOWED) {
    assert.equal(isReadonlyCommand(command), true, `should allow: ${command}`);
  }
});

for (const [group, commands] of Object.entries(REFUSED)) {
  test(`read-only allowlist refuses ${group}`, () => {
    for (const command of commands) {
      assert.equal(isReadonlyCommand(command), false, `should refuse: ${JSON.stringify(command)}`);
    }
  });
}

// ─── SHELL_MODE=full: confirmation ──────────────────────────────────────────
test("full mode: read-only commands run without confirmation", async () => {
  await withShellMode("full", () => {
    assert.equal(getPolicyBlockReason(TOOLS.host_shell, { command: "uptime" }), null);
  });
});

test("full mode: other commands need confirm: true", async () => {
  await withShellMode("full", () => {
    const blocked = getPolicyBlockReason(TOOLS.host_shell, { command: "reboot" });
    assert.match(blocked, /confirm: true/);
    assert.equal(getPolicyBlockReason(TOOLS.host_shell, { command: "reboot", confirm: true }), null);
  });
});

test("full mode: confirm must be the boolean true, not a truthy string", async () => {
  await withShellMode("full", () => {
    assert.match(getPolicyBlockReason(TOOLS.host_shell, { command: "reboot", confirm: "true" }), /confirm: true/);
    assert.match(getPolicyBlockReason(TOOLS.host_shell, { command: "reboot", confirm: 1 }), /confirm: true/);
  });
});

// ─── SHELL_MODE=readonly ────────────────────────────────────────────────────
test("readonly mode: allows read commands, blocks the rest even with confirm", async () => {
  await withShellMode("readonly", () => {
    assert.equal(getPolicyBlockReason(TOOLS.host_shell, { command: "uptime" }), null);
    assert.match(getPolicyBlockReason(TOOLS.host_shell, { command: "reboot" }), /SHELL_MODE=readonly/);
    assert.match(
      getPolicyBlockReason(TOOLS.host_shell, { command: "reboot", confirm: true }),
      /SHELL_MODE=readonly/,
    );
  });
});

test("readonly mode also covers tools that run shell commands indirectly", async () => {
  await withShellMode("readonly", () => {
    assert.equal(getPolicyBlockReason(TOOLS.storage_config, { action: "zfs_list" }), null);
    assert.match(
      getPolicyBlockReason(TOOLS.storage_config, { action: "zfs_create", zfsCommand: "create tank/x", confirm: true }),
      /SHELL_MODE=readonly/,
    );
    assert.match(
      getPolicyBlockReason(TOOLS.network_config, { action: "apply", confirm: true }),
      /SHELL_MODE=readonly/,
    );
    assert.match(
      getPolicyBlockReason(TOOLS.run_community_script, { script: "pihole", confirm: true }),
      /SHELL_MODE=readonly/,
    );
  });
});

// ─── SHELL_MODE=off ─────────────────────────────────────────────────────────
test("off mode: blocks every shell-running call, even read-only ones", async () => {
  await withShellMode("off", () => {
    assert.match(getPolicyBlockReason(TOOLS.host_shell, { command: "uptime" }), /SHELL_MODE=off/);
    assert.match(getPolicyBlockReason(TOOLS.lxc_shell, { vmid: 101, command: "uptime" }), /SHELL_MODE=off/);
    assert.match(getPolicyBlockReason(TOOLS.vm_ssh, { ip: "10.0.0.5", command: "uptime" }), /SHELL_MODE=off/);
  });
});

test("off mode: tools that don't run shell commands are unaffected", async () => {
  await withShellMode("off", () => {
    assert.equal(getPolicyBlockReason(TOOLS.proxmox_api, { method: "GET", path: "/version" }), null);
    assert.equal(getPolicyBlockReason(TOOLS.get_status, { scope: "cluster" }), null);
    assert.equal(getPolicyBlockReason(TOOLS.network_config, { action: "list" }), null);
  });
});

test("unknown tool is left for callTool to report", () => {
  assert.equal(getPolicyBlockReason(undefined, {}), null);
});
