import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import {
  SUDO_COMMANDS,
  SUDO_ZFS_PROPERTIES,
  withHostPrivilege,
  sudoZfsPropertiesRefusal,
} from "../src/privilege.js";
import { shellQuote } from "../src/ssh.js";
import { isReadonlyCommand, withSafePsEnvironment, getPolicyBlockReason } from "../src/policy.js";
import { TOOLS } from "../src/tools.js";
import { CONFIG } from "../src/config.js";

// ─── withHostPrivilege ──────────────────────────────────────────────────────
test("sudo off: commands are sent unchanged", () => {
  for (const command of ["pct list", "zfs list", "ifreload -a", "uptime"]) {
    assert.equal(withHostPrivilege(command, false), command);
  }
});

test("sudo on: only the Proxmox tools get sudo -n", () => {
  assert.equal(withHostPrivilege("pct exec 101 -- bash -c 'id'", true), "sudo -n pct exec 101 -- bash -c 'id'");
  assert.equal(withHostPrivilege("  zfs list", true), "sudo -n zfs list");
  for (const name of SUDO_COMMANDS) assert.match(withHostPrivilege(`${name} x`, true), /^sudo -n /, name);
  for (const command of ["uptime", "cat /var/log/syslog", "env -u PS_PERSONALITY ps aux", "pctx list", "zfsx", "sudo pct list"]) {
    assert.equal(withHostPrivilege(command, true), command, command);
  }
});

test("sudo on: zfs create may set only the listed properties, with plain values", () => {
  assert.equal(sudoZfsPropertiesRefusal({ compression: "lz4", recordsize: "1M", quota: "10G" }), null);
  assert.equal(sudoZfsPropertiesRefusal(undefined), null);
  for (const properties of [
    { mountpoint: "/etc" },
    { canmount: "on" },
    { sharenfs: "rw=@0.0.0.0/0,no_root_squash" },
    { sharesmb: "on" },
    { setuid: "on" },
    { keylocation: "file:///etc/shadow" },
    { "com.example:owner": "alice" },
    { compression: "lz4,x" },
    { compression: "a=b" },
  ]) {
    assert.ok(sudoZfsPropertiesRefusal(properties), JSON.stringify(properties));
  }
});

// ─── PROXMOX_SSH_SUDO in config ─────────────────────────────────────────────
const CONFIG_URL = new URL("../src/config.js", import.meta.url).href;

function loadConfig(env) {
  const script = `const { CONFIG } = await import(${JSON.stringify(CONFIG_URL)}); console.log(CONFIG.ssh.sudo);`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { ...process.env, PROXMOX_SSH_USER: "", PROXMOX_SSH_SUDO: "", ...env },
    encoding: "utf8",
  });
  return { status: child.status, sudo: child.stdout.trim(), error: child.stderr };
}

test("PROXMOX_SSH_SUDO defaults to off and needs a non-root user when on", () => {
  assert.equal(CONFIG.ssh.sudo, false);
  assert.equal(loadConfig({}).sudo, "false");
  assert.equal(loadConfig({ PROXMOX_SSH_SUDO: "on", PROXMOX_SSH_USER: "mcp" }).sudo, "true");
  const asRoot = loadConfig({ PROXMOX_SSH_SUDO: "on" });
  assert.equal(asRoot.status, 1);
  assert.match(asRoot.error, /PROXMOX_SSH_USER/);
  const typo = loadConfig({ PROXMOX_SSH_SUDO: "yes", PROXMOX_SSH_USER: "mcp" });
  assert.equal(typo.status, 1);
  assert.match(typo.error, /PROXMOX_SSH_SUDO/);
});

// ─── deploy/sudoers.proxmox-mcp ─────────────────────────────────────────────
// The sudoers file is the boundary in this mode, so it is checked against the
// commands the server really sends. Each Cmnd_Alias holds one command: a path
// and either an exact argument string or a ^...$ regular expression (sudo
// 1.9.10+, POSIX extended, matched against the arguments joined by spaces).
const SUDOERS_PATH = new URL("../deploy/sudoers.proxmox-mcp", import.meta.url);
const SUDOERS = fs.readFileSync(SUDOERS_PATH, "utf8");

// sudoers needs , : = and \ escaped in arguments; undo that for matching.
const unescapeSudoers = (text) => text.replaceAll(/\\([,:=\\])/g, "$1");

const RULES = SUDOERS.split("\n")
  .map((line) => /^Cmnd_Alias (\w+) = (\/\S+) (.+)$/.exec(line))
  .filter(Boolean)
  .map(([, alias, binary, args]) => ({
    alias,
    name: binary.split("/").at(-1),
    match: args.startsWith("^")
      ? (text) => new RegExp(unescapeSudoers(args), "s").test(text)
      : (text) => text === unescapeSudoers(args),
  }));

// Splits a command the way the remote shell would, for the quoting
// shellQuote produces: plain words and single-quoted strings, joined when
// they touch ('a'\''b' is one word).
function shellWords(command) {
  const words = [];
  let end = -1;
  for (const match of command.matchAll(/'([^']*)'|\\(.)|([^\s'\\]+)/g)) {
    const piece = match[1] ?? match[2] ?? match[3];
    if (match.index === end) words[words.length - 1] += piece;
    else words.push(piece);
    end = match.index + match[0].length;
  }
  return words;
}

// True if sudoers would let the dedicated user run this command as root.
function sudoAllows(command) {
  const [name, ...args] = shellWords(command);
  return RULES.some((rule) => rule.name === name && rule.match(args.join(" ")));
}

const lines = (text) =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

test("sudoers: the shell-word splitter undoes shellQuote", () => {
  assert.deepEqual(shellWords(`a ${shellQuote("it's a test")} b`), ["a", "it's a test", "b"]);
  assert.deepEqual(shellWords("zfs create -o 'compression=lz4' 'tank/data'"), ["zfs", "create", "-o", "compression=lz4", "tank/data"]);
});

test("sudoers: every rule is granted to the user, and every tool has a rule", () => {
  const grant = SUDOERS.split("\n").find((line) => line.startsWith("mcp ALL=(root) NOPASSWD: "));
  assert.ok(grant, "grant line");
  assert.deepEqual(new Set(grant.split(": ")[1].split(", ")), new Set(RULES.map((rule) => rule.alias)));
  assert.deepEqual(new Set(RULES.map((rule) => rule.name)), SUDO_COMMANDS);
});

test("sudoers: the commands the server builds are allowed", () => {
  const built = [
    `pct exec 101 -- bash -c ${shellQuote(withSafePsEnvironment("ps aux"))}`,
    `pct exec 101 -- bash -c ${shellQuote("echo 'quoted' && df -h")}`,
    TOOLS.storage_config.shellCommand({ action: "zfs_list" }),
    TOOLS.storage_config.shellCommand({ action: "zfs_create", dataset: "tank/data" }),
    TOOLS.storage_config.shellCommand({
      action: "zfs_create",
      dataset: "tank/vm-disks/child",
      parents: true,
      properties: { compression: "lz4", recordsize: "1M", quota: "10G" },
    }),
    TOOLS.network_config.shellCommand({ action: "apply" }),
  ];
  for (const command of built) assert.equal(sudoAllows(command), true, command);
});

// The read-only allowlist forms of these tools must work under sudo too.
test("sudoers: the read-only forms of the Proxmox tools are allowed", () => {
  for (const command of lines(`
    pct list
    pct config 101
    pct config 101 --current
    pct config 101 --snapshot before-upgrade
    pct status 101
    pct status 101 --verbose
    qm list
    qm list --full 1
    qm config 100
    qm config 100 --current
    qm config 100 --snapshot before-upgrade
    qm status 100 --verbose
    pvesm status
    pvesm status --storage local
    pvesm status --content images
    zpool status
    zpool status -x
    zpool status -v tank
    zpool list
    zpool list -H -o name,size
    zfs list
    zfs list -t snapshot -o name,used
    zfs list -rH tank
  `)) {
    assert.equal(isReadonlyCommand(command), true, `read-only list: ${command}`);
    assert.equal(sudoAllows(command), true, `sudoers: ${command}`);
  }
});

// Each of these is root on the host (or close to it), so sudoers must refuse
// it however the request reached the user, parser bugs included.
test("sudoers: root-equivalent forms are refused", () => {
  for (const command of lines(`
    pct push 101 /etc/shadow /tmp/shadow
    pct pull 101 /etc/shadow /tmp/x
    pct create 200 local:vztmpl/debian.tar.zst --mp0 /,mp=/host
    pct set 101 --mp0 /,mp=/host
    pct enter 101
    pct destroy 101
    pct exec 101 --keep-env 1 -- bash -c id
    pct exec 101 -- sh -c id
    pct exec 101
    pct list --x
    pct config 101 --delete net0
    qm set 100 --args -device
    qm guest exec 100 -- id
    qm monitor 100
    qm destroy 100
    qm start 100
    pvesm alloc local 100 vm-100-disk-9 1G
    pvesm set local --disable 1
    zpool status -c smart
    zpool status -xc smart
    zpool destroy tank
    zpool export tank
    zpool import -f tank
    zfs destroy -r tank/data
    zfs set mountpoint=/ tank/data
    zfs create -o mountpoint=/etc tank/x
    zfs create -o sharenfs=rw=@0.0.0.0/0 tank/x
    zfs create -o canmount=on tank/x
    zfs create -V 10G tank/vol
    zfs create tank
    zfs create tank/x extra
    ifreload -a -f
    ifreload
  `)) {
    assert.equal(sudoAllows(command), false, command);
  }
});

test("sudoers: zfs create allows exactly the properties the server allows", () => {
  const rule = SUDOERS.split("\n").find((line) => line.startsWith("Cmnd_Alias MCP_ZFS_CREATE "));
  const names = /-o \(([a-z_|]+)\)/.exec(rule)[1].split("|");
  assert.deepEqual(new Set(names), SUDO_ZFS_PROPERTIES);
});

// visudo checks the syntax only; the tests above check what the rules match.
const hasVisudo = !spawnSync("visudo", ["--version"]).error;
test("sudoers: visudo accepts the file", { skip: !hasVisudo && "visudo not installed" }, () => {
  const result = spawnSync("visudo", ["-cf", SUDOERS_PATH.pathname], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test("sudo on: storage_config refuses zfs_create properties sudoers would refuse", () => {
  const previous = CONFIG.ssh.sudo;
  CONFIG.ssh.sudo = true;
  try {
    const call = (properties) =>
      getPolicyBlockReason(TOOLS.storage_config, { action: "zfs_create", dataset: "tank/x", properties, confirm: true });
    assert.match(call({ mountpoint: "/etc" }) ?? "", /PROXMOX_SSH_SUDO=on/);
    assert.match(call({ "com.example:owner": "alice" }) ?? "", /PROXMOX_SSH_SUDO=on/);
    assert.equal(call({ compression: "lz4" }), null);
  } finally {
    CONFIG.ssh.sudo = previous;
  }
  assert.equal(
    getPolicyBlockReason(TOOLS.storage_config, { action: "zfs_create", dataset: "tank/x", properties: { mountpoint: "/srv/x" }, confirm: true }),
    null,
    "sudo off: mountpoint stays allowed",
  );
});
