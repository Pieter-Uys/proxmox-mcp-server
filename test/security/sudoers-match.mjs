// Simulates sudo's matching of deploy/sudoers.proxmox-mcp against the exact
// strings the server sends under PROXMOX_SSH_SUDO=on.
//
// The sudo tier's security property: a confirmed-dangerous Proxmox command,
// when sent, matches NO sudoers rule (so sudo -n fails and it never runs as
// root), while every legitimate command the server sends matches a rule (so the
// tier doesn't break normal use). This parses the real file, so a future edit
// that loosens a regex is caught here.
//
// Not a substitute for real sudo: it models path resolution and single-quote
// removal, then matches the argument string against each rule's ERE as JS
// RegExp (a close superset of POSIX ERE for these patterns).

import "../env.js";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { withHostPrivilege } from "../../src/privilege.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sudoersText = fs.readFileSync(path.join(repoRoot, "deploy/sudoers.proxmox-mcp"), "utf8");

// ─── Parse the sudoers Cmnd_Alias rules ─────────────────────────────────────
// Each: Cmnd_Alias NAME = /abs/path <argspec>. An argspec starting with ^ is an
// ERE over the space-joined arguments; otherwise it is a literal arg string.
const rules = [];
for (const line of sudoersText.split("\n")) {
  const m = /^Cmnd_Alias\s+(\w+)\s*=\s*(\/\S+)\s+(.+?)\s*$/.exec(line);
  if (!m) continue;
  const [, name, cmdPath, argspec] = m;
  rules.push({
    name,
    command: path.basename(cmdPath),
    regex: argspec.startsWith("^") ? new RegExp(argspec) : null,
    literal: argspec.startsWith("^") ? null : argspec,
  });
}
assert.ok(rules.length >= 13, `expected to parse the sudoers rules, got ${rules.length}`);

// ─── Model sudo matching ────────────────────────────────────────────────────
// Minimal shell tokenizer: splits on whitespace, keeps single-quoted spans
// (including shellQuote's '\'' escape) as one argument. Good enough for the
// server's commands, which only ever single-quote.
function tokenize(commandString) {
  const args = [];
  let current = "";
  let inQuote = false;
  let started = false;
  for (let i = 0; i < commandString.length; i++) {
    const ch = commandString[i];
    if (inQuote) {
      if (ch === "'") inQuote = false;
      else current += ch;
      continue;
    }
    if (ch === "'") { inQuote = true; started = true; continue; }
    if (ch === " " || ch === "\t") {
      if (started) { args.push(current); current = ""; started = false; }
      continue;
    }
    current += ch;
    started = true;
  }
  if (started) args.push(current);
  return args;
}

// True if sudo (with this file) would permit the command the server sends.
// Strips a leading `sudo -n`, resolves the tool, and tests its arguments.
function sudoAllows(sentCommand) {
  let argv = tokenize(sentCommand);
  if (argv[0] === "sudo") {
    argv = argv.slice(1);
    while (argv[0]?.startsWith("-")) argv = argv.slice(1); // drop -n and friends
  }
  const [tool, ...rest] = argv;
  const joined = rest.join(" ");
  return rules.some((rule) => {
    if (rule.command !== tool) return false;
    return rule.regex ? rule.regex.test(joined) : rule.literal === joined;
  });
}

// What the server actually sends for a host command under sudo=on.
const sent = (command) => withHostPrivilege(command, true);

const failures = [];
const expectAllowed = (command, note) => {
  if (!sudoAllows(sent(command))) failures.push(`should be ALLOWED but sudo would reject: ${command}  [${note}]`);
};
const expectRejected = (command, note) => {
  if (sudoAllows(sent(command))) failures.push(`should be REJECTED but sudo would allow: ${command}  [${note}]`);
};

// ─── Legit commands the server sends: every one must be allowed ─────────────
for (const [command, note] of [
  ["pct exec 100 -- bash -c 'cat /etc/hostname'", "lxc_shell"],
  ["pct exec 7 -- bash -c 'grep x /etc/app.conf'", "lxc_shell other vmid"],
  ["pct list", "read"],
  ["pct config 100", "read"],
  ["pct config 100 --current", "read"],
  ["pct status 101", "read"],
  ["qm list", "read"],
  ["qm config 100", "read"],
  ["qm status 100", "read"],
  ["pvesm status", "read"],
  ["pvesm status --content images", "read"],
  ["zpool status", "read"],
  ["zpool status -v rpool", "read"],
  ["zpool list", "read"],
  ["zpool list -o name,size", "read"],
  ["zfs list", "read"],
  ["zfs list -r -o name,used tank/data", "read"],
  ["zfs create -p -o 'compression=lz4' 'tank/data'", "zfs_create as the server builds it"],
  ["zfs create 'tank/data'", "zfs_create no options"],
  ["ifreload -a", "network apply"],
]) expectAllowed(command, note);

// ─── Dangerous commands: every one must be rejected by sudo ─────────────────
for (const [command, note] of [
  ["zfs destroy rpool/data", "destroy"],
  ["zfs destroy -r rpool", "recursive destroy"],
  ["zfs create -o mountpoint=/etc 'tank/x'", "mountpoint over /etc"],
  ["zfs create -o exec=on 'tank/x'", "exec property"],
  ["zfs create -o setuid=on 'tank/x'", "setuid property"],
  ["zfs create -o sharenfs=on 'tank/x'", "share to remote root"],
  ["zfs rename a b", "rename"],
  ["zfs set compression=on tank", "set"],
  ["pct push 100 /etc/shadow /tmp/x", "push a host file into a container"],
  ["pct pull 100 /etc/shadow /tmp/x", "pull a file out of a container"],
  ["pct create 200 local:vztmpl/x.tar", "create a container"],
  ["pct destroy 100", "destroy a container"],
  ["pct set 100 -mp0 /etc", "bind a host path"],
  ["qm set 100 --args '-drive file=/dev/sda'", "qm set --args"],
  ["qm create 999", "qm create"],
  ["qm destroy 100", "qm destroy"],
  ["zpool status -c /tmp/evil.sh rpool", "status -c runs a script as root"],
  ["zpool scrub rpool", "scrub"],
  ["zpool create newpool /dev/sdb", "create"],
  ["zpool destroy rpool", "destroy"],
  ["pvesm remove local", "pvesm remove"],
  ["ifreload -a extra", "ifreload with an extra arg"],
  ["ifdown vmbr0", "ifdown is not even a sudo command, but check it isn't matched"],
]) expectRejected(command, note);

// ─── Report ─────────────────────────────────────────────────────────────────
console.log(`\nSudoers-match: ${rules.length} rules parsed, ${20 + 23} commands checked\n`);
if (failures.length) {
  console.log(`!!! ${failures.length} FAILURE(S):`);
  for (const f of failures) console.log(`  ${f}`);
} else {
  console.log("Every legit command is allowed by sudoers and every dangerous one is rejected.");
}
console.log("");
assert.equal(failures.length, 0, `${failures.length} sudoers-match failure(s)`);
