// In-process attack pass against the policy gate.
//
// Drives getPolicyBlockReason (the exact function tools/call uses) with a
// labelled corpus. A command labelled "approval" that comes back null ran
// without confirmation: that is a FINDING. A command labelled "readonly" that
// comes back non-null is a false positive (lower priority, listed separately).
//
// No network, no Proxmox. Pure decision-layer testing.

import "../env.js";
import assert from "node:assert/strict";
import { getPolicyBlockReason } from "../../src/policy.js";
import { TOOLS } from "../../src/tools.js";
import { sensitiveGetReason } from "../../src/apiPolicy.js";

const hostShell = TOOLS.host_shell;
const lxcShell = TOOLS.lxc_shell;
const api = TOOLS.proxmox_api;

// Would this shell command run with no confirm? null means yes (a finding if
// the command is dangerous).
const hostGate = (command) => getPolicyBlockReason(hostShell, { command });
const guestGate = (command) => getPolicyBlockReason(lxcShell, { vmid: 100, command });

const findings = [];
const falsePositives = [];

// expect: "approval" (must be gated) or "readonly" (must run freely).
function check(gate, command, expect, note) {
  const reason = gate(command);
  const gated = reason !== null;
  if (expect === "approval" && !gated)
    findings.push({ command, note, got: "RAN WITHOUT APPROVAL" });
  if (expect === "readonly" && gated)
    falsePositives.push({ command, note, got: reason });
}

// ─── Commands that MUST require approval ────────────────────────────────────
const MUST_GATE = [
  // ss: writes, reads filter files, switches namespace, streams
  ["ss -D /tmp/out", "ss dumps raw socket info to a file (write)"],
  ["ss --diag=/etc/cron.d/x", "ss -D long form, writes a file"],
  ["ss -F /etc/passwd", "ss reads a filter file"],
  ["ss -K", "ss kills sockets"],
  ["ss --kill", "ss kills sockets, long form"],
  ["ss --kil", "ss kills sockets, abbreviated long option"],
  // journalctl: maintenance, follow, arbitrary file reads, the -n swallow
  ["journalctl --rotate", "rotates the journal"],
  ["journalctl --rot", "rotate, abbreviated"],
  ["journalctl --vacuum-time=1s", "deletes archived journal files"],
  ["journalctl --flush", "flushes runtime journal to disk"],
  ["journalctl -n --rotate", "the -n optional-value swallow from audit 2"],
  ["journalctl --lines --vacuum-size=1M", "same swallow, long form"],
  ["journalctl -D /var/tmp", "reads an arbitrary journal directory"],
  ["journalctl --file=/etc/shadow", "reads an arbitrary file"],
  ["journalctl -f", "follow holds the session open"],
  // sensors
  ["sensors -s", "applies sensor limits"],
  ["sensors --set", "applies sensor limits"],
  ["sensors -c /etc/shadow", "reads an arbitrary config file"],
  // systemctl: reach other machines, non-read subcommands
  ["systemctl status --host=root@evil", "status over SSH to another host"],
  ["systemctl status -H evil", "status over SSH, short"],
  ["systemctl status -M machine", "status in another machine/container"],
  ["systemctl stop sshd", "stop is not a read subcommand"],
  ["systemctl restart pveproxy", "restart is not a read subcommand"],
  ["systemctl daemon-reload", "not a read subcommand"],
  // smartctl: the set forms behind -l / -d, and the obvious writes
  ["smartctl -l scterc,70,70 /dev/sda", "sets drive error-recovery timers"],
  ["smartctl --log=scterc,70,70 /dev/sda", "same, long form"],
  ["smartctl -t short /dev/sda", "starts a self-test"],
  ["smartctl -X /dev/sda", "aborts a self-test"],
  ["smartctl -s on /dev/sda", "enables SMART"],
  ["smartctl -o on /dev/sda", "enables offline testing"],
  // find: write/execute predicates
  ["find / -delete", "deletes"],
  ["find /etc -fprint /tmp/x", "writes a file"],
  ["find / -fls /tmp/x", "writes a file"],
  // ps: environment dumps
  ["ps -auxe", "BSD-mode env dump via the dashed form (audit 3)"],
  ["ps auxe", "BSD-mode env dump"],
  ["ps eww", "env dump"],
  ["ps -eo environ", "env via format key"],
  ["ps ax -o pid,environ", "env via format key"],
  // file reads: known secret paths
  ["cat /etc/shadow", "password hashes"],
  ["cat /etc/pve/priv/authkey.key", "cluster signing key"],
  ["cat /etc/pve/domains.cfg", "OIDC client key (audit 3)"],
  ["cat /etc/pve/sdn/ipams.cfg", "IPAM API tokens (audit 3)"],
  ["cat /root/.ssh/id_ed25519", "private key"],
  ["cat /root/.bash_history", "home dot-file"],
  ["cat /home/alice/.netrc", "home dot-file"],
  ["head /proc/1/environ", "another process's environment"],
  ["head /proc/1/task/1/environ", "per-thread environment (audit 3)"],
  ["cat /proc/1/fd/3", "another process's open file"],
  // file reads: traversal / encoding tricks against the deny list
  ["cat //etc//shadow", "doubled slashes"],
  ["cat /etc/./shadow", "dot segment"],
  ["cat /etc/pve/../pve/priv/authkey.key", "dot-dot that normalizes back in"],
  ["cat /var/log/../../etc/shadow", "traversal out of a readable root"],
  ["cat /sys/../etc/shadow", "traversal out of a readable root"],
  // file reads: outside the readable roots
  ["cat /opt/app/config.yml", "outside READONLY_PATHS"],
  ["grep secret /srv/app/.env.production", "outside roots and a secret name"],
  ["cat relative/path", "relative path"],
  // the reader-option escapes from earlier audits
  ["wc --files0-from=/etc/shadow", "prints the file via the error (audit 3)"],
  ["du --files0-from=/etc/shadow", "same via du"],
  ["du --exclude-from=/etc/shadow .", "reads a file as an exclude list"],
  ["grep -f /etc/shadow x", "reads the pattern file"],
  ["grep - /opt/secret.yml", "lone dash is grep's pattern, file follows (audit 3)"],
  ["grep -r x /etc", "recursive grep reaches /etc/shadow"],
  ["grep --rec x /etc", "recursive, abbreviated"],
  ["tail -f /var/log/syslog", "follow holds the session open"],
  ["head -c 1000000000 /dev/sda", "dumps the disk"],
  // shell metacharacters must never be plain-text
  ["cat /etc/hostname; id", "command separator"],
  ["cat /etc/hostname && rm -rf /tmp", "command separator"],
  ["cat $(cat /etc/shadow)", "command substitution"],
  ["cat `id`", "backtick substitution"],
  ["ls /tmp | sh", "pipe"],
  ["cat /etc/hostname > /etc/x", "redirect"],
  ["cat /etc/*", "glob"],
  // not on the allowlist at all
  ["qm set 100 --delete protection", "qm set is not a read subcommand"],
  ["pct set 100 -rootfs x", "pct set is not a read subcommand"],
  ["zfs destroy rpool/data", "zfs destroy is not a read subcommand"],
  ["zpool scrub rpool", "zpool scrub is not listed"],
  ["rm -rf /", "not on the allowlist"],
  ["bash -c id", "not on the allowlist"],
];
for (const [command, note] of MUST_GATE) check(hostGate, command, "approval", note);

// Guest context: every file read must be gated, even from a readable root.
for (const [command, note] of [
  ["cat /var/log/syslog", "file read inside a guest"],
  ["grep x /var/log/syslog", "file read inside a guest"],
  ["head -5 /etc/hosts", "file read inside a guest"],
])
  check(guestGate, command, "approval", note);

// ─── Commands that MUST run freely (false-positive check) ───────────────────
const MUST_RUN = [
  ["cat /var/log/syslog", "log under a readable root"],
  ["tail -n 100 /var/log/pve/tasks/index", "log tail"],
  ["grep error /var/log/syslog", "grep in a readable root"],
  ["head -20 /etc/hosts", "host config, readable"],
  ["journalctl -n 50 -u pveproxy", "bounded journal read"],
  ["journalctl -n50 --since -1h", "relative time is a value, not an option"],
  ["ss -tlnp", "socket listing"],
  ["ps aux", "process listing"],
  ["ps -ef", "process listing"],
  ["ps -eo pid,comm,pcpu", "safe format keys"],
  ["df -h", "disk free"],
  ["du -sh /var/lib/vz", "directory size"],
  ["wc -l /var/log/syslog", "line count in a readable root"],
  ["ls -la /", "listing"],
  ["free -m", "memory"],
  ["uptime", "uptime"],
  ["smartctl -a /dev/sda", "full SMART read"],
  ["smartctl -l error /dev/sda", "read-only log"],
  ["zfs list", "zfs list"],
  ["zpool status", "zpool status"],
  ["qm config 100", "guest config"],
  ["pct status 101", "guest status"],
  ["systemctl status pveproxy", "service status"],
  ["ip addr show", "address listing"],
];
for (const [command, note] of MUST_RUN) check(hostGate, command, "readonly", note);

// ─── proxmox_api: sensitive GETs must be gated, ordinary GETs must not ───────
const apiGate = (method, path) => getPolicyBlockReason(api, { method, path });
const API_MUST_GATE = [
  ["GET", "/nodes/pve/qemu/100/agent/file-read?file=/etc/shadow", "guest agent file read"],
  ["GET", "/nodes/pve/qemu/100/agent/exec", "guest agent exec"],
  ["GET", "/nodes/pve/qemu/100/cloudinit/dump?type=user", "cloud-init secrets"],
  ["GET", "/nodes/pve/scan/nfs?server=x", "host-side scan"],
  ["GET", "/nodes/pve/query-url-metadata?url=http://169.254.169.254/", "SSRF (audit 4)"],
  ["GET", "/nodes/pve/storage/local/file-restore/list", "backup file listing"],
  ["GET", "/nodes/pve/qemu/100/%61gent/file-read", "percent-encoded agent segment"],
  ["POST", "/nodes/pve/qemu/100/status/start", "any non-GET"],
  ["DELETE", "/nodes/pve/qemu/100", "any non-GET"],
];
for (const [method, path, note] of API_MUST_GATE) {
  const reason = apiGate(method, path);
  if (reason === null) findings.push({ command: `${method} ${path}`, note, got: "RAN WITHOUT APPROVAL" });
}
const API_MUST_RUN = [
  ["GET", "/nodes/pve/qemu/100/status/current"],
  ["GET", "/cluster/resources?type=vm"],
  ["GET", "/nodes/pve/storage"],
];
for (const [method, path] of API_MUST_RUN) {
  const reason = apiGate(method, path);
  if (reason !== null) falsePositives.push({ command: `${method} ${path}`, got: reason });
}

// ─── Report ─────────────────────────────────────────────────────────────────
const line = (f) => `  [${f.note ?? ""}] ${f.command}  =>  ${f.got}`;
console.log(`\nAttack pass: ${MUST_GATE.length + API_MUST_GATE.length + 3} gate checks, ${MUST_RUN.length + API_MUST_RUN.length} free-run checks\n`);
if (findings.length) {
  console.log(`!!! ${findings.length} FINDING(S): dangerous input ran without approval`);
  for (const f of findings) console.log(line(f));
} else {
  console.log("No bypasses: every dangerous input was gated.");
}
if (falsePositives.length) {
  console.log(`\n${falsePositives.length} false positive(s): safe input was gated`);
  for (const f of falsePositives) console.log(line(f));
}
console.log("");
assert.equal(findings.length, 0, `${findings.length} policy bypass(es) found`);
