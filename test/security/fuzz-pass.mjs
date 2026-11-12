// Generative fuzzing of the policy gate with decidable oracles.
//
// Unlike the curated corpus, these generate inputs across a space and decide
// correctness without a real host:
//   O1  any shell metacharacter in a command => must be gated
//   O2  every abbreviation of a dangerous long option => must be gated
//   O3  any path constructed to resolve to a known secret => must be gated
//   O4  content read of any path outside the readable roots => must be gated

import "../env.js";
import assert from "node:assert/strict";
import { getPolicyBlockReason } from "../../src/policy.js";
import { TOOLS } from "../../src/tools.js";

const gate = (command) => getPolicyBlockReason(TOOLS.host_shell, { command });
const findings = [];
let checks = 0;
const mustGate = (command, oracle, note) => {
  checks++;
  if (gate(command) === null) findings.push({ oracle, command, note });
};

// ─── O1: shell metacharacters ───────────────────────────────────────────────
// PLAIN_WORD is the whole defence against the shell interpreting an argument.
// The precise property: any character the shell gives meaning, embedded inside
// a word, must make the command non-plain and so force approval. (Pure
// trailing/leading whitespace is excluded: the policy trims it and the shell
// ignores it, so it is not an injection.) The null byte and the Unicode line
// separators are included because the shell/stripping can treat them specially.
const METACHARS = [
  ";", "|", "&", "$", "`", "\\", "<", ">", "(", ")", "{", "}",
  "*", "?", "[", "]", "'", '"', "!", "~", "#", "\0", " ", " ",
  "\n", "\r", // newline/CR are not in the word-split set, so they stay in-word
  // NB: space and tab are the word-split set [ \t]; embedding them just creates
  // another operand, decided by each command's own operand rules, so they are
  // separators rather than injections and are excluded here.
];
const CARRIERS = ["cat /var/log/syslog", "grep x /var/log/syslog", "tail /var/log/syslog", "ls /var/log"];
for (const carrier of CARRIERS) {
  for (const ch of METACHARS) {
    // Embedded inside the final word, and splicing a second command after a
    // separator. Both are real injections and must be gated.
    mustGate(`${carrier}${ch}id`, "O1-metachar", `embedded ${JSON.stringify(ch)}`);
    mustGate(`${carrier}${ch}cat /etc/shadow`, "O1-inject", `spliced after ${JSON.stringify(ch)}`);
  }
}
// Classic injection payloads spliced into the command, each a single word so
// word-splitting alone does not neutralise them.
for (const payload of [
  "$(id)", "`id`", "${IFS}cat", "a;id", "a|id", "a&&id", "a||id",
  "a>/tmp/x", "a<secret", "*.conf", "../*", "{a,b}",
])
  mustGate(`cat /var/log/syslog${payload}`, "O1-metachar", `payload ${JSON.stringify(payload)}`);

// ─── O2: option-abbreviation space ──────────────────────────────────────────
// GNU getopt accepts any unambiguous prefix of a long option. A denylist that
// named the full spelling was escaped by --kil and --rot. Every prefix (length
// 3 up) of a dangerous option must be gated, for every argument order.
const DANGEROUS_LONG = {
  ss: ["--diag", "--kill"],
  journalctl: ["--rotate", "--flush", "--sync", "--vacuum-size", "--vacuum-time", "--vacuum-files", "--file", "--directory", "--setup-keys"],
  sensors: ["--set"],
  systemctl: ["--host", "--machine", "--root"],
};
// A read-only base per command so only the dangerous option is the variable.
const SAFE_BASE = {
  ss: "ss -tln",
  journalctl: "journalctl -n 5",
  sensors: "sensors",
  systemctl: "systemctl status",
};
for (const [cmd, options] of Object.entries(DANGEROUS_LONG)) {
  for (const option of options) {
    for (let len = 3; len <= option.length; len++) {
      const prefix = option.slice(0, len);
      mustGate(`${SAFE_BASE[cmd]} ${prefix}`, "O2-abbrev", `${cmd} ${prefix} (for ${option})`);
      mustGate(`${SAFE_BASE[cmd]} ${prefix}=1s`, "O2-abbrev", `${cmd} ${prefix}=value`);
      mustGate(`${cmd} ${prefix}`, "O2-abbrev", `${cmd} ${prefix} first-arg`);
    }
  }
}
// journalctl -n optional-value swallow: -n/--lines followed by any dangerous
// option must still gate the option, not skip it as -n's value.
for (const cmd of DANGEROUS_LONG.journalctl)
  for (const nForm of ["-n", "--lines", "--lin"])
    mustGate(`journalctl ${nForm} ${cmd}`, "O2-swallow", `journalctl ${nForm} ${cmd}`);

// ─── O3: paths constructed to resolve to a secret ───────────────────────────
// Each base is a known secret location. The obfuscations preserve the target
// after POSIX normalization, so the policy must gate every one. This tests the
// normalizer, not a fixed list.
const SECRET_TARGETS = [
  "/etc/shadow", "/etc/pve/priv/authkey.key", "/etc/pve/domains.cfg",
  "/etc/pve/sdn/ipams.cfg", "/root/.ssh/id_rsa", "/root/.bash_history",
  "/proc/1/environ", "/proc/1/task/1/environ",
];
// f(target) -> an equivalent path string.
const OBFUSCATIONS = [
  (p) => p,
  (p) => p.replace(/\//g, "//"),
  (p) => p.replace(/\//g, "///"),
  (p) => p.replace("/", "/./"),
  (p) => p.replace(/\/([^/]+)\//, "/$1/./"),
  (p) => p.replace(/^\/([^/]+)\//, "/$1/x/../"),
  (p) => `/.${p}`,
  (p) => p.replace(/^\//, "/./"),
  (p) => p.replace(/^\//, "/../"), // leading .. is dropped by the normalizer, still resolves in-tree by segment match
  (p) => `/var/log/../..${p}`, // round-trip through a readable root then out
  (p) => `/sys/../..${p}`,
];
for (const readerCmd of ["cat", "head", "tail -n 1", "grep x"]) {
  for (const target of SECRET_TARGETS) {
    for (const obf of OBFUSCATIONS) {
      const path = obf(target);
      mustGate(`${readerCmd} ${path}`, "O3-secret-path", `${readerCmd} ${path} (= ${target})`);
    }
  }
}

// ─── O4: content reads outside the readable roots ───────────────────────────
// A reference oracle: a path is freely readable only if, after normalization,
// it sits under a default readable root. Generate absolute paths and, for any
// the reference says is outside, assert the policy gates it.
const READABLE_ROOTS = [
  "/var/log", "/sys", "/proc", "/etc/network", "/etc/hostname", "/etc/hosts",
  "/etc/os-release", "/etc/apt",
]; // a conservative subset; anything the policy frees that is NOT under these is worth seeing
const OUTSIDE_PATHS = [
  "/opt/app/config.yml", "/srv/data/secret.txt", "/tmp/x", "/usr/local/x",
  "/mnt/backup/dump.sql", "/boot/grub/grub.cfg", "/etc/fstab", "/etc/passwd",
  "/var/lib/mysql/ibdata1", "/home/alice/notes.txt", "/data/.env",
];
const underRoot = (p) => READABLE_ROOTS.some((r) => p === r || p.startsWith(r + "/"));
for (const reader of ["cat", "head", "grep x"]) {
  for (const p of OUTSIDE_PATHS) {
    if (underRoot(p)) continue;
    mustGate(`${reader} ${p}`, "O4-outside-root", `${reader} ${p}`);
  }
}

// ─── Report ─────────────────────────────────────────────────────────────────
console.log(`\nFuzz pass: ${checks} generated checks across O1-O4\n`);
if (findings.length) {
  console.log(`!!! ${findings.length} FINDING(S): generated input ran without approval`);
  const byOracle = {};
  for (const f of findings) (byOracle[f.oracle] ??= []).push(f);
  for (const [oracle, fs] of Object.entries(byOracle)) {
    console.log(`\n  ${oracle}: ${fs.length}`);
    for (const f of fs.slice(0, 20)) console.log(`    ${f.command}   [${f.note}]`);
    if (fs.length > 20) console.log(`    ... and ${fs.length - 20} more`);
  }
} else {
  console.log("No bypasses: every generated dangerous input was gated.");
}
console.log("");
assert.equal(findings.length, 0, `${findings.length} fuzz bypass(es) found`);
