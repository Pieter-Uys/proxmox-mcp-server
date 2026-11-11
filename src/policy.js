import path from "node:path";
import { SECURITY } from "./config.js";

// ─── Shell command confirmation (SHELL_MODE=full) ───────────────────────────
// Any command the read-only allowlist doesn't accept needs confirm: true.
// A list of known-dangerous commands can never be complete (find -delete,
// ip link set down, lvremove, qm set --delete, ...), so approval is the default.
//
// `context` is "host" for commands on the Proxmox host and "guest" for
// commands inside a container or VM, where file reads are gated more tightly.
export function shellConfirmationReasonFor(context) {
  return (args) => readonlyRefusal(String(args.command || ""), context);
}
export const shellConfirmationReason = shellConfirmationReasonFor("host");

// ─── Policy: shell mode and destructive-action confirmation ─────────────────
// Returns a reason string if server policy blocks this call, or null if it may run.
export function getPolicyBlockReason(tool, args) {
  if (!tool) return null; // callTool reports unknown tools

  // Hard limits set by the server's configuration. Checked first so no shell
  // mode skips them, and confirm: true can't override them.
  const refusal = tool.refusalReason?.(args);
  if (refusal) return refusal;

  // Any call that runs a shell command, not just the shell tools, obeys SHELL_MODE.
  const command = tool.shellCommand?.(args);
  if (command != null && SECURITY.shellMode === "off")
    return "Shell commands are disabled (SHELL_MODE=off).";
  if (command != null && SECURITY.shellMode === "readonly") {
    return isReadonlyCommand(command, tool.shellContext)
      ? null
      : "Only single read-only commands with read-only options are allowed (SHELL_MODE=readonly).";
  }

  const reason = tool.confirmationReason?.(args);
  if (!reason) return null;
  // Anything that would need approval is off the table in TOOL_MODE=readonly.
  if (SECURITY.toolMode === "readonly")
    return `Only reads are allowed (TOOL_MODE=readonly). ${reason}`;
  if (args.confirm === true) return null;
  return `${reason} Ask the user to approve this exact action, then call again with confirm: true.`;
}

// ─── SHELL_MODE=readonly ────────────────────────────────────────────────────
// A command passes only if every word is plain text and the command's own rule
// accepts its arguments. Plain text rules out anything the shell would
// interpret: separators (; & | newline), redirects, quotes, variables, globs.
// Checking only the first word would let through `date -s ...`,
// `find / -delete`, `ip link set eth0 down` and similar.
const PLAIN_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;

// A command that reads a sensitive path, or file contents outside the readable
// roots, is never read-only in the sense that matters here: it needs
// confirm: true, and SHELL_MODE=readonly refuses it.
export function isReadonlyCommand(command, context = "host") {
  return readonlyRefusal(command, context) === null;
}

// Why the command needs approval, or null if it is read-only. Checked in this
// order so the reason describes the real risk: a command that could change
// something is never described as a read.
function readonlyRefusal(command, context = "host") {
  const words = plainWords(command);
  if (words === null || !passesAllowlist(words))
    return "This command isn't on the read-only list, so it could change the system.";
  const [name, ...args] = words;
  if (touchesSensitivePath(name, args))
    return "This command reads a path that can hold secrets (keys, password hashes, cluster credentials).";
  return contentReadRefusal(name, args, context);
}

// True if the command's own rule accepts its arguments, before the
// sensitive-path check.
function passesAllowlist([name, ...args]) {
  return Object.hasOwn(READONLY_COMMANDS, name) && READONLY_COMMANDS[name](args);
}

// The command's words, or null if any word is something the shell would interpret.
function plainWords(command) {
  const words = command.trim().split(/[ \t]+/);
  return words.every((word) => PLAIN_WORD.test(word)) ? words : null;
}

// ─── Readable roots for file contents ───────────────────────────────────────
// The deny list above names known secret locations, but a list of secrets can
// never be complete (.netrc, .pgpass, keyrings, wireguard configs, ...). So the
// commands that print file contents are read-only only for files under
// READONLY_PATHS, on the host. Inside a container or VM, secrets can be
// anywhere, so every file read there needs approval. ls, stat, find and du,
// which show names and sizes rather than contents, are unaffected.
function contentReadRefusal(name, args, context) {
  if (!CONTENT_READERS.has(name)) return null;
  const files = fileOperands(name, args);
  if (files === null)
    return `This command uses a ${name} option the read check doesn't know, so it can't tell which files it reads.`;
  if (files.length === 0) return null; // reads stdin, which is empty over SSH
  if (context === "guest")
    return "File reads inside a container or VM need approval: secrets there can be anywhere.";
  if (files.some((file) => !file.startsWith("/")))
    return "This command reads a file by relative path; use an absolute path under READONLY_PATHS, or approve the read.";
  const roots = SECURITY.readonlyPaths.map((root) => root.split("/").filter(Boolean));
  const outside = files.find((file) => !roots.some((root) => startsWithSegments(pathSegments(file), root)));
  return outside
    ? `This command reads ${outside.slice(0, 120)}, which is outside READONLY_PATHS (${SECURITY.readonlyPaths.join(", ")}).`
    : null;
}

// The files a content reader would open, or null if an option is unknown. Option values are skipped (head -n
// 5), except values that are themselves files (grep -f FILE).
//
// Getting this wrong in one direction is safe (an option value counted as a
// file only adds a prompt) and in the other is a bypass (a file swallowed as a
// value is never checked). So only options whose value is required in the
// real program take one; --color's value is optional and attached only, so
// it is a flag here. Long options must match exactly: GNU tools accept
// abbreviations (--regex for --regexp), and an unknown one could change how
// the rest of the line parses, so it makes the command need approval.
const READER_OPTIONS = {
  cat: {
    valued: "",
    fileValued: "",
    longFlags: ["--number", "--number-nonblank", "--show-all", "--show-ends", "--show-tabs", "--squeeze-blank", "--show-nonprinting"],
    longValued: [],
    fileLongValued: [],
  },
  head: {
    valued: "nc",
    fileValued: "",
    longFlags: ["--quiet", "--silent", "--verbose", "--zero-terminated"],
    longValued: ["--lines", "--bytes"],
    fileLongValued: [],
  },
  tail: {
    valued: "nc",
    fileValued: "",
    longFlags: ["--quiet", "--silent", "--verbose", "--zero-terminated"],
    longValued: ["--lines", "--bytes"],
    fileLongValued: [],
  },
  grep: {
    valued: "emABCdD",
    fileValued: "f",
    longFlags: [
      "--ignore-case", "--no-ignore-case", "--invert-match", "--word-regexp", "--line-regexp", "--count",
      "--files-with-matches", "--files-without-match", "--only-matching", "--quiet", "--silent",
      "--no-messages", "--byte-offset", "--with-filename", "--no-filename", "--line-number", "--initial-tab",
      "--null", "--null-data", "--text", "--extended-regexp", "--fixed-strings", "--basic-regexp",
      "--perl-regexp", "--line-buffered", "--color", "--colour",
    ],
    longValued: [
      "--regexp", "--max-count", "--after-context", "--before-context", "--context", "--directories",
      "--devices", "--include", "--exclude", "--exclude-dir", "--label", "--group-separator",
    ],
    fileLongValued: ["--file", "--exclude-from"],
  },
};

function fileOperands(name, args) {
  const spec = READER_OPTIONS[name];
  // patternGiven: grep -e/-f supplied the pattern, so every operand is a file.
  const found = { operands: [], files: [], patternGiven: false };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") {
      found.operands.push(...args.slice(index + 1));
      break;
    }
    const consumed = readReaderOption(spec, arg, args[index + 1], found);
    if (consumed === null) return null;
    index += consumed;
  }
  // grep's first operand is the pattern unless -e or -f gave one.
  if (name === "grep" && !found.patternGiven) found.operands.shift();
  return [...found.files, ...found.operands];
}

// Reads one word into `found`. Returns how many following words it consumed
// as a value, or null for an unknown long option.
function readReaderOption(spec, arg, next, found) {
  if (arg.startsWith("--")) return readReaderLongOption(spec, arg, next, found);
  if (arg.startsWith("-") && arg.length > 1) return readReaderShortCluster(spec, arg, next, found);
  if (arg !== "-") found.operands.push(arg);
  return 0;
}

function readReaderLongOption(spec, arg, next, found) {
  const [option, attached] = splitLongOption(arg);
  if (spec.longFlags.includes(option)) return 0; // --color=auto keeps its attached value
  const isFile = spec.fileLongValued.includes(option);
  if (!isFile && !spec.longValued.includes(option)) return null;
  const value = attached ?? next;
  noteValue(found, value, { isFile, isPattern: option === "--regexp" });
  return attached === undefined ? 1 : 0;
}

// The first valued letter in a cluster takes the rest of the word as its value
// (-n50), or the next word if nothing follows it (-n 50).
function readReaderShortCluster(spec, arg, next, found) {
  if (/^-\d+$/.test(arg)) return 0; // head -20, tail -100
  for (let position = 1; position < arg.length; position++) {
    const letter = arg[position];
    const isFile = spec.fileValued.includes(letter);
    if (!isFile && !spec.valued.includes(letter)) continue;
    const attached = arg.slice(position + 1);
    noteValue(found, attached || next, { isFile, isPattern: letter === "e" });
    return attached ? 0 : 1;
  }
  return 0;
}

function noteValue(found, value, { isFile, isPattern }) {
  if (isFile || isPattern) found.patternGiven = true;
  if (isFile && value !== undefined) found.files.push(value);
}

// ─── Sensitive paths ────────────────────────────────────────────────────────
// Readers like cat and grep are on the allowlist, so without this a
// prompt-injected model could read password hashes, SSH keys or cluster
// secrets with no approval. Best effort: a symlink, a hard link or a copy
// elsewhere can still reach the same data (see the README's residual risks).
//
// Paths that hold secrets, as segments; "*" matches any one segment. They match
// anywhere in a path, not just at the root, so /proc/1/root/etc/shadow and a
// container's /var/lib/lxc/101/rootfs/etc/shadow are caught too.
const SENSITIVE_PATHS = [
  "/etc/shadow",
  "/etc/shadow-", // the backup copy passwd tools keep
  "/etc/gshadow",
  "/etc/gshadow-",
  "/etc/pve/priv",
  "/etc/pve/user.cfg",
  "/etc/corosync/authkey",
  "/var/lib/pve-cluster", // config.db holds everything under /etc/pve, priv included
  "/root/.ssh",
  "/home/*/.ssh",
  "/proc/kcore", // physical memory (per-process files: see isSensitiveProcPath)
  "/etc/wireguard",
  "/etc/ppp/chap-secrets",
  "/etc/ppp/pap-secrets",
].map((pathText) => pathText.split("/").filter(Boolean));

// File or directory names that hold secrets wherever they are.
const SENSITIVE_NAMES = [
  /id_rsa/i,
  /id_ed25519/i,
  /id_ecdsa/i,
  /authorized_keys/i,
  /^ssh_host_/i,
  /^\.ssh$/i,
  /\.pem$/i,
  /\.key$/i,
  /^\.env(\..+)?$/i, // .env, .env.local, .env.production
  /\.env$/i, // prod.env
  /\.(keyring|p12|pfx|kdbx|jks)$/i, // Ceph keyrings, PKCS#12 bundles, password databases, Java keystores
  /^\.(netrc|pgpass|my\.cnf|git-credentials)$/i,
  /^\.\w*history$/i, // .bash_history, .zsh_history, .python_history: typed passwords end up here
  /^\.(aws|kube|docker|gnupg|password-store)$/i, // credential directories
  /^rclone\.conf$/i,
  /credentials/i, // Samba, AWS and other credential files
];

// Commands that print file contents. For these, raw devices are sensitive too:
// `head -c 100M /dev/sda` would dump the disk, secrets and all.
const CONTENT_READERS = new Set(["cat", "head", "tail", "grep"]);

// qm config and pct config are left on the allowlist. Their output can include
// secrets a user put there (API keys in a description, a cloud-init cipassword
// hash, hookscript arguments), but nothing in the command line says when that
// is the case, and the same data is available through the Proxmox API GET
// calls that already run without confirmation. Treat guest config as readable.

function touchesSensitivePath(name, args) {
  if (name === "grep" && isRecursiveGrep(args)) return true;
  return args.some((arg) =>
    pathCandidates(arg).some(
      (candidate) => isSensitivePath(candidate) || (CONTENT_READERS.has(name) && isRawDevice(candidate)),
    ),
  );
}

// The ways an argument can name a path: as itself (`/etc/shadow`), after an
// equals sign (`--file=/etc/shadow`), or attached to a short option (`-f/etc/shadow`).
function pathCandidates(arg) {
  const candidates = [arg];
  const equals = arg.indexOf("=");
  if (equals !== -1) candidates.push(arg.slice(equals + 1));
  const slash = arg.indexOf("/");
  if (arg.startsWith("-") && slash !== -1) candidates.push(arg.slice(slash));
  return candidates;
}

// Resolves `.`, `..` and repeated slashes, so /etc/../etc//shadow is /etc/shadow.
// A relative path's leading `..` segments are dropped: where they lead depends
// on the working directory, and matching anywhere in the path covers the rest.
function pathSegments(candidate) {
  return path.posix
    .normalize(candidate)
    .split("/")
    .filter((segment) => segment && segment !== "..");
}

// Files under /proc/<pid> (or self, thread-self, and task/<tid>) are sensitive
// except a few that only describe the process. The rest reach its environment,
// memory, open files (fd, map_files) or another root filesystem (root, cwd).
const PROC_PROCESS = /^(\d+|self|thread-self)$/;
const PROC_READABLE_FILES = new Set([
  "status", "stat", "statm", "cmdline", "comm", "limits", "io", "sched", "cgroup", "oom_score", "wchan",
]);

function isSensitiveProcPath(segments) {
  return segments.some((segment, index) => {
    if (segment !== "proc" || !PROC_PROCESS.test(segments[index + 1] ?? "")) return false;
    let rest = segments.slice(index + 2);
    if (rest[0] === "task" && rest.length > 1) rest = rest.slice(2); // task/<tid>/...
    if (rest.length === 0) return false; // the directory itself
    return !(rest.length === 1 && PROC_READABLE_FILES.has(rest[0]));
  });
}

// Dot-files and dot-directories directly in a home directory (/root/.x,
// /home/<user>/.x) hold shell history, tokens and tool credentials too often
// to list one by one.
function isHomeDotPath(segments) {
  return segments.some(
    (segment, index) =>
      (segment === "root" && segments[index + 1]?.startsWith(".")) ||
      (segment === "home" && segments[index + 1] !== undefined && segments[index + 2]?.startsWith(".")),
  );
}

function isSensitivePath(candidate) {
  const segments = pathSegments(candidate);
  if (isSensitiveProcPath(segments) || isHomeDotPath(segments)) return true;
  return segments.some(
    (segment, index) =>
      SENSITIVE_NAMES.some((pattern) => pattern.test(segment)) ||
      SENSITIVE_PATHS.some((sensitive) => startsWithSegments(segments.slice(index), sensitive)),
  );
}

// Anchored at the root (or the working directory, for a relative path), so a
// project folder that happens to be called "dev" is not caught.
function isRawDevice(candidate) {
  return pathSegments(candidate)[0] === "dev";
}

// True if `segments` is `prefix` or a path under it.
function startsWithSegments(segments, prefix) {
  return (
    segments.length >= prefix.length &&
    prefix.every((expected, index) => expected === "*" || expected === segments[index])
  );
}

// A recursive grep reads every file under a directory, so `grep -r x /etc`
// would read /etc/shadow without naming it. Checking each file it might reach
// isn't possible here, so recursive grep always needs confirmation.
//
// GNU grep accepts any unambiguous prefix of a long option (--rec) and of an
// option value (-d rec), so prefixes are matched, not exact spellings. A
// prefix too short to be unambiguous makes grep exit with an error, so
// matching it too is harmless.
function isRecursiveGrep(args) {
  return args.some((arg, index) => {
    const next = args[index + 1];
    if (/^-[A-Za-z]+$/.test(arg)) {
      // -r or -R anywhere in a cluster. That also covers a value attached to
      // -d (-drec, -idrecurse), since every prefix of "recurse" starts with r.
      // A cluster ending in d takes the next word as its value (-d rec).
      return /[rR]/.test(arg) || (arg.endsWith("d") && isRecurseValue(next));
    }
    if (!arg.startsWith("--")) return false;
    const [name, attachedValue] = splitLongOption(arg);
    if (isLongOptionPrefix(name, "--recursive") || isLongOptionPrefix(name, "--dereference-recursive"))
      return true;
    return isLongOptionPrefix(name, "--directories") && isRecurseValue(attachedValue ?? next);
  });
}

function splitLongOption(arg) {
  const equals = arg.indexOf("=");
  return equals === -1 ? [arg, undefined] : [arg.slice(0, equals), arg.slice(equals + 1)];
}

// "--rec" for "--recursive": at least one letter after the dashes.
const isLongOptionPrefix = (name, option) => name.length > 2 && option.startsWith(name);
const isRecurseValue = (value) => typeof value === "string" && value !== "" && "recurse".startsWith(value);

const anyArgs = () => true;
const onlyArgsIn = (...allowed) => (args) => args.every((arg) => allowed.includes(arg));

// ─── Exact option allowlists ────────────────────────────────────────────────
// A denylist of bad options fails the same way a denylist of bad commands
// does: `ss -D FILE` overwrites a file, and GNU getopt accepts any unambiguous
// abbreviation, so `ss --kil` and `journalctl --rot` slipped past rules that
// named --kill and --rotate. These commands instead list every option they
// accept, by exact name, and anything else is refused.
//
// spec fields, all optional:
//   flags        short letters that take no value, alone or clustered (-tlnp)
//   valued       short letters that take a value: the rest of the word
//                (-n50) or the next word (-n 50)
//   long         long options that take no value (--no-pager)
//   longValued   long options that take a value (--unit=x or --unit x)
//   longOptional long options with an optional attached value (--boot, --boot=-1)
//   optionalValued  { "-n": pattern } options whose value is optional in the real
//                program: the next word is taken only if it matches the pattern,
//                as the program does, and is otherwise checked as an option
//   valuePatterns   { "--since": pattern } options whose value may start with -
//   numeric      also accept -NUMBER words (tail -100, journalctl -b -1)
//   positional   check for each word that is not an option or a value
function optionsMatch(args, spec) {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    const next = args[index + 1];
    if (arg.startsWith("--")) {
      const [name, attachedValue] = splitLongOption(arg);
      if (spec.long?.includes(name) && attachedValue === undefined) continue;
      if (spec.longOptional?.includes(name)) continue;
      if (spec.optionalValued && Object.hasOwn(spec.optionalValued, name)) {
        if (attachedValue === undefined && spec.optionalValued[name].test(next ?? "")) index++;
        continue;
      }
      if (!spec.longValued?.includes(name)) return false;
      if (attachedValue !== undefined) continue;
      if (!isAcceptableValue(spec, name, next)) return false;
      index++;
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) {
      if (spec.numeric && /^-\d+$/.test(arg)) continue;
      const cluster = parseShortCluster(arg, spec);
      if (cluster === null) return false;
      if (cluster.optional) {
        if (spec.optionalValued[cluster.option].test(next ?? "")) index++;
        continue;
      }
      if (cluster.takesNext) {
        if (!isAcceptableValue(spec, cluster.option, next)) return false;
        index++;
      }
      continue;
    }
    if (spec.positional && !spec.positional(arg)) return false;
  }
  return true;
}

// A value taken from the next word. It must exist, and must not start with -
// unless the spec allows that for this option (valuePatterns): a program
// whose option argument is optional parses such a word as an option of its
// own, so skipping it here could hide one (journalctl -n --rotate).
function isAcceptableValue(spec, option, value) {
  if (value === undefined) return false;
  if (!value.startsWith("-")) return true;
  return Boolean(spec.valuePatterns?.[option]?.test(value));
}

// For a cluster like -tlnp or -n50: null if a letter isn't allowed. Otherwise
// the option the cluster ends in, whether it takes the next word as its value
// (takesNext), and whether that value is optional (optional). A valued letter
// with more letters after it has its value attached (-n50) and takes nothing.
function parseShortCluster(arg, spec) {
  for (let position = 1; position < arg.length; position++) {
    const letter = arg[position];
    const option = `-${letter}`;
    const isLast = position === arg.length - 1;
    if (spec.valued?.includes(letter)) return { option, takesNext: isLast, optional: false };
    if (spec.optionalValued && Object.hasOwn(spec.optionalValued, option))
      return { option, takesNext: false, optional: isLast };
    if (!spec.flags?.includes(letter)) return null;
  }
  return { option: null, takesNext: false, optional: false };
}

// For tools whose first word is a subcommand: the subcommand must be listed,
// and its remaining words must match that subcommand's spec.
const subcommands = (specs) => ([subcommand, ...rest]) =>
  Object.hasOwn(specs, subcommand) && optionsMatch(rest, specs[subcommand]);

const isVmid = (word) => /^\d+$/.test(word);
const isNotNumber = (word) => !/^\d+$/.test(word); // a bare number is a repeat interval for zpool

// ss: -K kills sockets, -D/--diag writes a raw dump to a file, -F reads a
// filter file, -N switches network namespace, -E streams events forever.
const SS_SPEC = {
  flags: "tulnpaemiosxw46rHOZzSdb0T",
  valued: "Af",
  long: [
    "--tcp", "--udp", "--listening", "--numeric", "--processes", "--all", "--extended",
    "--memory", "--info", "--options", "--summary", "--unix", "--raw", "--ipv4", "--ipv6",
    "--resolve", "--no-header", "--oneline", "--context", "--contexts", "--sctp", "--dccp",
    "--packet", "--threads",
  ],
  longValued: ["--query", "--socket", "--family"],
};

// journalctl: no maintenance (--rotate, --vacuum-*, --flush, --sync,
// --setup-keys, ...) and no -f/--follow, which would hold the SSH session open
// until the timeout. -D and --file are left out: they read arbitrary paths.
const JOURNAL_LINES = /^(\+?\d+|all)$/;
const RELATIVE_TIME = /^-\d+[a-z]*$/;
const JOURNALCTL_SPEC = {
  flags: "krxeaqlbmN",
  valued: "upSUotgFc",
  long: [
    "--no-pager", "--reverse", "--dmesg", "--all", "--quiet", "--full", "--no-full", "--utc",
    "--no-hostname", "--list-boots", "--disk-usage", "--system", "--merge", "--catalog",
    "--pager-end", "--fields",
  ],
  longValued: [
    "--unit", "--priority", "--since", "--until", "--output", "--identifier",
    "--grep", "--field", "--cursor", "--after-cursor", "--facility",
  ],
  longOptional: ["--boot"],
  // -n/--lines takes the next word only if it is [+]N or "all" (systemd's
  // parse_lines, graceful); otherwise the word is parsed as an option.
  optionalValued: { "-n": JOURNAL_LINES, "--lines": JOURNAL_LINES },
  // Relative times such as -1h are values, not options.
  valuePatterns: { "-S": RELATIVE_TIME, "--since": RELATIVE_TIME, "-U": RELATIVE_TIME, "--until": RELATIVE_TIME },
  numeric: true,
};

// sensors: -s/--set applies limits; -c reads an arbitrary config file.
const SENSORS_SPEC = { flags: "ujfAv", long: ["--fahrenheit", "--no-adapter"] };

// systemctl: only these subcommands, and no -H/--host or -M/--machine (they
// reach other machines) or --root.
const SYSTEMCTL_OPTIONS = {
  flags: "laq",
  valued: "tnop",
  long: ["--no-pager", "--full", "--all", "--plain", "--no-legend", "--quiet", "--failed", "--no-ask-password"],
  longValued: ["--type", "--state", "--lines", "--output", "--property"],
};

// tail: no -f/-F/--follow/--retry/-s, which only make sense while following.
const TAIL_SPEC = {
  flags: "qvz",
  valued: "nc",
  long: ["--quiet", "--silent", "--verbose", "--zero-terminated"],
  longValued: ["--lines", "--bytes"],
  numeric: true,
};

// find: every predicate is named, with whether it takes a value. Anything that
// runs, deletes or writes (-exec, -delete, -fprint, -fls, ...) is absent.
const FIND_PREDICATES = new Map([
  ...["-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex",
    "-type", "-xtype", "-maxdepth", "-mindepth", "-mtime", "-mmin", "-atime", "-amin",
    "-ctime", "-cmin", "-size", "-newer", "-user", "-group", "-uid", "-gid", "-perm",
    "-links", "-inum", "-samefile", "-printf", "-fstype"].map((name) => [name, 1]),
  ...["-print", "-print0", "-ls", "-empty", "-xdev", "-mount", "-o", "-a", "-or", "-and",
    "-not", "-prune", "-nouser", "-nogroup", "-readable", "-writable", "-executable",
    "-true", "-false", "-H", "-L", "-P", "-follow", "-daystart", "-depth", "-quit"].map((name) => [name, 0]),
]);

function isReadonlyFind(args) {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!arg.startsWith("-")) continue; // a starting path
    if (!FIND_PREDICATES.has(arg)) return false;
    index += FIND_PREDICATES.get(arg); // a value may itself start with - (-mtime -7)
    if (index >= args.length) return false;
  }
  return true;
}

// Proxmox CLI boolean options may be given bare (--current) or with =value.
const pveBooleans = (...names) => ({ longOptional: names });

// ─── smartctl ───────────────────────────────────────────────────────────────
// smartctl mixes read and write forms behind the same options: `-l scterc`
// reads the error recovery setting, but `-l scterc,70,70` sets it, and
// `-l scttempint,N` sets the logging interval. So the value after -l / --log
// must be a known read-only log name, with nothing after it.
const SMARTCTL_READ_LOGS = new Set([
  "error",
  "xerror",
  "selftest",
  "xselftest",
  "directory",
  "background",
  "scttemp",
  "scttempsts",
  "scttemphist",
  "scterc",
  "sataphy",
  "sasphy",
  "devstat",
  "ssd",
]);
// A device type such as sat, scsi, nvme or auto. Types that take extra values
// (megaraid,N and so on) are left out on purpose.
const SMARTCTL_DEVICE_TYPE = /^[a-z][a-z0-9]*$/;
// Option clusters that only print: -a all, -x xall, -H health, -i info,
// -A attributes, -c capabilities, -j json. Anything else (-s, -t, -X, -o, -S
// and so on) can enable, start or abort something, so it is refused.
const SMARTCTL_PRINT_CLUSTER = /^-[aAHixcj]+$/;
const SMARTCTL_PRINT_LONG = new Set(["--all", "--xall", "--health", "--info", "--attributes", "--capabilities", "--json"]);
// Options that take a value, and the check that value must pass.
const SMARTCTL_VALUE_OPTIONS = {
  "-l": (value) => SMARTCTL_READ_LOGS.has(value),
  "--log": (value) => SMARTCTL_READ_LOGS.has(value),
  "-d": (value) => SMARTCTL_DEVICE_TYPE.test(value),
  "--device": (value) => SMARTCTL_DEVICE_TYPE.test(value),
};

// Splits `--log=error` or `-lerror` into the option and its attached value.
function splitSmartctlOption(arg) {
  if (arg.startsWith("--")) {
    const equals = arg.indexOf("=");
    return equals === -1 ? [arg, undefined] : [arg.slice(0, equals), arg.slice(equals + 1)];
  }
  if (/^-[ld]./.test(arg)) return [arg.slice(0, 2), arg.slice(2)];
  return [arg, undefined];
}

// Walks the arguments in order so a value is always checked as the value of
// its option, never mistaken for a device path.
function isReadonlySmartctl(args) {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!arg.startsWith("-")) continue; // a device path
    if (SMARTCTL_PRINT_CLUSTER.test(arg) || SMARTCTL_PRINT_LONG.has(arg)) continue;
    const [option, attachedValue] = splitSmartctlOption(arg);
    if (!Object.hasOwn(SMARTCTL_VALUE_OPTIONS, option)) return false;
    const value = attachedValue ?? args[++index];
    if (value === undefined || !SMARTCTL_VALUE_OPTIONS[option](value)) return false;
  }
  return true;
}

// ─── ps ─────────────────────────────────────────────────────────────────────
// procps reparses the whole command line in BSD mode whenever the normal parse
// fails (parser.c, try_bsd), and in BSD mode a word containing e prints every
// process's environment, the same data /proc/*/environ holds. A failure is
// easy to cause (an unknown user, a bad format key, conflicting formats), and
// then -ef, or a value such as a user name containing e, becomes that request.
// So ps accepts only shapes that can't fail: at most one selection and one
// format, with values from fixed sets.
const PS_BSD_COMMANDS = new Set(["aux", "auxww", "axjf", "ax"]);
// -e or -A (select all) and a SysV format letter, alone or combined (-ef, -ely).
const PS_CLUSTER = /^-(?<select>[eA])?(?<format>f|F|l|ly)?$/;
const PS_CLUSTER_WITH_FORMAT_LIST = /^-(?<select>[eA])?o$/; // -o FORMAT, -eo FORMAT
const PS_FORMAT_KEYS = new Set([
  "pid", "ppid", "pgid", "sid", "uid", "user", "ruser", "euser", "gid", "group", "tty", "stat",
  "state", "ni", "pri", "psr", "nlwp", "lwp", "%cpu", "pcpu", "%mem", "pmem", "rss", "vsz", "sz",
  "time", "etime", "etimes", "start", "lstart", "stime", "cmd", "args", "comm", "ucmd", "wchan",
]);
const isPsFormat = (value) => value?.split(",").every((key) => PS_FORMAT_KEYS.has(key)) ?? false;
const isPsSort = (value) =>
  value?.split(",").every((key) => PS_FORMAT_KEYS.has(key.replace(/^[+-]/, ""))) ?? false;
const PS_PID_LIST = /^\d+(,\d+)*$/;
const PS_COMMAND_LIST = /^[A-Za-z0-9_.@:+][A-Za-z0-9_.@:+-]*(,[A-Za-z0-9_.@:+][A-Za-z0-9_.@:+-]*)*$/;

// What one ps word asks for: the parts of the command it claims (selection,
// format, sort) and how many following words it consumes, or null if it isn't
// an accepted shape.
function readPsWord(arg, next) {
  if (arg === "--no-headers") return { parts: [], consumes: 0 };
  if (arg === "-p") return PS_PID_LIST.test(next ?? "") ? { parts: ["selection"], consumes: 1 } : null;
  if (arg === "-C") return PS_COMMAND_LIST.test(next ?? "") ? { parts: ["selection"], consumes: 1 } : null;
  const [name, attached] = splitLongOption(arg);
  if (name === "--sort") return readPsSort(attached, next);
  return readPsCluster(arg, next);
}

function readPsSort(attached, next) {
  const keys = attached ?? next;
  return isPsSort(keys) ? { parts: ["sort"], consumes: attached === undefined ? 1 : 0 } : null;
}

// -e, -A, -f, -ef, -ely and so on, or -o / -eo followed by a format list.
function readPsCluster(arg, next) {
  if (arg === "-") return null;
  const cluster = PS_CLUSTER.exec(arg) ?? PS_CLUSTER_WITH_FORMAT_LIST.exec(arg);
  if (!cluster) return null;
  const { select, format } = cluster.groups;
  const parts = [select && "selection", format && "format"].filter(Boolean);
  if (!arg.endsWith("o")) return { parts, consumes: 0 };
  return isPsFormat(next) ? { parts: [...parts, "format"], consumes: 1 } : null;
}

// Each part may be claimed once: a second selection or format could conflict,
// and a conflict is a parse failure, which is what triggers the BSD retry.
function isReadonlyPs(args) {
  if (args.length === 1 && PS_BSD_COMMANDS.has(args[0])) return true;
  const claimed = new Set();
  for (let index = 0; index < args.length; index++) {
    const word = readPsWord(args[index], args[index + 1]);
    if (!word || word.parts.some((part) => claimed.has(part))) return false;
    for (const part of word.parts) claimed.add(part);
    index += word.consumes;
  }
  return true;
}

const READONLY_COMMANDS = {
  // Readers whose options can't change anything.
  ls: anyArgs,
  cat: anyArgs,
  head: anyArgs,
  grep: anyArgs,
  wc: anyArgs,
  stat: anyArgs,
  df: anyArgs,
  du: anyArgs,
  free: anyArgs,
  uptime: anyArgs,
  ps: isReadonlyPs,
  lsblk: anyArgs,
  uname: anyArgs,
  whoami: anyArgs,
  pveversion: anyArgs,

  // Readers that also have state-changing forms, which are refused.
  hostname: onlyArgsIn("-I", "-i", "-f", "-s", "-d", "-A", "-a", "--fqdn", "--short"), // a name argument sets it
  date: (args) => args.every((arg) => arg.startsWith("+") || ["-u", "--utc", "-R", "-I"].includes(arg)), // -s / MMDDhhmm set the clock
  // These list every option they accept (see "Exact option allowlists").
  tail: (args) => optionsMatch(args, TAIL_SPEC),
  find: isReadonlyFind,
  journalctl: (args) => optionsMatch(args, JOURNALCTL_SPEC),
  ss: (args) => optionsMatch(args, SS_SPEC),
  sensors: (args) => optionsMatch(args, SENSORS_SPEC),
  smartctl: isReadonlySmartctl,
  ip: (args) =>
    ["a", "addr", "address", "r", "route", "link"].includes(args[0]) &&
    (args.length === 1 || ["show", "list", "ls", "sh"].includes(args[1])),

  // Tools whose read-only subcommands are allowed, each with its own options.
  zfs: subcommands({ list: { flags: "rHp", valued: "otsSd" } }),
  zpool: subcommands({
    status: { flags: "xvPLpgD", positional: isNotNumber },
    list: { flags: "HpPvgL", valued: "o", positional: isNotNumber },
  }),
  pvesm: subcommands({ status: { longValued: ["--storage", "--content", "--enabled", "--format", "--target"] } }),
  qm: subcommands({
    list: { longValued: ["--full"] },
    config: { ...pveBooleans("--current"), longValued: ["--snapshot"], positional: isVmid },
    status: { ...pveBooleans("--verbose"), positional: isVmid },
  }),
  pct: subcommands({
    list: {},
    config: { ...pveBooleans("--current"), longValued: ["--snapshot"], positional: isVmid },
    status: { ...pveBooleans("--verbose"), positional: isVmid },
  }),
  systemctl: subcommands({
    status: SYSTEMCTL_OPTIONS,
    "list-units": SYSTEMCTL_OPTIONS,
    "is-active": SYSTEMCTL_OPTIONS,
  }),
};
