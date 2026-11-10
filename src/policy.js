import path from "node:path";
import { SECURITY } from "./config.js";

// ─── Shell command confirmation (SHELL_MODE=full) ───────────────────────────
// Any command the read-only allowlist doesn't accept needs confirm: true.
// A list of known-dangerous commands can never be complete (find -delete,
// ip link set down, lvremove, qm set --delete, ...), so approval is the default.
export function shellConfirmationReason(args) {
  const command = String(args.command || "");
  if (isReadonlyCommand(command)) return null;
  return readsSensitivePathOnly(command)
    ? "This command reads a path that can hold secrets (keys, password hashes, cluster credentials)."
    : "This command isn't on the read-only list, so it could change the system.";
}

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
    return isReadonlyCommand(command)
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

// A command that reads a sensitive path is never read-only in the sense that
// matters here: it needs confirm: true, and SHELL_MODE=readonly refuses it.
export function isReadonlyCommand(command) {
  const words = plainWords(command);
  return words !== null && passesAllowlist(words) && !touchesSensitivePath(words[0], words.slice(1));
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

// True if the command would be read-only but for a sensitive path. Commands
// that could also change something (rm, chmod) get the general reason instead,
// so the approval text never calls a delete a read.
function readsSensitivePathOnly(command) {
  const words = plainWords(command);
  return words !== null && passesAllowlist(words) && touchesSensitivePath(words[0], words.slice(1));
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
  "/proc/*/environ", // another process's environment, which often carries secrets
  "/proc/*/root", // a view of another root filesystem, which would bypass the rest
  "/proc/*/cwd",
  "/proc/kcore",
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

function isSensitivePath(candidate) {
  const segments = pathSegments(candidate);
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
//   numeric      also accept -NUMBER words (tail -100, journalctl -b -1)
//   positional   check for each word that is not an option or a value
function optionsMatch(args, spec) {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg.startsWith("--")) {
      const [name, attachedValue] = splitLongOption(arg);
      if (spec.long?.includes(name) && attachedValue === undefined) continue;
      if (spec.longOptional?.includes(name)) continue;
      if (!spec.longValued?.includes(name)) return false;
      if (attachedValue === undefined && ++index >= args.length) return false;
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) {
      if (spec.numeric && /^-\d+$/.test(arg)) continue;
      const consumesNext = shortClusterTakesNextWord(arg, spec);
      if (consumesNext === null) return false;
      if (consumesNext && ++index >= args.length) return false;
      continue;
    }
    if (spec.positional && !spec.positional(arg)) return false;
  }
  return true;
}

// For a cluster like -tlnp or -n50: null if a letter isn't allowed, true if the
// cluster ends in a valued letter whose value is the next word, otherwise false.
function shortClusterTakesNextWord(arg, spec) {
  for (let position = 1; position < arg.length; position++) {
    const letter = arg[position];
    if (spec.valued?.includes(letter)) return position === arg.length - 1;
    if (!spec.flags?.includes(letter)) return null;
  }
  return false;
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
const JOURNALCTL_SPEC = {
  flags: "krxeaqlbmN",
  valued: "unpSUotgFc",
  long: [
    "--no-pager", "--reverse", "--dmesg", "--all", "--quiet", "--full", "--no-full", "--utc",
    "--no-hostname", "--list-boots", "--disk-usage", "--system", "--merge", "--catalog",
    "--pager-end", "--fields",
  ],
  longValued: [
    "--unit", "--lines", "--priority", "--since", "--until", "--output", "--identifier",
    "--grep", "--field", "--cursor", "--after-cursor", "--facility",
  ],
  longOptional: ["--boot"],
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
// BSD-style ps options (no dash) include `e`, which prints every process's
// environment after its command: `ps eww`, `ps auxe`. That is the same data
// /proc/*/environ holds, so it is treated the same way.
// Short options that take the next word as a value, alone (-o) or at the end of a cluster (-eo).
const PS_VALUE_LETTERS = "CGUgpqstuoOk";
const PS_LONG_VALUE_OPTIONS = /^--(pid|ppid|sid|tty|user|User|group|Group|format|sort|cols|columns|rows|width|quick-pid)$/;

function printsProcessEnvironment(args) {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    const takesValue = /^-[A-Za-z]+$/.test(arg) && PS_VALUE_LETTERS.includes(arg.at(-1));
    if (takesValue || PS_LONG_VALUE_OPTIONS.test(arg)) {
      index++; // the option's value, e.g. the name in -C pveproxy
      continue;
    }
    if (/^[A-Za-z]+$/.test(arg) && arg.includes("e")) return true;
  }
  return false;
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
  ps: (args) => !printsProcessEnvironment(args),
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
