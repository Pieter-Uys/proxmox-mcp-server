import path from "node:path";
import { SECURITY } from "./config.js";

// ─── Shell command confirmation (SHELL_MODE=full) ───────────────────────────
// Any command the read-only allowlist doesn't accept needs confirm: true.
// A list of known-dangerous commands can never be complete (find -delete,
// ip link set down, lvremove, qm set --delete, ...), so approval is the default.
export function shellConfirmationReason(args) {
  const command = String(args.command || "");
  if (isReadonlyCommand(command)) return null;
  return readsSensitivePath(command)
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
  if (!reason || args.confirm === true) return null;
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
  if (!words) return false;
  const [name, ...args] = words;
  return (
    Object.hasOwn(READONLY_COMMANDS, name) &&
    READONLY_COMMANDS[name](args) &&
    !touchesSensitivePath(name, args)
  );
}

// The command's words, or null if any word is something the shell would interpret.
function plainWords(command) {
  const words = command.trim().split(/[ \t]+/);
  return words.every((word) => PLAIN_WORD.test(word)) ? words : null;
}

function readsSensitivePath(command) {
  const words = plainWords(command);
  return words !== null && touchesSensitivePath(words[0], words.slice(1));
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
  /\.env$/i,
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
function isRecursiveGrep(args) {
  return args.some(
    (arg, index) =>
      (/^-[A-Za-z]+$/.test(arg) && /[rR]/.test(arg)) ||
      /^--(dereference-)?recursive$/.test(arg) ||
      arg === "--directories=recurse" ||
      arg === "-drecurse" ||
      (arg === "-d" && args[index + 1] === "recurse") ||
      (arg === "--directories" && args[index + 1] === "recurse"),
  );
}

const anyArgs = () => true;
const firstArgIn = (...allowed) => (args) => allowed.includes(args[0]);
const onlyArgsIn = (...allowed) => (args) => args.every((arg) => allowed.includes(arg));
const noArgIn = (...forbidden) => (args) => !args.some((arg) => forbidden.includes(arg));
// True if a short-option cluster such as `-tlnK` contains `letter`.
const hasShortOption = (args, letter) =>
  args.some((arg) => /^-[A-Za-z]+$/.test(arg) && arg.includes(letter));
const hasLongOption = (args, name) =>
  args.some((arg) => arg === name || arg.startsWith(`${name}=`));

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

const READONLY_COMMANDS = {
  // Readers whose options can't change anything.
  ls: anyArgs,
  cat: anyArgs,
  head: anyArgs,
  tail: anyArgs,
  grep: anyArgs,
  wc: anyArgs,
  stat: anyArgs,
  df: anyArgs,
  du: anyArgs,
  free: anyArgs,
  uptime: anyArgs,
  ps: anyArgs,
  lsblk: anyArgs,
  uname: anyArgs,
  whoami: anyArgs,
  pveversion: anyArgs,

  // Readers that also have state-changing forms, which are refused.
  hostname: onlyArgsIn("-I", "-i", "-f", "-s", "-d", "-A", "-a", "--fqdn", "--short"), // a name argument sets it
  date: (args) => args.every((arg) => arg.startsWith("+") || ["-u", "--utc", "-R", "-I"].includes(arg)), // -s / MMDDhhmm set the clock
  find: noArgIn("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"),
  journalctl: (args) =>
    !args.some((arg) =>
      /^--(vacuum|rotate|flush|sync|relinquish-var|smart-relinquish-var|setup-keys|update-catalog)/.test(arg),
    ),
  ss: (args) => !hasShortOption(args, "K") && !hasLongOption(args, "--kill"), // -K kills sockets
  sensors: (args) => !hasShortOption(args, "s") && !hasLongOption(args, "--set"),
  smartctl: isReadonlySmartctl,
  ip: (args) =>
    ["a", "addr", "address", "r", "route", "link"].includes(args[0]) &&
    (args.length === 1 || ["show", "list", "ls", "sh"].includes(args[1])),

  // Tools whose read-only subcommands are allowed.
  zfs: firstArgIn("list"),
  zpool: firstArgIn("status", "list"),
  pvesm: firstArgIn("status"),
  qm: firstArgIn("list", "config", "status"),
  pct: firstArgIn("list", "config", "status"),
  systemctl: firstArgIn("status", "list-units", "is-active"),
};
