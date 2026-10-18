import { SECURITY } from "./config.js";

// ─── Shell command confirmation (SHELL_MODE=full) ───────────────────────────
// Any command the read-only allowlist doesn't accept needs confirm: true.
// A list of known-dangerous commands can never be complete (find -delete,
// ip link set down, lvremove, qm set --delete, ...), so approval is the default.
export function shellConfirmationReason(args) {
  return isReadonlyCommand(String(args.command || ""))
    ? null
    : "This command isn't on the read-only list, so it could change the system.";
}

// ─── Policy: shell mode and destructive-action confirmation ─────────────────
// Returns a reason string if server policy blocks this call, or null if it may run.
export function getPolicyBlockReason(tool, args) {
  if (!tool) return null; // callTool reports unknown tools

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

export function isReadonlyCommand(command) {
  const words = command.trim().split(/[ \t]+/);
  if (!words.every((word) => PLAIN_WORD.test(word))) return false;
  const [name, ...args] = words;
  return Object.hasOwn(READONLY_COMMANDS, name) && READONLY_COMMANDS[name](args);
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
  smartctl: (args) =>
    args.every(
      (arg) =>
        !arg.startsWith("-") ||
        /^(-[aAHixcj]+|-[ld]\S*|--(all|xall|health|info|attributes|capabilities|json)|--(log|device)=\S+)$/.test(arg),
    ), // refuses -s, -t, -X, -o, -S (these enable, start or abort things)
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
