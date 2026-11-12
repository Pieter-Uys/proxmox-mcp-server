// ─── Running as a dedicated user with sudo ──────────────────────────────────
// With PROXMOX_SSH_SUDO=on, the server connects as an unprivileged user and
// only the Proxmox tools below are run with `sudo -n`. The sudoers file in
// deploy/sudoers.proxmox-mcp then decides which forms of them may run as root:
// pct exec, the read-only forms of pct, qm, pvesm, zpool and zfs list,
// zfs create with a fixed set of properties, and ifreload -a. Everything else,
// including an approved host_shell command, runs with the user's own rights.
//
// That makes the sudoers file, not the read-only parser, the limit on what an
// approved command can do as root: it holds even when the parser is wrong.
// Whole-command rules (`pct *`, `zfs *`) would be root-equivalent (pct push,
// pct create with a bind mount, qm set --args, zfs destroy), so the file lists
// subcommand forms, and test/privilege.test.js checks it against this module.

// Commands whose first word is one of these get `sudo -n` in front.
export const SUDO_COMMANDS = new Set(["pct", "qm", "pvesm", "zfs", "zpool", "ifreload"]);

// ZFS properties zfs create may set under sudo. Left out on purpose:
// mountpoint and canmount (a dataset mounted over /etc or /root), sharenfs and
// sharesmb (with mountpoint, a remote client writing into it as root), and
// setuid, exec, devices, zoned and the encryption and key properties.
export const SUDO_ZFS_PROPERTIES = new Set([
  "atime", "relatime", "compression", "recordsize", "quota", "refquota", "reservation", "refreservation",
  "xattr", "acltype", "sync", "primarycache", "secondarycache", "logbias", "dedup", "copies", "checksum",
  "dnodesize", "special_small_blocks", "readonly",
]);

// Values those properties take (lz4, 128K, 10G, off, posixacl).
export const SUDO_ZFS_VALUE = /^[A-Za-z0-9_.-]+$/;

// `command` as sent to the host: with `sudo -n ` in front when sudo is on and
// its first word is a Proxmox tool. -n makes sudo fail at once instead of
// waiting for a password when sudoers doesn't allow the form.
export function withHostPrivilege(command, sudo) {
  if (!sudo) return command;
  const trimmed = command.trimStart();
  const firstWord = trimmed.split(/[ \t]/, 1)[0];
  return SUDO_COMMANDS.has(firstWord) ? `sudo -n ${trimmed}` : command;
}

// Why zfs create can't set these properties under sudo, or null.
export function sudoZfsPropertiesRefusal(properties = {}) {
  for (const [name, value] of Object.entries(properties)) {
    if (!SUDO_ZFS_PROPERTIES.has(name))
      return `With PROXMOX_SSH_SUDO=on, zfs create can't set ${String(name).slice(0, 60)} (sudoers allows only: ${[...SUDO_ZFS_PROPERTIES].join(", ")}).`;
    if (!SUDO_ZFS_VALUE.test(value))
      return `With PROXMOX_SSH_SUDO=on, ZFS property values may only use letters, digits and _ . - (got ${name}=${String(value).slice(0, 40)}).`;
  }
  return null;
}
