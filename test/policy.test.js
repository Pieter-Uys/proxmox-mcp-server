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
  "smartctl -l error /dev/sda",
  "smartctl -l scterc /dev/sda",
  "smartctl --log=selftest /dev/sda",
  "smartctl -lxerror /dev/sda",
  "smartctl -d sat -H /dev/sda",
  "smartctl --device=nvme -a /dev/nvme0",
  "smartctl -x -j /dev/sda",
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
  "smartctl set forms hidden behind -l, --log and -d": [
    "smartctl -l scterc,70,70 /dev/sda",
    "smartctl --log=scterc,70,70 /dev/sda",
    "smartctl -lscterc,70,70 /dev/sda",
    "smartctl --log scterc,70,70 /dev/sda",
    "smartctl -l scttempint,60 /dev/sda",
    "smartctl -l scttempint,60,p /dev/sda",
    "smartctl -l unknownlog /dev/sda",
    "smartctl -l /dev/sda",
    "smartctl -l",
    "smartctl -d -s on /dev/sda",
    "smartctl -d sat,auto -s on /dev/sda",
    "smartctl --device=-s /dev/sda",
    "smartctl -d megaraid,0 /dev/sda",
    "smartctl -a -o on /dev/sda",
    "smartctl -X /dev/sda",
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

// ─── Sensitive paths ────────────────────────────────────────────────────────
// One command per line, so long tables of commands stay easy to read.
const lines = (text) =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

const SENSITIVE_READS = {
  "listed paths and anything under them": lines(`
    cat /etc/shadow
    cat /etc/shadow-
    cat /etc/gshadow
    ls /etc/pve/priv
    cat /etc/pve/priv/authkey.key
    cat /etc/pve/priv/token.cfg
    cat /etc/pve/user.cfg
    cat /etc/corosync/authkey
    ls -la /root/.ssh
    cat /root/.ssh/config
    cat /home/alice/.ssh/config
    cat /etc/ssh/ssh_host_ed25519_key
    stat /etc/ssh/ssh_host_rsa_key.pub
    du -sh /var/lib/pve-cluster
    head /var/lib/pve-cluster/config.db
    cat /proc/1/environ
  `),
  "secret-looking file names anywhere": lines(`
    cat /opt/app/id_rsa
    cat /srv/backup/id_ed25519.bak
    cat /etc/ssl/private/server.pem
    cat /etc/pve/nodes/pve/pve-ssl.key
    cat /opt/proxmox-mcp/.env
    cat .env
    tail /root/.ssh/authorized_keys
    find / -name authorized_keys
    cat /opt/app/.env.production
    cat /srv/app/.env.local
  `),
  "traversal, repeated slashes and other roots": lines(`
    cat /etc/../etc/shadow
    cat /etc//shadow
    cat //etc/shadow
    cat /var/../etc/./shadow
    cat ../../etc/shadow
    cat etc/shadow
    cat /proc/1/root/etc/shadow
    cat /var/lib/lxc/101/rootfs/etc/shadow
    cat /home/alice/../../root/.ssh/id_ed25519
  `),
  "paths passed as option values": lines(`
    grep -f /etc/shadow /var/log/syslog
    grep -f/etc/shadow /var/log/syslog
    grep --file=/etc/shadow /var/log/syslog
    find /var -newer /etc/shadow
  `),
  "recursive grep, which would reach secrets without naming them": lines(`
    grep -r password /etc
    grep -R password /etc
    grep -rn password /var/log
    grep --recursive password /etc
    grep -d recurse password /etc
    grep --directories=recurse password /etc
    grep --rec password /etc
    grep --der password /etc
    grep -d rec password /etc
    grep -id recurse password /etc
    grep -drec password /etc
    grep --directories=rec password /etc
    grep --directories recurse password /etc
  `),
  "process environments printed by ps": lines(`
    ps eww
    ps auxe
    ps e
    ps -C pveproxy e
  `),
  "raw devices read by content readers": lines(`
    head -c 1000000 /dev/sda
    cat /dev/mapper/pve-root
    grep -a root /dev/sda1
  `),
};

for (const [group, commands] of Object.entries(SENSITIVE_READS)) {
  test(`sensitive reads are not read-only: ${group}`, async () => {
    for (const command of commands) {
      assert.equal(isReadonlyCommand(command), false, `should not be read-only: ${command}`);
      await withShellMode("full", () => {
        // ps environment output is refused by the ps rule itself, so it gets the general reason.
        const expected = group.startsWith("process environments") ? /could change the system.*confirm: true/ : /secrets.*confirm: true/;
        assert.match(getPolicyBlockReason(TOOLS.host_shell, { command }), expected, command);
        assert.equal(getPolicyBlockReason(TOOLS.host_shell, { command, confirm: true }), null, command);
      });
      await withShellMode("readonly", () => {
        assert.match(
          getPolicyBlockReason(TOOLS.host_shell, { command, confirm: true }),
          /SHELL_MODE=readonly/,
          command,
        );
      });
    }
  });
}

test("ordinary reads stay read-only next to the sensitive-path check", () => {
  for (const command of [
    "cat /etc/hostname",
    "ls /var/log",
    "ls /etc/pve",
    "ls /root",
    "cat /etc/ssh/sshd_config",
    "cat /etc/pve/storage.cfg",
    "grep error /var/log/syslog",
    "grep -i error /var/log/syslog",
    "tail -n 100 /var/log/syslog",
    "stat /etc/passwd",
    "du -sh /var/lib/vz",
    "cat /home/alice/dev/notes.txt",
    "smartctl -a /dev/sda",
    "lsblk /dev/sda",
    "ls /dev",
    "grep -d skip error /var/log/syslog",
    "grep --devices=skip error /var/log/syslog",
    "grep --regexp=error /var/log/syslog",
    "cat /etc/environment",
    "ps aux",
    "ps -ef",
    "ps -eo user,pid,comm",
    "ps -o user",
    "ps -C pveproxy",
    "ps --sort=pid",
  ]) {
    assert.equal(isReadonlyCommand(command), true, `should allow: ${command}`);
  }
});

test("the confirmation reason names secrets only for reads, never for commands that change things", async () => {
  await withShellMode("full", () => {
    assert.match(getPolicyBlockReason(TOOLS.host_shell, { command: "cat /etc/shadow" }), /reads a path that can hold secrets/);
    for (const command of ["rm -rf /root/.ssh", "chmod 777 /etc/shadow", "cp /etc/shadow /tmp/x"]) {
      const reason = getPolicyBlockReason(TOOLS.host_shell, { command });
      assert.match(reason, /could change the system/, command);
      assert.doesNotMatch(reason, /reads a path/, command);
    }
  });
});

test("lxc_shell and vm_ssh apply the same sensitive-path check", async () => {
  await withShellMode("full", () => {
    assert.match(getPolicyBlockReason(TOOLS.lxc_shell, { vmid: 101, command: "cat /etc/shadow" }), /secrets/);
    assert.match(getPolicyBlockReason(TOOLS.vm_ssh, { ip: "10.0.0.5", command: "cat /root/.ssh/id_rsa" }), /secrets/);
  });
});

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
      getPolicyBlockReason(TOOLS.storage_config, { action: "zfs_create", dataset: "tank/x", confirm: true }),
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

// ─── Exact option allowlists (audit H1, H4) ─────────────────────────────────
const STATE_CHANGING_OPTIONS = {
  "ss writes or kills": lines(`
    ss -D /etc/network/interfaces
    ss --diag=/etc/hosts
    ss --diag /etc/hosts
    ss -tlnD /tmp/x
    ss --kil
    ss --ki
    ss -F /etc/shadow
    ss -N other
    ss -E
  `),
  "journalctl maintenance, including abbreviations": lines(`
    journalctl --rot
    journalctl --flu
    journalctl --vacuum-t=1s
    journalctl --setup
    journalctl --sync
    journalctl --relinquish
    journalctl --update-cat
    journalctl --file=/var/lib/pve-cluster/config.db
    journalctl -D /var/log/journal
  `),
  "sensors set and config forms": lines(`
    sensors --se
    sensors -s
    sensors -c /etc/sensors3.conf
  `),
  "systemctl reaching other machines or changing state": lines(`
    systemctl status --host=root@other
    systemctl status -H root@other
    systemctl status --machine=foo
    systemctl list-units -M foo
    systemctl status --root=/mnt
  `),
  "find predicates outside the named set": lines(`
    find / -delet
    find / -execdir id
    find / -fls /tmp/x
    find / -newerXY x
  `),
  "zfs, zpool, pvesm, qm and pct options they don't name": lines(`
    zfs list -bogus
    zfs list --bogus
    zpool status 1
    zpool status -T d 1
    zpool list 5
    pvesm status --delete local
    qm config 100 --delete net0
    qm config abc
    pct config 101 --bogus
    qm list --bogus
  `),
  "follow modes that hold the connection open (H4)": lines(`
    tail -f /var/log/syslog
    tail -F /var/log/syslog
    tail -qf /var/log/syslog
    tail --follow /var/log/syslog
    tail --follow=name /var/log/syslog
    tail --retry /var/log/syslog
    tail -s 1 /var/log/syslog
    journalctl -f
    journalctl --follow
    journalctl -fu pveproxy
    journalctl -u pveproxy -f
  `),
};

for (const [group, commands] of Object.entries(STATE_CHANGING_OPTIONS)) {
  test(`read-only allowlist refuses ${group}`, () => {
    for (const command of commands) {
      assert.equal(isReadonlyCommand(command), false, `should refuse: ${command}`);
    }
  });
}

test("commands with option rules refuse an option they don't name", () => {
  for (const base of [
    "ss",
    "journalctl",
    "sensors",
    "systemctl status pveproxy",
    "find /var/log",
    "tail /var/log/syslog",
    "zfs list",
    "zpool status",
    "zpool list",
    "pvesm status",
    "qm list",
    "qm config 100",
    "qm status 100",
    "pct list",
    "pct config 101",
    "pct status 101",
  ]) {
    for (const option of ["--definitely-not-an-option", "-Q"]) {
      assert.equal(isReadonlyCommand(`${base} ${option}`), false, `should refuse: ${base} ${option}`);
    }
  }
});

test("everyday read options keep working under the exact allowlists", () => {
  for (const command of lines(`
    ss -tlnp
    ss -tunap
    ss -s
    ss --tcp --listening --numeric --processes
    ss -tn state established
    ss -A tcp
    journalctl -u pveproxy -n 50
    journalctl -u pveproxy --since=today --no-pager
    journalctl -b -1 -p err
    journalctl -k -n 100
    journalctl --list-boots
    journalctl --disk-usage
    journalctl -o json -n 5
    journalctl -xe --no-pager
    sensors
    sensors -j
    sensors -u coretemp-isa-0000
    systemctl status pveproxy
    systemctl status pveproxy --no-pager -l
    systemctl list-units --type=service --state=running
    systemctl list-units -t service --failed
    systemctl is-active pveproxy
    find /var/log -name syslog
    find /var/log -type f -mtime -7 -size +1M
    find /etc/pve -maxdepth 1 -type d
    find / -xdev -name core -print
    tail /var/log/syslog
    tail -n 100 /var/log/syslog
    tail -n100 /var/log/syslog
    tail -100 /var/log/syslog
    tail -c 4096 /var/log/syslog
    tail --lines=20 /var/log/syslog
    zfs list
    zfs list -t snapshot -o name,used
    zfs list -rH tank
    zpool status
    zpool status -x
    zpool status -v tank
    zpool list -H -o name,size
    pvesm status
    pvesm status --storage local
    pvesm status --content images
    qm list
    qm list --full 1
    qm config 100
    qm config 100 --current
    qm config 100 --snapshot before-upgrade
    qm status 100 --verbose
    pct list
    pct config 101
    pct status 101
  `)) {
    assert.equal(isReadonlyCommand(command), true, `should allow: ${command}`);
  }
});
