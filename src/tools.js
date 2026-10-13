import { CONFIG } from "./config.js";
import { proxmoxRequest } from "./proxmox.js";
import { sshExec, runOnHost, formatCommandResult, shellQuote } from "./ssh.js";
import { shellConfirmationReason } from "./policy.js";
import { pick } from "./utils.js";

// ─── Tools ──────────────────────────────────────────────────────────────────
// Argument schemas for values that end up in shell commands, API paths or
// Proxmox property strings. Validated before any tool runs (see validate.js).
const VMID = { type: "integer", minimum: 100 };
const NODE = { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9.-]*$" };
const NAME_SEGMENT = { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9._-]*$" };
const NON_NEGATIVE_INTEGER = { type: "integer", minimum: 0 };

// Builds a tool's run() that dispatches on args.action.
function dispatchByAction(actions) {
  return (args, node) => pick(actions, args.action, "action")(args, node);
}

const NETWORK_RELOAD_COMMAND = "ifreload -a";

function communityScriptCommand(args) {
  return `bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/${args.script}.sh)"`;
}

function zfsCommand(args) {
  if (args.action === "zfs_list") return "zfs list";
  if (args.action === "zfs_create") return `zfs ${args.zfsCommand}`;
  return null;
}

// Proxmox calls VMs "qemu" in API paths; the tool's `level` says "vm".
const GUEST_PATH_TYPE = { vm: "qemu", lxc: "lxc" };

// manage_vm actions whose Proxmox status endpoint has a different name.
const STATUS_ENDPOINT = { restart: "reboot" };

function firewallRulesPath(args, node) {
  if (args.level === "cluster") return "/cluster/firewall/rules";
  if (args.level === "host") return `/nodes/${node}/firewall/rules`;
  return `/nodes/${node}/${GUEST_PATH_TYPE[args.level]}/${args.vmid}/firewall/rules`;
}

// Declares arguments that only some calls need, e.g. `pos` for a delete.
// Checked with the schema before the tool runs (see validate.js).
function requireWhen(field, values, required) {
  return { field, values, required };
}

// Each tool keeps its schema, policy and implementation together:
//   description, inputSchema  advertised to clients via tools/list
//   shellCommand(args)        shell command this call runs, or null (SHELL_MODE applies)
//   requiredWhen              arguments that only some actions need (requireWhen)
//   confirmationReason(args)  why this call needs confirm: true, or null
//   run(args, node)           performs the call; returns text or JSON data
export const TOOLS = {
  proxmox_api: {
    description:
      "Make any Proxmox REST API call. Anything other than GET requires confirm: true.",
    inputSchema: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"] },
        path: { type: "string" },
        body: { type: "object" },
      },
      required: ["method", "path"],
    },
    confirmationReason: (args) =>
      args.method === "GET" ? null : `${args.method} API calls change the system.`,
    run: (args) => proxmoxRequest(args.method, args.path, args.body),
  },

  host_shell: {
    description:
      "Run a shell command on the Proxmox host via SSH. Commands that aren't plain read-only commands require confirm: true.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
    shellCommand: (args) => args.command,
    confirmationReason: shellConfirmationReason,
    run: (args) => runOnHost(args.command),
  },

  lxc_shell: {
    description:
      "Run a command inside an LXC container via pct exec. Commands that aren't plain read-only commands require confirm: true.",
    inputSchema: {
      type: "object",
      properties: { vmid: VMID, command: { type: "string" } },
      required: ["vmid", "command"],
    },
    shellCommand: (args) => args.command,
    confirmationReason: shellConfirmationReason,
    run: (args) =>
      runOnHost(
        `pct exec ${args.vmid} -- bash -c ${shellQuote(args.command)}`,
      ),
  },

  vm_ssh: {
    description:
      "SSH into a VM by IP and run a command. Commands that aren't plain read-only commands require confirm: true.",
    inputSchema: {
      type: "object",
      properties: {
        ip: { type: "string" },
        username: { type: "string" },
        password: { type: "string" },
        command: { type: "string" },
      },
      required: ["ip", "command"],
    },
    shellCommand: (args) => args.command,
    confirmationReason: shellConfirmationReason,
    run: async (args) => {
      const result = await sshExec(args.command, {
        host: args.ip,
        username: args.username || "root",
        password: args.password,
      });
      return formatCommandResult(result);
    },
  },

  run_community_script: {
    description:
      "Run a community-scripts.org LXC script on Proxmox. Always requires confirm: true (downloads and runs remote code as root).",
    inputSchema: {
      type: "object",
      properties: {
        script: {
          type: "string",
          pattern: "^[a-z0-9][a-z0-9-]*$",
          description: "Script name e.g. pihole, nextcloud, unbound",
        },
      },
      required: ["script"],
    },
    shellCommand: communityScriptCommand,
    confirmationReason: () =>
      "Community scripts download and run remote code as root.",
    run: (args) => runOnHost(communityScriptCommand(args)),
  },

  get_status: {
    description: "Get Proxmox cluster/node/VM/LXC/storage status.",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "string",
          enum: ["cluster", "nodes", "vms", "lxc", "storage", "tasks"],
        },
        node: NODE,
      },
      required: ["scope"],
    },
    run: (args, node) => {
      const pathForScope = {
        cluster: "/cluster/status",
        nodes: "/nodes",
        vms: `/nodes/${node}/qemu`,
        lxc: `/nodes/${node}/lxc`,
        storage: `/nodes/${node}/storage`,
        tasks: `/nodes/${node}/tasks`,
      };
      return proxmoxRequest("GET", pick(pathForScope, args.scope, "scope"));
    },
  },

  create_lxc: {
    description: "Create a new LXC container.",
    inputSchema: {
      type: "object",
      properties: {
        vmid: VMID,
        hostname: { type: "string" },
        ostemplate: { type: "string" },
        memory: { type: "number" },
        cores: { type: "number" },
        disk: { type: "string" },
        net: { type: "string" },
        password: { type: "string" },
        start: { type: "boolean" },
        onboot: { type: "boolean" },
        startOrder: NON_NEGATIVE_INTEGER,
        unprivileged: { type: "boolean" },
        node: NODE,
      },
      required: ["vmid", "hostname", "ostemplate"],
    },
    run: (args, node) =>
      proxmoxRequest("POST", `/nodes/${node}/lxc`, {
        vmid: args.vmid,
        hostname: args.hostname,
        ostemplate: args.ostemplate,
        memory: args.memory || 512,
        cores: args.cores || 1,
        rootfs: args.disk || "local-lvm:8",
        net0: args.net || "name=eth0,bridge=vmbr0,ip=dhcp",
        unprivileged: args.unprivileged !== false ? 1 : 0,
        onboot: args.onboot !== false ? 1 : 0,
        start: args.start !== false ? 1 : 0,
        ...(args.password && { password: args.password }),
        ...(args.startOrder !== undefined && {
          startup: `order=${args.startOrder}`,
        }),
      }),
  },

  manage_vm: {
    description:
      "Start, stop, restart, or delete a VM or LXC. stop and delete require confirm: true.",
    inputSchema: {
      type: "object",
      properties: {
        vmid: VMID,
        action: {
          type: "string",
          enum: ["start", "stop", "restart", "shutdown", "delete"],
        },
        type: { type: "string", enum: ["lxc", "qemu"] },
        node: NODE,
      },
      required: ["vmid", "action"],
    },
    confirmationReason: (args) =>
      ["delete", "stop"].includes(args.action)
        ? `manage_vm ${args.action} is destructive.`
        : null,
    run: (args, node) => {
      const guestPath = `/nodes/${node}/${args.type || "lxc"}/${args.vmid}`;
      return args.action === "delete"
        ? proxmoxRequest("DELETE", guestPath)
        : proxmoxRequest("POST", `${guestPath}/status/${STATUS_ENDPOINT[args.action] ?? args.action}`);
    },
  },

  firewall_rule: {
    description:
      "Manage Proxmox firewall rules. delete requires confirm: true.",
    inputSchema: {
      type: "object",
      properties: {
        action: { type: "string", enum: ["add", "delete", "list"] },
        level: { type: "string", enum: ["host", "cluster", "vm", "lxc"] },
        vmid: VMID,
        node: NODE,
        rule: { type: "object" },
        pos: NON_NEGATIVE_INTEGER,
      },
      required: ["action", "level"],
    },
    requiredWhen: [
      requireWhen("level", ["vm", "lxc"], ["vmid"]),
      requireWhen("action", ["add"], ["rule"]),
      requireWhen("action", ["delete"], ["pos"]),
    ],
    confirmationReason: (args) =>
      args.action === "delete"
        ? "Deleting firewall rules is destructive."
        : null,
    run: dispatchByAction({
      list: (args, node) => proxmoxRequest("GET", firewallRulesPath(args, node)),
      add: (args, node) =>
        proxmoxRequest("POST", firewallRulesPath(args, node), args.rule),
      delete: (args, node) =>
        proxmoxRequest("DELETE", `${firewallRulesPath(args, node)}/${args.pos}`),
    }),
  },

  network_config: {
    description:
      "Manage Proxmox network interfaces and VLANs. delete and apply require confirm: true.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "create", "update", "delete", "apply"],
        },
        iface: NAME_SEGMENT,
        node: NODE,
        config: { type: "object" },
      },
      required: ["action"],
    },
    requiredWhen: [requireWhen("action", ["create", "update", "delete"], ["iface"])],
    shellCommand: (args) =>
      args.action === "apply" ? NETWORK_RELOAD_COMMAND : null,
    confirmationReason: (args) =>
      ["delete", "apply"].includes(args.action)
        ? `network_config ${args.action} can cut off connectivity.`
        : null,
    run: dispatchByAction({
      list: (args, node) => proxmoxRequest("GET", `/nodes/${node}/network`),
      create: (args, node) =>
        proxmoxRequest("POST", `/nodes/${node}/network`, {
          ...args.config,
          iface: args.iface, // after config, so config can't replace the validated name
        }),
      update: (args, node) =>
        proxmoxRequest(
          "PUT",
          `/nodes/${node}/network/${args.iface}`,
          args.config,
        ),
      delete: (args, node) =>
        proxmoxRequest("DELETE", `/nodes/${node}/network/${args.iface}`),
      apply: () => runOnHost(NETWORK_RELOAD_COMMAND),
    }),
  },

  storage_config: {
    description:
      "Manage Proxmox storage (NFS, SMB, ZFS, LVM). delete and zfs_create require confirm: true.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "add", "update", "delete", "zfs_list", "zfs_create"],
        },
        storage: NAME_SEGMENT,
        config: { type: "object" },
        zfsCommand: {
          type: "string",
          pattern: "^[^;&|`<>$()\\n\\r\\\\]*$",
          description: "Arguments to zfs, e.g. create tank/data (no shell operators)",
        },
      },
      required: ["action"],
    },
    requiredWhen: [
      requireWhen("action", ["add", "update", "delete"], ["storage"]),
      requireWhen("action", ["zfs_create"], ["zfsCommand"]),
    ],
    shellCommand: zfsCommand,
    confirmationReason: (args) =>
      ["delete", "zfs_create"].includes(args.action)
        ? `storage_config ${args.action} can destroy data.`
        : null,
    run: dispatchByAction({
      list: () => proxmoxRequest("GET", "/storage"),
      add: (args) =>
        proxmoxRequest("POST", "/storage", {
          ...args.config,
          storage: args.storage, // after config, so config can't replace the validated name
        }),
      update: (args) =>
        proxmoxRequest("PUT", `/storage/${args.storage}`, args.config),
      delete: (args) => proxmoxRequest("DELETE", `/storage/${args.storage}`),
      zfs_list: (args) => runOnHost(zfsCommand(args)),
      zfs_create: (args) => runOnHost(zfsCommand(args)),
    }),
  },

  set_boot_order: {
    description: "Set VM/LXC startup order.",
    inputSchema: {
      type: "object",
      properties: {
        vmid: VMID,
        order: NON_NEGATIVE_INTEGER,
        upDelay: NON_NEGATIVE_INTEGER,
        downDelay: NON_NEGATIVE_INTEGER,
        type: { type: "string", enum: ["lxc", "qemu"] },
        node: NODE,
      },
      required: ["vmid", "order"],
    },
    run: (args, node) => {
      const startup = `order=${args.order}${args.upDelay ? `,up=${args.upDelay}` : ""}${args.downDelay ? `,down=${args.downDelay}` : ""}`;
      return proxmoxRequest(
        "PUT",
        `/nodes/${node}/${args.type || "lxc"}/${args.vmid}/config`,
        { startup, onboot: 1 },
      );
    },
  },

  backup_vm: {
    description:
      "Create a backup of a VM or LXC. mode stop requires confirm: true.",
    inputSchema: {
      type: "object",
      properties: {
        vmid: VMID,
        storage: NAME_SEGMENT,
        compress: { type: "string", enum: ["0", "gzip", "lzo", "zstd"] },
        mode: { type: "string", enum: ["snapshot", "suspend", "stop"] },
        node: NODE,
      },
      required: ["vmid"],
    },
    confirmationReason: (args) =>
      args.mode === "stop" ? "Backup mode stop shuts the guest down." : null,
    run: (args, node) =>
      proxmoxRequest("POST", `/nodes/${node}/vzdump`, {
        vmid: args.vmid,
        storage: args.storage || "local",
        compress: args.compress || "zstd",
        mode: args.mode || "snapshot",
      }),
  },
};

// What tools/list advertises. Tools that can require confirmation get a
// `confirm` argument added to their schema.
const CONFIRM_PROPERTY = {
  type: "boolean",
  description:
    "Set true only after the user has explicitly approved this specific destructive action in the conversation.",
};
export const TOOL_LIST = Object.entries(TOOLS).map(([name, tool]) => ({
  name,
  description: tool.description,
  inputSchema: tool.confirmationReason
    ? {
        ...tool.inputSchema,
        properties: { ...tool.inputSchema.properties, confirm: CONFIRM_PROPERTY },
      }
    : tool.inputSchema,
}));

export async function callTool(toolName, args) {
  const tool = pick(TOOLS, toolName, "tool");
  const output = await tool.run(args, args.node || CONFIG.proxmox.node);
  return {
    content: [
      {
        type: "text",
        text:
          typeof output === "string" ? output : JSON.stringify(output, null, 2),
      },
    ],
  };
}

export function findTool(toolName) {
  return Object.hasOwn(TOOLS, toolName) ? TOOLS[toolName] : undefined;
}
