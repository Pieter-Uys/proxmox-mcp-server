import { CONFIG, SECURITY } from "./config.js";
import { COMMUNITY_SCRIPT_TIMEOUT_MS, HOST_KEY_FINGERPRINT } from "./constants.js";
import { ipVersion, cidrListIncludes } from "./cidr.js";
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

// ─── Community scripts ──────────────────────────────────────────────────────
// Remote code that runs as root. COMMUNITY_SCRIPTS_REF pins the commit or tag;
// without it the main branch is used, and the confirmation message and audit
// entry name the exact URL so the user can see what will run.
const COMMUNITY_SCRIPTS_RAW_URL = "https://raw.githubusercontent.com/community-scripts/ProxmoxVE";
const COMMUNITY_SCRIPTS_DEFAULT_REF = "main";

export function communityScriptSource(script, ref = CONFIG.communityScripts.ref) {
  const resolvedRef = ref || COMMUNITY_SCRIPTS_DEFAULT_REF;
  return {
    ref: resolvedRef,
    pinned: Boolean(ref),
    url: `${COMMUNITY_SCRIPTS_RAW_URL}/${resolvedRef}/ct/${script}.sh`,
  };
}

function communityScriptCommand(args) {
  return `bash -c "$(curl -fsSL ${communityScriptSource(args.script).url})"`;
}

function communityScriptConfirmationReason(args) {
  const { url, ref, pinned } = communityScriptSource(args.script);
  const pinNote = pinned
    ? `pinned to ref ${ref} by COMMUNITY_SCRIPTS_REF`
    : `ref ${ref}, an unpinned branch that can change at any time; set COMMUNITY_SCRIPTS_REF to pin it`;
  return `Community scripts download and run remote code as root. This runs ${url} (${pinNote}).`;
}

// zfs_create builds `zfs create` from structured arguments. It used to run
// `zfs <anything>`, so `destroy -r rpool/data` was valid input to an action
// named create, which would mislead the person approving it.
const ZFS_PROPERTY_NAME = /^[a-z][a-z0-9_.:-]*$/; // native (compression) or user (com.example:owner)
const ZFS_PROPERTY_VALUE = /^[A-Za-z0-9_.:/@+=,-]+$/;

function zfsCommand(args) {
  if (args.action === "zfs_list") return "zfs list";
  if (args.action !== "zfs_create") return null;
  const parents = args.parents ? ["-p"] : [];
  const properties = Object.entries(args.properties ?? {}).map(
    ([name, value]) => `-o ${shellQuote(`${name}=${value}`)}`,
  );
  return ["zfs create", ...parents, ...properties, shellQuote(args.dataset)].join(" ");
}

// Why zfs_create's properties can't be used, or null. Values are quoted
// anyway; this keeps them to plain names and values a person can read.
function zfsPropertiesRefusal(args) {
  if (args.action !== "zfs_create" || args.properties === undefined) return null;
  for (const [name, value] of Object.entries(args.properties)) {
    if (!ZFS_PROPERTY_NAME.test(name)) return `"${String(name).slice(0, 60)}" is not a ZFS property name.`;
    if (typeof value !== "string" || !ZFS_PROPERTY_VALUE.test(value))
      return `ZFS property ${name} needs a plain string value (letters, digits and _ . : / @ + = , -).`;
  }
  return null;
}

// Why vm_ssh won't connect, or null if it may. Without these limits vm_ssh
// could reach any host the server can route to, and a password would pass
// through the model's context (and the client's transcript) in plain text.
export function vmSshRefusalReason(args) {
  if (!ipVersion(args.ip))
    return `vm_ssh needs a literal IPv4 or IPv6 address, not "${String(args.ip).slice(0, 100)}". Host names are not accepted.`;
  const allowed = SECURITY.vmSshAllowedCidrs;
  if (allowed && !cidrListIncludes(allowed, args.ip))
    return `vm_ssh may not connect to ${args.ip}: it is outside VM_SSH_ALLOWED_CIDRS.`;
  if (args.password !== undefined && SECURITY.vmSshPasswordAuth !== "on")
    return "vm_ssh password login is disabled (VM_SSH_PASSWORD_AUTH=off). Leave out the password; the server's configured SSH key is used.";
  // Without a pinned host key the password goes to whichever machine answers
  // at that address, so it is only sent to a host that proves who it is.
  // Checked here as well as by the schema: run() calls this for direct
  // callTool use, which skips schema validation, and an empty hostKey would
  // otherwise mean no host verifier at all.
  if (args.password !== undefined && !(typeof args.hostKey === "string" && HOST_KEY_FINGERPRINT.test(args.hostKey)))
    return "vm_ssh sends a password only to a pinned host. Add hostKey (the VM's SHA256 fingerprint, from ssh-keyscan <ip> | ssh-keygen -lf -), or leave out the password.";
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

// The Proxmox `startup` value, e.g. "order=2,up=30,down=10".
export function startupSetting({ order, upDelay, downDelay }) {
  return [`order=${order}`, upDelay && `up=${upDelay}`, downDelay && `down=${downDelay}`]
    .filter(Boolean)
    .join(",");
}

// Declares arguments that only some calls need, e.g. `pos` for a delete.
// Checked with the schema before the tool runs (see validate.js).
function requireWhen(field, values, required) {
  return { field, values, required };
}

// Each tool keeps its schema, policy and implementation together:
//   description, inputSchema  advertised to clients via tools/list
//   annotations               the four MCP hints, always explicit booleans, advertised
//                             via tools/list so hosts can warn before risky calls
//   refusalReason(args)       why server configuration refuses this call outright
//                             (confirm: true can't override it), or null
//   shellCommand(args)        shell command this call runs, or null (SHELL_MODE applies)
//   requiredWhen              arguments that only some actions need (requireWhen)
//   confirmationReason(args)  why this call needs confirm: true, or null
//   auditFields(args)         extra fields for this call's audit entry
//   run(args, node)           performs the call; returns text or JSON data
export const TOOLS = {
  proxmox_api: {
    // Any REST method, including DELETE.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
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
    // Arbitrary commands on the host, which can also reach the network.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
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
    // Arbitrary commands in a container, which can also reach the network.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
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
    // Arbitrary commands on an IP the caller names (within VM_SSH_ALLOWED_CIDRS if set).
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    description:
      "SSH into a VM by IP address and run a command, using the server's SSH key. Commands that aren't plain read-only commands require confirm: true. The VM's host key is only checked when hostKey is given.",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IPv4 or IPv6 address of the VM (not a host name). The server may limit which ranges are allowed.",
        },
        username: { type: "string" },
        password: {
          type: "string",
          description:
            "Only accepted when the server sets VM_SSH_PASSWORD_AUTH=on (off by default). Otherwise leave this out and the server's SSH key is used.",
        },
        hostKey: {
          type: "string",
          pattern: HOST_KEY_FINGERPRINT.source,
          description:
            "Optional SHA256 host key fingerprint of the VM (SHA256:...). When given, the connection is refused if the VM presents a different key. Required with password.",
        },
        command: { type: "string" },
      },
      required: ["ip", "command"],
    },
    refusalReason: vmSshRefusalReason,
    shellCommand: (args) => args.command,
    confirmationReason: shellConfirmationReason,
    run: async (args) => {
      // Checked again here so a direct callTool can't skip the limits.
      const refusal = vmSshRefusalReason(args);
      if (refusal) throw new Error(refusal);
      const result = await sshExec(args.command, {
        host: args.ip,
        username: args.username || "root",
        password: args.password,
        hostKey: args.hostKey,
      });
      return formatCommandResult(result);
    },
  },

  run_community_script: {
    // Downloads remote code and runs it as root.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    description:
      "Run a community-scripts.org LXC script on Proxmox. Always requires confirm: true (downloads and runs remote code as root). Untested through this server: it runs without a terminal (these scripts normally expect one) and stops after 20 minutes, which may leave an install half done.",
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
    confirmationReason: communityScriptConfirmationReason,
    auditFields: (args) => {
      const { url, ref, pinned } = communityScriptSource(args.script);
      return { scriptUrl: url, scriptRef: ref, scriptPinned: pinned };
    },
    run: (args) => runOnHost(communityScriptCommand(args), { timeoutMs: COMMUNITY_SCRIPT_TIMEOUT_MS }),
  },

  get_status: {
    // GET requests only.
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
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
    // Additive, but advertised as destructive like every confirm-gated tool:
    // it consumes resources and can create a privileged container.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
    description: "Create a new LXC container. Requires confirm: true.",
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
    confirmationReason: (args) =>
      args.unprivileged === false
        ? "This creates a privileged container, which runs as real root on the host."
        : "This creates a new container and uses host resources.",
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
    // Includes stop and delete.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
    description:
      "Start, stop, restart, shut down or delete a VM or LXC. Every action requires confirm: true.",
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
    // Every action changes a guest's state; stop and delete can lose data.
    confirmationReason: (args) =>
      ["delete", "stop"].includes(args.action)
        ? `manage_vm ${args.action} is destructive.`
        : `manage_vm ${args.action} changes whether the guest is running.`,
    run: (args, node) => {
      const guestPath = `/nodes/${node}/${args.type || "lxc"}/${args.vmid}`;
      return args.action === "delete"
        ? proxmoxRequest("DELETE", guestPath)
        : proxmoxRequest("POST", `${guestPath}/status/${STATUS_ENDPOINT[args.action] ?? args.action}`);
    },
  },

  firewall_rule: {
    // Includes deleting rules; add is not idempotent.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
    description:
      "Manage Proxmox firewall rules. add and delete require confirm: true.",
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
    confirmationReason: (args) => {
      if (args.action === "list") return null;
      return args.action === "delete"
        ? "Deleting firewall rules is destructive."
        : "A new firewall rule can lock everyone out (DROP) or open the host (ACCEPT).";
    },
    run: dispatchByAction({
      list: (args, node) => proxmoxRequest("GET", firewallRulesPath(args, node)),
      add: (args, node) =>
        proxmoxRequest("POST", firewallRulesPath(args, node), args.rule),
      delete: (args, node) =>
        proxmoxRequest("DELETE", `${firewallRulesPath(args, node)}/${args.pos}`),
    }),
  },

  network_config: {
    // Includes deleting interfaces and applying config.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
    description:
      "Manage Proxmox network interfaces and VLANs. Everything except list requires confirm: true.",
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
    confirmationReason: (args) => {
      if (args.action === "list") return null;
      return ["delete", "apply"].includes(args.action)
        ? `network_config ${args.action} can cut off connectivity.`
        : `network_config ${args.action} stages a network change that the next apply makes live.`;
    },
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
    // Includes deleting storage and creating ZFS datasets.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
    description:
      "Manage Proxmox storage (NFS, SMB, ZFS, LVM). Everything except list and zfs_list requires confirm: true. zfs_create only creates a dataset.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "add", "update", "delete", "zfs_list", "zfs_create"],
        },
        storage: NAME_SEGMENT,
        config: { type: "object" },
        dataset: {
          type: "string",
          // pool/child[/child...]: never an option, a snapshot or a bare pool.
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.:-]*(/[A-Za-z0-9][A-Za-z0-9_.:-]*)+$",
          description: "Dataset to create, e.g. tank/data",
        },
        properties: {
          type: "object",
          description: "ZFS properties to set at creation, e.g. { \"compression\": \"lz4\" }",
        },
        parents: { type: "boolean", description: "Create missing parent datasets (zfs create -p)" },
      },
      required: ["action"],
    },
    requiredWhen: [
      requireWhen("action", ["add", "update", "delete"], ["storage"]),
      requireWhen("action", ["zfs_create"], ["dataset"]),
    ],
    refusalReason: zfsPropertiesRefusal,
    shellCommand: zfsCommand,
    confirmationReason: (args) => {
      if (["list", "zfs_list"].includes(args.action)) return null;
      if (["delete", "zfs_create"].includes(args.action)) return `storage_config ${args.action} can destroy data.`;
      return `storage_config ${args.action} changes storage, and can take it offline.`;
    },
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
    // Overwrites the startup and onboot settings; same input gives the same state.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
    },
    description: "Set VM/LXC startup order. Requires confirm: true.",
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
    confirmationReason: () => "This overwrites the guest's startup order and turns on start at boot.",
    run: (args, node) => {
      const startup = startupSetting(args);
      return proxmoxRequest(
        "PUT",
        `/nodes/${node}/${args.type || "lxc"}/${args.vmid}/config`,
        { startup, onboot: 1 },
      );
    },
  },

  backup_vm: {
    // Adds a backup each call; mode stop shuts the guest down, and hints are tool-wide.
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
    description:
      "Create a backup of a VM or LXC. Requires confirm: true.",
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
      args.mode === "stop"
        ? "Backup mode stop shuts the guest down."
        : "A backup writes a new archive, which can fill the target storage.",
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
  annotations: tool.annotations,
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
