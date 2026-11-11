import fs from "node:fs";
import { parseCidrList, ipVersion } from "./cidr.js";
import { HOST_KEY_FINGERPRINT } from "./constants.js";

// ─── Required settings ─────────────────────────────────────────────────────
// Settings that point at real infrastructure have no defaults. If one is
// missing the server refuses to start, rather than quietly connecting to
// hardcoded production hosts (e.g. from a local test run).
const REQUIRED_SETTINGS = [
  "PROXMOX_HOST",
  "PROXMOX_TOKEN_ID",
  "PROXMOX_TOKEN_SECRET",
  "PROXMOX_SSH_HOST",
  "MCP_BASE_URL",
  "AUTHENTIK_URL",
];
const missingSettings = REQUIRED_SETTINGS.filter((name) => !process.env[name]);
if (missingSettings.length) {
  console.error(`Missing required settings: ${missingSettings.join(", ")}. Set them in .env.`);
  process.exit(1);
}

// Reads a non-negative integer setting, refusing to start on anything else so a
// typo can't silently turn a protection off.
function parseNonNegativeInt(name, fallback) {
  const raw = process.env[name] || fallback;
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
    console.error(`${name} must be a non-negative integer, got "${raw}".`);
    process.exit(1);
  }
  return Number(raw);
}

// Reads an optional SSH host key fingerprint ("SHA256:..."). A malformed one
// refuses to start, since ignoring it would silently turn pinning off.
function parseOptionalHostKey(name) {
  const raw = process.env[name]?.trim();
  if (!raw) return undefined;
  if (!HOST_KEY_FINGERPRINT.test(raw)) {
    console.error(`${name} must be an OpenSSH SHA256 fingerprint (SHA256:...), got "${raw}".`);
    process.exit(1);
  }
  return raw;
}

// Reads an optional git ref (commit SHA or tag). It ends up in a shell command
// and a URL path, so only plain ref characters are accepted.
function parseOptionalGitRef(name) {
  const raw = process.env[name]?.trim();
  if (!raw) return undefined;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(raw)) {
    console.error(`${name} must be a commit SHA or tag (letters, digits, . _ -), got "${raw}".`);
    process.exit(1);
  }
  return raw;
}

// The default readable roots: logs, kernel and process status, and host
// configuration that holds no credentials. /etc/pve/priv and other secret
// paths under these are still refused by the deny list.
const DEFAULT_READONLY_PATHS = [
  "/var/log",
  "/sys",
  "/proc",
  "/etc/pve",
  "/etc/network",
  "/etc/hostname",
  "/etc/hosts",
  "/etc/os-release",
  "/etc/apt/sources.list",
  "/etc/apt/sources.list.d",
];

// Reads READONLY_PATHS: comma-separated absolute paths, normalised. A relative
// or empty entry refuses to start rather than being ignored.
function parseReadonlyPaths(name) {
  const raw = process.env[name];
  if (raw === undefined || !raw.trim()) return DEFAULT_READONLY_PATHS;
  const entries = raw.split(",").map((entry) => entry.trim());
  const invalid = entries.find((entry) => !entry.startsWith("/") || /(^|\/)\.\.?(\/|$)/.test(entry));
  if (invalid !== undefined) {
    console.error(`${name} entries must be absolute paths without . or .. segments, got "${invalid}".`);
    process.exit(1);
  }
  return entries.map((entry) => entry.replace(/\/+$/, "") || "/");
}

// Reads an optional comma-separated list, lower-cased, or null when unset or
// blank. A value with no entries in it (",") refuses to start: it means a
// restriction was intended, and null would mean no restriction at all.
function parseOptionalList(name) {
  const raw = process.env[name];
  if (!raw?.trim()) return null;
  const entries = raw
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  if (!entries.length) {
    console.error(`${name} is set but lists no entries, got "${raw}". Remove it or list at least one.`);
    process.exit(1);
  }
  return entries;
}

// Private address ranges: RFC 1918 for IPv4 and unique local fc00::/7 for IPv6.
const PRIVATE_RANGES = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7";

// Reads a comma-separated CIDR list, or `fallback` when unset. Refuses to
// start on a malformed entry, since dropping it would change who is reachable.
function parseCidrListSetting(name, fallback) {
  const raw = process.env[name]?.trim() ? process.env[name] : fallback;
  try {
    return parseCidrList(raw);
  } catch (error) {
    console.error(`${name} is invalid: ${error.message}.`);
    process.exit(1);
  }
}

// ─── Config ────────────────────────────────────────────────────────────────
export const CONFIG = {
  proxmox: {
    host: process.env.PROXMOX_HOST,
    port: process.env.PROXMOX_PORT || "8006",
    tokenId: process.env.PROXMOX_TOKEN_ID,
    tokenSecret: process.env.PROXMOX_TOKEN_SECRET,
    node: process.env.PROXMOX_NODE || "proxmox",
    // Optional CA certificate to trust for the Proxmox API (e.g. a copy of
    // /etc/pve/pve-root-ca.pem), for hosts using Proxmox's own certificate.
    caCert: process.env.PROXMOX_CA_CERT
      ? fs.readFileSync(process.env.PROXMOX_CA_CERT)
      : undefined,
  },
  ssh: {
    host: process.env.PROXMOX_SSH_HOST,
    port: Number.parseInt(process.env.PROXMOX_SSH_PORT || "22", 10),
    username: process.env.PROXMOX_SSH_USER || "root",
    privateKey: process.env.PROXMOX_SSH_KEY
      ? fs.readFileSync(process.env.PROXMOX_SSH_KEY)
      : undefined,
    // SHA256 fingerprint of the Proxmox host's SSH key. When set, a host that
    // presents any other key is refused before authenticating.
    hostKey: parseOptionalHostKey("PROXMOX_SSH_HOST_KEY"),
  },
  server: {
    port: Number.parseInt(process.env.MCP_PORT || "3000", 10),
    baseUrl: process.env.MCP_BASE_URL,
  },
  authentik: {
    url: process.env.AUTHENTIK_URL,
    slug: process.env.AUTHENTIK_APP_SLUG || "proxmox-mcp",
    // The OAuth client id. When set, a JWT is accepted only if its `aud` claim
    // names it, so a token Authentik issued for another application on the
    // same provider can't be replayed here.
    audience: process.env.AUTHENTIK_AUDIENCE?.trim() || undefined,
  },
  communityScripts: {
    // Commit SHA or tag of community-scripts/ProxmoxVE that run_community_script
    // fetches from. Unset means the main branch, which can change at any time.
    ref: parseOptionalGitRef("COMMUNITY_SCRIPTS_REF"),
  },
};

// ─── Security settings ──────────────────────────────────────────────────────
// AUTH_MODE:  enforce (default) | log (accept but record failures) | off
// SHELL_MODE: full (default, dangerous commands need confirm) | readonly | off
export const SECURITY = {
  authMode: (process.env.AUTH_MODE || "enforce").toLowerCase(),
  shellMode: (process.env.SHELL_MODE || "full").toLowerCase(),
  // full (default) | readonly: refuse every call that would need confirm: true,
  // whatever the model sends, for a look-but-don't-touch deployment.
  toolMode: (process.env.TOOL_MODE || "full").toLowerCase(),
  auditLog: process.env.AUDIT_LOG || "/var/log/proxmox-mcp/audit.jsonl",
  // true (default): a tool call is refused if its audit entry can't be
  // written, so nothing runs unrecorded. false: run anyway and log the failure.
  auditRequired: (process.env.AUDIT_REQUIRED || "true").toLowerCase(),
  // Requests per client IP per minute across the OAuth and MCP routes. 0 disables.
  rateLimitPerMinute: parseNonNegativeInt("RATE_LIMIT_PER_MINUTE", "120"),
  // Reverse proxy hops in front of the server (e.g. 1 for a Cloudflare tunnel),
  // so the limiter sees real client IPs. 0 means no proxy.
  trustProxyHops: parseNonNegativeInt("TRUST_PROXY_HOPS", "0"),
  // Usernames, emails or subject ids allowed to use the server, or null for
  // anyone Authentik signs in. A second check after Authentik's own binding.
  allowedUsers: parseOptionalList("ALLOWED_USERS"),
  // Authentik group names whose members may use the server. Either list
  // matching is enough; with neither set, anyone Authentik signs in may.
  allowedGroups: parseOptionalList("ALLOWED_GROUPS"),
  // Absolute paths whose files cat, head, tail and grep may read on the host
  // without approval. Everything else, and every file read inside a container
  // or VM, needs confirm: true. The deny list of secret paths applies on top.
  readonlyPaths: parseReadonlyPaths("READONLY_PATHS"),
  // Addresses vm_ssh may connect to, as a net.BlockList. Defaults to private
  // ranges, so it can't reach the internet unless that is configured.
  vmSshAllowedCidrs: parseCidrListSetting("VM_SSH_ALLOWED_CIDRS", PRIVATE_RANGES),
  // off (default): vm_ssh refuses a password argument and uses the configured
  // key, so passwords never pass through the model's context. on: allowed.
  vmSshPasswordAuth: (process.env.VM_SSH_PASSWORD_AUTH || "off").toLowerCase(),
};

// A typo here must not silently change the security posture (an unknown
// SHELL_MODE would otherwise behave like "full"), so refuse to start instead.
const ALLOWED_MODES = {
  AUTH_MODE: [SECURITY.authMode, ["enforce", "log", "off"]],
  SHELL_MODE: [SECURITY.shellMode, ["full", "readonly", "off"]],
  TOOL_MODE: [SECURITY.toolMode, ["full", "readonly"]],
  AUDIT_REQUIRED: [SECURITY.auditRequired, ["true", "false"]],
  VM_SSH_PASSWORD_AUTH: [SECURITY.vmSshPasswordAuth, ["off", "on"]],
};
for (const [name, [value, allowed]] of Object.entries(ALLOWED_MODES)) {
  if (!allowed.includes(value)) {
    console.error(`Invalid ${name}="${value}". Expected one of: ${allowed.join(", ")}.`);
    process.exit(1);
  }
}

// ─── Listening address ──────────────────────────────────────────────────────
// MCP_BIND_ADDRESS defaults to 0.0.0.0 so Docker's port publishing works.
// AUTH_MODE=log or off lets anyone who reaches the port run tools as root on
// the Proxmox host, so it needs an explicit ALLOW_INSECURE_AUTH=yes and then
// listens on loopback only.
const LOOPBACK_ADDRESSES = new Set(["127.0.0.1", "::1"]);

function chooseBindAddress() {
  const requested = process.env.MCP_BIND_ADDRESS?.trim() || undefined;
  if (requested && !ipVersion(requested)) {
    console.error(`MCP_BIND_ADDRESS must be an IP address, got "${requested}".`);
    process.exit(1);
  }
  if (SECURITY.authMode === "enforce") return requested ?? "0.0.0.0";
  if (process.env.ALLOW_INSECURE_AUTH !== "yes") {
    console.error(
      `AUTH_MODE=${SECURITY.authMode} accepts requests without a valid login. Set ALLOW_INSECURE_AUTH=yes to confirm this is a local test; the server then listens on 127.0.0.1 only.`,
    );
    process.exit(1);
  }
  if (requested && !LOOPBACK_ADDRESSES.has(requested)) {
    console.error(`AUTH_MODE=${SECURITY.authMode} only listens on loopback, but MCP_BIND_ADDRESS is ${requested}.`);
    process.exit(1);
  }
  return requested ?? "127.0.0.1";
}
CONFIG.server.bindAddress = chooseBindAddress();

// ─── Pins that must be in force ─────────────────────────────────────────────
// Without a pinned host key any machine that answers as the Proxmox host gets
// every shell command, and without an audience a token Authentik issued to
// another application is accepted. Both used to be optional, which meant an
// upgraded deployment had neither, so each is now required unless explicitly
// waived with an ALLOW_* setting of exactly "yes".
function requirePinOrWaiver({ missing, waiver, message }) {
  if (!missing || process.env[waiver] === "yes") return;
  console.error(`${message}\nOr set ${waiver}=yes to run without it (not recommended).`);
  process.exit(1);
}

requirePinOrWaiver({
  missing: SECURITY.shellMode !== "off" && !CONFIG.ssh.hostKey,
  waiver: "ALLOW_UNPINNED_SSH_HOST",
  message:
    "PROXMOX_SSH_HOST_KEY is not set, so the Proxmox host's SSH key would not be checked. " +
    `Get the fingerprint with: ssh-keyscan ${CONFIG.ssh.host} | ssh-keygen -lf -  ` +
    "and set PROXMOX_SSH_HOST_KEY to the SHA256:... value (ed25519 if present).",
});

requirePinOrWaiver({
  missing: SECURITY.authMode !== "off" && !CONFIG.authentik.audience,
  waiver: "ALLOW_ANY_AUDIENCE",
  message:
    "AUTHENTIK_AUDIENCE is not set, so tokens issued to any application on this Authentik provider would be accepted. " +
    "Set it to the provider's Client ID (Authentik admin: Applications, Providers, your provider, Client ID).",
});
