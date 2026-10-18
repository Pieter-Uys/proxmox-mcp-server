import fs from "node:fs";

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
  },
  server: {
    port: Number.parseInt(process.env.MCP_PORT || "3000", 10),
    baseUrl: process.env.MCP_BASE_URL,
  },
  authentik: {
    url: process.env.AUTHENTIK_URL,
    slug: process.env.AUTHENTIK_APP_SLUG || "proxmox-mcp",
  },
};

// ─── Security settings ──────────────────────────────────────────────────────
// AUTH_MODE:  enforce (default) | log (accept but record failures) | off
// SHELL_MODE: full (default, dangerous commands need confirm) | readonly | off
export const SECURITY = {
  authMode: (process.env.AUTH_MODE || "enforce").toLowerCase(),
  shellMode: (process.env.SHELL_MODE || "full").toLowerCase(),
  auditLog: process.env.AUDIT_LOG || "/var/log/proxmox-mcp/audit.jsonl",
  // Requests per client IP per minute across the OAuth and MCP routes. 0 disables.
  rateLimitPerMinute: parseNonNegativeInt("RATE_LIMIT_PER_MINUTE", "120"),
  // Reverse proxy hops in front of the server (e.g. 1 for a Cloudflare tunnel),
  // so the limiter sees real client IPs. 0 means no proxy.
  trustProxyHops: parseNonNegativeInt("TRUST_PROXY_HOPS", "0"),
};

// A typo here must not silently change the security posture (an unknown
// SHELL_MODE would otherwise behave like "full"), so refuse to start instead.
const ALLOWED_MODES = {
  AUTH_MODE: [SECURITY.authMode, ["enforce", "log", "off"]],
  SHELL_MODE: [SECURITY.shellMode, ["full", "readonly", "off"]],
};
for (const [name, [value, allowed]] of Object.entries(ALLOWED_MODES)) {
  if (!allowed.includes(value)) {
    console.error(`Invalid ${name}="${value}". Expected one of: ${allowed.join(", ")}.`);
    process.exit(1);
  }
}
