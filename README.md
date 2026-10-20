# Proxmox MCP Server

[![CI](https://github.com/Pieter-Uys/proxmox-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/Pieter-Uys/proxmox-mcp-server/actions/workflows/ci.yml)
![Node](https://img.shields.io/badge/node-%3E%3D20.6-339933?logo=node.js&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A remote [MCP](https://modelcontextprotocol.io) server that lets an AI assistant such as Claude manage a Proxmox VE host through tool calls.

- **Stack:** Node.js and Express, JSON-RPC over HTTP
- **Auth:** OAuth login through [Authentik](https://goauthentik.io)
- **Exposure:** built for a Cloudflare Tunnel, but any public HTTPS address works
- **Guardrails:** confirmation for destructive actions, shell modes, argument validation, rate limiting and an audit log

> **New here?** The [setup guide](docs/SETUP.md) walks through the Proxmox API token, SSH key, Authentik application, tunnel, and running the server with Node, systemd or Docker.

## Contents

- [Quick start](#quick-start)
- [Tools](#tools)
- [Security model](#security-model)
- [Configuration](#configuration)
- [Tests](#tests)
- [Project layout](#project-layout)
- [License and privacy](#license-and-privacy)

## Quick start

Requires Node 20.6 or newer.

```bash
git clone https://github.com/Pieter-Uys/proxmox-mcp-server.git
cd proxmox-mcp-server
npm install
cp .env.example .env   # then fill it in, see Configuration
node --env-file=.env server.js
```

Check it is up with `curl http://localhost:3000/health`.

## Tools

The server exposes 13 tools.

| Tool | What it does | Needs `confirm: true` for |
| --- | --- | --- |
| `get_status` | Cluster, node, VM, LXC and storage status | Never (read-only) |
| `proxmox_api` | Any Proxmox REST API call | Every non-GET call |
| `manage_vm` | Start, stop, restart or delete a VM or LXC | `stop`, `delete` |
| `create_lxc` | Create a new LXC container | |
| `backup_vm` | Back up a VM or LXC | `mode: stop` |
| `set_boot_order` | Set VM and LXC startup order | |
| `firewall_rule` | Manage Proxmox firewall rules | `delete` |
| `network_config` | Manage network interfaces and VLANs | `delete`, `apply` |
| `storage_config` | Manage NFS, SMB, ZFS and LVM storage | `delete`, `zfs_create` |
| `host_shell` | Run a command on the Proxmox host over SSH | Anything off the read-only allowlist |
| `lxc_shell` | Run a command inside an LXC via `pct exec` | Anything off the read-only allowlist |
| `vm_ssh` | SSH into a VM by IP and run a command | Anything off the read-only allowlist |
| `run_community_script` | Run a [community-scripts.org](https://community-scripts.org) LXC script | Always (runs remote code as root) |

### MCP annotations

Every tool declares all four MCP annotation hints in `tools/list`, so clients can warn before risky calls:

- `readOnlyHint`: only `get_status` is read-only.
- `destructiveHint`: set on anything that can delete, stop or overwrite something.
- `idempotentHint`: set where repeating the call has no further effect.
- `openWorldHint`: set on the shell tools, `vm_ssh` and `run_community_script`, since they can reach beyond the Proxmox host.

A test keeps these hints consistent with each tool's confirmation and shell policy.

`initialize` negotiates the protocol version: it accepts `2025-03-26` or `2024-11-05`, uses the client's version if supported, and otherwise falls back to `2025-03-26`.

## Security model

| Layer | What it does |
| --- | --- |
| **Authentication** | Every `/mcp`, `/sse` and `/messages` request needs a bearer token. JWTs are verified locally against Authentik's signing keys (RS256, issuer, expiry). Opaque tokens are checked through Authentik's userinfo endpoint. Results are cached for up to 5 minutes per token hash. |
| **Confirmation** | Deletes, hard stops, network apply, ZFS commands, community scripts, non-GET `proxmox_api` calls and any shell command off the read-only allowlist are rejected unless sent with `confirm: true`. The rejection tells the model to get explicit approval from the user first. |
| **Shell modes** | `SHELL_MODE` controls every call that runs a shell command, including `storage_config` ZFS actions and `network_config apply`. |
| **Argument validation** | Every tool call is checked against the tool's input schema (types, enums, required fields, no unknown arguments) before policy runs. Values that reach shell commands or API paths (`vmid`, `node`, `iface`, `storage`, `script`, `zfsCommand`) are restricted to safe formats. |
| **Rate limiting** | OAuth and MCP routes are limited per client IP (`RATE_LIMIT_PER_MINUTE`). Over-limit requests get HTTP 429. `/health` is not limited. |
| **Audit log** | Every tool call and auth event is written as JSON Lines to `AUDIT_LOG`, with user, source IP, arguments (secrets redacted), outcome and duration. Rotate it with logrotate or similar on the host. |

### Modes

| Setting | Values |
| --- | --- |
| `AUTH_MODE` | `enforce` (default), `log` (accept but record failures), `off` |
| `SHELL_MODE` | `full` (default, risky commands need confirmation), `readonly` (single allowlisted read-only commands, no chaining), `off` |

The server refuses to start if either has an unrecognised value.

### Things to know

- **`confirm: true` is a speed bump, not a hard boundary.** The model sets it. It works alongside the client's own tool-approval prompts and the audit trail.
- **CORS allows any origin** (`Access-Control-Allow-Origin: *`). This is deliberate: clients send a bearer token in the `Authorization` header and the server sets no cookies, so a page on another origin has no ambient credentials to abuse. If you only expect specific browser-based clients, tighten it in `server.js`.

## Configuration

Copy `.env.example` to `.env` (it is git-ignored) and fill it in.

The server will not start unless the variables marked **required** are set, so a run without configuration can't reach real infrastructure by accident.

**Proxmox API**

| Variable | Notes |
| --- | --- |
| `PROXMOX_HOST` | **Required.** Proxmox host name or IP |
| `PROXMOX_PORT` | API port, usually `8006` |
| `PROXMOX_TOKEN_ID` | **Required.** API token ID, e.g. `user@pam!mcp` |
| `PROXMOX_TOKEN_SECRET` | **Required.** API token secret |
| `PROXMOX_NODE` | Default node name, e.g. `pve` |
| `PROXMOX_CA_CERT` | CA to trust for the API, e.g. a copy of `/etc/pve/pve-root-ca.pem` |

**SSH (used by the shell tools)**

| Variable | Notes |
| --- | --- |
| `PROXMOX_SSH_HOST` | **Required.** Host to SSH into |
| `PROXMOX_SSH_PORT` | Usually `22` |
| `PROXMOX_SSH_USER` | Usually `root` |
| `PROXMOX_SSH_KEY` | Path to the private key |

**Server and OAuth**

| Variable | Notes |
| --- | --- |
| `MCP_PORT` | Port to listen on, default `3000` |
| `MCP_BASE_URL` | **Required.** Public HTTPS address of this server |
| `AUTHENTIK_URL` | **Required.** Base URL of your Authentik instance |
| `AUTHENTIK_APP_SLUG` | Authentik application slug, e.g. `proxmox-mcp` |

**Security**

| Variable | Notes |
| --- | --- |
| `AUTH_MODE` | See [Modes](#modes) |
| `SHELL_MODE` | See [Modes](#modes) |
| `AUDIT_LOG` | Path to the JSON Lines audit log |
| `RATE_LIMIT_PER_MINUTE` | Requests per client IP per minute, default `120`. `0` disables. |
| `TRUST_PROXY_HOPS` | Set to `1` behind a tunnel or single reverse proxy so limits apply per real client IP. Leave `0` when exposed directly. |

## Tests

```bash
npm test
```

Uses Node's built-in test runner, with no extra dependencies and no network or Proxmox access. CI runs the suite and `npm audit` on every pull request and push to `main`.

The suite covers:

- the read-only shell allowlist, including the cases it must refuse (chaining, redirects, substitution, `date -s`, `find -delete`, `ss -K`, `ip link set` and so on)
- `SHELL_MODE` enforcement across `full`, `readonly` and `off`, including tools that run shell commands indirectly
- which tool calls require `confirm: true`, and that only the boolean `true` counts
- argument validation against the real tool schemas, including shell and path injection attempts
- audit log redaction of secret-looking fields

## Project layout

```text
server.js                 Entry point: Express setup, CORS, /health, rate limiter, routers
src/
  config.js               Environment-driven CONFIG and SECURITY settings
  constants.js            Timeouts, cache TTLs and limits
  tools.js                Every MCP tool (schema, confirmation rule, implementation) and callTool
  policy.js               SHELL_MODE enforcement and the read-only command allowlist
  validate.js             Tool argument validation against each tool's input schema
  jsonrpc.js              MCP JSON-RPC method handling and tool-call auditing
  rpc.js                  JSON-RPC 2.0 result and error helpers
  auth.js                 Bearer token verification and the requireAuth middleware
  authentik.js            Authentik endpoints and OAuth scopes
  rateLimit.js            Per-IP rate limiter
  proxmox.js              Proxmox REST API client
  ssh.js                  SSH client
  audit.js                JSON Lines audit log with secret redaction
  utils.js                Small shared helpers
  routes/
    mcp.js                MCP transports: /mcp, /sse, /messages
    oauth.js              OAuth discovery and proxy endpoints
    middleware.js         Body parsing, async handler wrapper, error handlers
test/                     Unit tests (npm test)
docs/SETUP.md             Step-by-step setup guide
deploy/                   systemd unit file
Dockerfile                Container image
```

## License and privacy

MIT. See [LICENSE](LICENSE).

See [PRIVACY.md](PRIVACY.md) for what this server logs and where data goes.
