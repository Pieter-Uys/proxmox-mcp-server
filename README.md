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
| `vm_ssh` | SSH into a VM by IP address and run a command, with the server's SSH key. Private ranges only by default (`VM_SSH_ALLOWED_CIDRS`). An optional `hostKey` pins the VM's key; a `password` needs `VM_SSH_PASSWORD_AUTH=on` and a `hostKey` | Anything off the read-only allowlist |
| `run_community_script` | Run a [community-scripts.org](https://community-scripts.org) LXC script, from the commit or tag in `COMMUNITY_SCRIPTS_REF` if set. Untested through this server: runs without a terminal, stops after 20 minutes | Always (runs remote code as root) |

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
| **Authentication** | Every `/mcp`, `/sse` and `/messages` request needs a bearer token. JWTs are verified locally against Authentik's signing keys (RS256 only, issuer, expiry, and audience when `AUTHENTIK_AUDIENCE` is set). Opaque tokens are checked through Authentik's userinfo endpoint. Results are cached for up to 5 minutes per token hash, never past the token's own expiry. `ALLOWED_USERS` optionally limits which signed-in users are accepted, checked on every request. |
| **Confirmation** | Deletes, hard stops, network apply, ZFS commands, community scripts, non-GET `proxmox_api` calls and any shell command off the read-only allowlist, or that reads a path that can hold secrets (`/etc/shadow`, `/etc/pve/priv`, SSH keys, `*.pem`, `*.key`, `.env` files and similar), or that prints other processes' environments (`ps e`), or that greps recursively, are rejected unless sent with `confirm: true`. The rejection tells the model to get explicit approval from the user first. |
| **Shell modes** | `SHELL_MODE` controls every call that runs a shell command, including `storage_config` ZFS actions and `network_config apply`. |
| **Hard limits** | Refusals that `confirm: true` can't override: `vm_ssh` needs a literal IP address inside `VM_SSH_ALLOWED_CIDRS` (private ranges by default), and refuses a `password` unless `VM_SSH_PASSWORD_AUTH=on` and a `hostKey` is pinned. |
| **SSH** | `PROXMOX_SSH_HOST_KEY` pins the Proxmox host's key. Output is capped at 1 MiB per command, after which the command is stopped and the result marked truncated. Commands time out after 60 seconds (community scripts after 20 minutes), and a timeout says the command may still be running. |
| **Argument validation** | Every tool call is checked against the tool's input schema (types, enums, required fields, no unknown arguments) before policy runs. Values that reach shell commands or API paths (`vmid`, `node`, `iface`, `storage`, `script`, `zfsCommand`) are restricted to safe formats. |
| **Rate limiting** | OAuth and MCP routes are limited per client IP (`RATE_LIMIT_PER_MINUTE`). Over-limit requests get HTTP 429. `/health` is not limited. |
| **Audit log** | Every tool call and auth event is written as JSON Lines to `AUDIT_LOG`, with user, source IP, arguments (secrets redacted), outcome and duration. Community script calls also record the script URL and git ref. The source IP comes from `cf-connecting-ip` only when `TRUST_PROXY_HOPS` is above `0`. Rotate it with logrotate or similar on the host. |

### Modes

| Setting | Values |
| --- | --- |
| `AUTH_MODE` | `enforce` (default), `log` (accept but record failures), `off` |
| `SHELL_MODE` | `full` (default, risky commands need confirmation), `readonly` (single allowlisted read-only commands, no chaining, no sensitive paths, no follow modes), `off` |
| `VM_SSH_PASSWORD_AUTH` | `off` (default, `vm_ssh` uses the server's key only), `on` |

The server refuses to start if any of these has an unrecognised value, or if `VM_SSH_ALLOWED_CIDRS` or `COMMUNITY_SCRIPTS_REF` is malformed.

### Things to know

- **`confirm: true` is a speed bump, not a hard boundary.** The model sets it. It works alongside the client's own tool-approval prompts and the audit trail.
- **Set `PROXMOX_SSH_HOST_KEY`**, and narrow `VM_SSH_ALLOWED_CIDRS` to your VM subnets. The default allows every private range, which includes the Proxmox host and the rest of your LAN.
- **Pin community scripts** with `COMMUNITY_SCRIPTS_REF` if you use `run_community_script`, or disable shell tools if you don't.
- **CORS allows any origin** (`Access-Control-Allow-Origin: *`). This is deliberate: clients send a bearer token in the `Authorization` header and the server sets no cookies, so a page on another origin has no ambient credentials to abuse. If you only expect specific browser-based clients, tighten it in `server.js`.

### Residual risks

These hold even with every setting above in place:

- **`confirm: true` is set by the model.** The server can't tell whether the user really approved the action. A prompt-injected model can set it. Rely on your client's own tool-approval prompts for anything that matters, and review the audit log.
- **Read-only means "does not change the host", not "safe to show the model".** Commands on the allowlist run as the SSH user, usually root, and print what they read. The sensitive-path check covers known secret locations; the SSH user's own file permissions are the real limit.
- **The read-only allowlist is best effort.** It is a parser for a small set of commands, not a sandbox. Symlinks, hard links, copies of secrets in unexpected places, or an option it doesn't know about can still expose data or change state without confirmation. `qm config` and `pct config` output can include secrets a user stored there. Use `SHELL_MODE=readonly` or `off` where that matters.
- **The shell tools are still root on the host.** Once a command is confirmed, `host_shell`, `lxc_shell`, ZFS, `network_config apply` and community scripts run with the SSH user's full rights, usually root. Anyone who can sign in, or any model that convinces a user to approve, can do anything root can.
- **Community scripts are only partly pinned.** `COMMUNITY_SCRIPTS_REF` pins the top-level script, but upstream scripts load their helpers from `community-scripts/core` on `main`.
- **`vm_ssh` only verifies a VM's host key when the call includes `hostKey`.** Without it, a machine that can intercept traffic to the VM could impersonate it. Set `PROXMOX_SSH_HOST_KEY` for the Proxmox host itself.

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
| `PROXMOX_SSH_KEY` | Path to the private key. `vm_ssh` uses it too |
| `PROXMOX_SSH_HOST_KEY` | SHA256 fingerprint of the host's SSH key, from `ssh-keyscan <host> \| ssh-keygen -lf -`. When set, a host presenting another key is refused before authenticating. Unset means the key is not checked, and the server warns at startup |
| `VM_SSH_ALLOWED_CIDRS` | Comma-separated ranges `vm_ssh` may connect to, e.g. `192.168.10.0/24`. Default: private ranges only (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`). Narrow it to your VM subnets |
| `VM_SSH_PASSWORD_AUTH` | `off` (default): `vm_ssh` refuses a `password` argument and uses `PROXMOX_SSH_KEY`, so passwords never pass through the model's context. `on` allows passwords, and only together with a `hostKey` fingerprint |

**Server and OAuth**

| Variable | Notes |
| --- | --- |
| `MCP_PORT` | Port to listen on, default `3000` |
| `MCP_BASE_URL` | **Required.** Public HTTPS address of this server |
| `AUTHENTIK_URL` | **Required.** Base URL of your Authentik instance |
| `AUTHENTIK_APP_SLUG` | Authentik application slug, e.g. `proxmox-mcp` |
| `AUTHENTIK_AUDIENCE` | The OAuth client ID of the Authentik provider. When set, a JWT is accepted only if its `aud` claim contains it, so tokens Authentik issued to other applications are refused. Unset skips the check. Opaque tokens have no `aud` to check |

**Security**

| Variable | Notes |
| --- | --- |
| `AUTH_MODE` | See [Modes](#modes) |
| `SHELL_MODE` | See [Modes](#modes) |
| `AUDIT_LOG` | Path to the JSON Lines audit log |
| `COMMUNITY_SCRIPTS_REF` | Commit SHA or tag of `community-scripts/ProxmoxVE` that `run_community_script` fetches from. Unset uses `main`, which can change between the user's approval and the run; the confirmation message and audit entry then show the exact URL. See [Residual risks](#residual-risks) |
| `RATE_LIMIT_PER_MINUTE` | Requests per client IP per minute, default `120`. `0` disables. |
| `TRUST_PROXY_HOPS` | Set to `1` behind a tunnel or single reverse proxy so limits apply per real client IP. Leave `0` when exposed directly. The audit log only uses Cloudflare's `cf-connecting-ip` header when this is above `0`; otherwise any client could set it. |
| `ALLOWED_USERS` | Optional comma-separated usernames, emails or subject IDs allowed to use the server, checked on every request, including cached tokens. Others are refused with `user not allowed`. Unset allows anyone Authentik signs in. A value that lists no entries (such as `,`) stops the server at startup. |

## Tests

```bash
npm test
```

Uses Node's built-in test runner, with no extra dependencies and no network or Proxmox access. CI runs the suite and `npm audit` on every pull request and push to `main`.

The suite covers:

- the read-only shell allowlist, including the cases it must refuse (chaining, redirects, substitution, `date -s`, `find -delete`, `ss -K`, `ss -D`, abbreviated long options such as `ss --kil` and `journalctl --rot`, `systemctl --host`, `tail -f`, `ip link set` and so on)
- `SHELL_MODE` enforcement across `full`, `readonly` and `off`, including tools that run shell commands indirectly
- which tool calls require `confirm: true`, and that only the boolean `true` counts
- argument validation against the real tool schemas, including shell and path injection attempts
- audit log redaction of secret-looking fields
- sensitive-path reads (including `..` traversal and `/proc/*/root` paths), recursive `grep` in its abbreviated forms (`--rec`, `-d rec`), `ps e` and the `smartctl` set forms behind `-l` and `-d`
- `vm_ssh` IP validation, the private-range default, `VM_SSH_ALLOWED_CIDRS`, `hostKey` and the password gate
- SSH host key pinning, the output cap and that a failing output handler can't crash the process
- JWT verification with locally signed tokens: signature, `kid`, algorithm (`none`, `HS256`), issuer, expiry, `nbf`, audience, `ALLOWED_USERS` and the token cache
- community script URLs and their audit fields

## Project layout

```text
server.js                 Entry point: Express setup, CORS, /health, rate limiter, routers
src/
  config.js               Environment-driven CONFIG and SECURITY settings
  cidr.js                 IP address checks and CIDR allowlists for vm_ssh
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
