# Proxmox MCP Server

[![CI](https://github.com/Pieter-Uys/proxmox-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/Pieter-Uys/proxmox-mcp-server/actions/workflows/ci.yml)
![Node](https://img.shields.io/badge/node-%3E%3D22-339933?logo=node.js&logoColor=white)
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

Requires Node 22 or newer (CI tests 22, 24 and 26).

```bash
git clone https://github.com/Pieter-Uys/proxmox-mcp-server.git
cd proxmox-mcp-server
npm install
cp .env.example .env   # then fill it in, see Configuration
node --env-file=.env server.js
```

Check it is up with `curl http://localhost:3000/health`.

## Tools

The server exposes 12 tools.

| Tool | What it does | Needs `confirm: true` for |
| --- | --- | --- |
| `get_status` | Cluster, node, VM, LXC and storage status | Never (read-only) |
| `proxmox_api` | Any Proxmox REST API call | Every non-GET call, and GETs that read guest files or secrets (see below) |
| `manage_vm` | Start, stop, restart, shut down or delete a VM or LXC | Every action |
| `create_lxc` | Create a new LXC container | Always |
| `backup_vm` | Back up a VM or LXC | Always |
| `set_boot_order` | Set VM and LXC startup order | Always |
| `firewall_rule` | Manage Proxmox firewall rules | `add`, `delete` |
| `network_config` | Manage network interfaces and VLANs | Everything except `list` |
| `storage_config` | Manage NFS, SMB, ZFS and LVM storage. `zfs_create` creates one dataset from `dataset`, `properties` and `parents` | Everything except `list`, `zfs_list` |
| `host_shell` | Run a command on the Proxmox host over SSH | Anything off the read-only allowlist |
| `lxc_shell` | Run a command inside an LXC via `pct exec` | Anything off the read-only allowlist |
| `vm_ssh` | SSH into a VM by IP address and run a command, with the server's SSH key. Private ranges only by default (`VM_SSH_ALLOWED_CIDRS`). An optional `hostKey` pins the VM's key; a `password` needs `VM_SSH_PASSWORD_AUTH=on` and a `hostKey` | Anything off the read-only allowlist |

### MCP annotations

Every tool declares all four MCP annotation hints in `tools/list`, so clients can warn before risky calls:

- `readOnlyHint`: only `get_status` is read-only.
- `destructiveHint`: set on anything that can delete, stop or overwrite something.
- `idempotentHint`: set where repeating the call has no further effect.
- `openWorldHint`: set on the shell tools and `vm_ssh`, since they can reach beyond the Proxmox host.

A test keeps these hints consistent with each tool's confirmation and shell policy.

`initialize` negotiates the protocol version: it accepts `2025-03-26` or `2024-11-05`, uses the client's version if supported, and otherwise falls back to `2025-03-26`.

## Security model

| Layer | What it does |
| --- | --- |
| **Authentication** | Every `/mcp` request needs a bearer token. JWTs are verified locally against Authentik's signing keys (RS256 only, issuer, expiry, and audience when `AUTHENTIK_AUDIENCE` is set). Anything that isn't a JWT is refused without contacting Authentik (Authentik's access tokens are JWTs). Keys in the JWKS that can't verify RS256 signatures are skipped. Results are cached for up to 5 minutes per token hash, never past the token's own expiry. `ALLOWED_USERS` and `ALLOWED_GROUPS` optionally limit which signed-in users are accepted, checked on every request. |
| **Confirmation** | One rule: every call that is not a pure read needs `confirm: true`. That covers every `manage_vm` action (including `start`), creating containers, backups, boot order, firewall, network and storage changes, ZFS, non-GET `proxmox_api` calls, GETs that read guest files or secrets (the QEMU guest agent, `cloudinit/dump`, backup `file-restore`, `scan`, which makes the host probe targets, and `query-url-metadata`, which makes it fetch a URL; a list of known cases, not a guarantee), and any shell command off the read-only allowlist, or that reads a path that can hold secrets (`/etc/shadow`, `/etc/pve/priv`, SSH keys, `*.pem`, `*.key`, `.env` files and similar), or that prints other processes' environments (`ps e`), or that greps recursively, are rejected unless sent with `confirm: true`. The rejection tells the model to get explicit approval from the user first. |
| **File reads** | `cat`, `head`, `tail` and `grep` are read-only on the host only for files under `READONLY_PATHS` (logs, `/proc`, `/sys`, the cluster and guest configs under `/etc/pve`, and a few host config files by default), and never for a known secret path or for standard input (no file, or `-`). Inside containers and VMs (`lxc_shell`, `vm_ssh`) every file read needs `confirm: true`, because secrets there can be anywhere. `ls`, `stat`, `find`, `wc` and `du`, which show names, counts and sizes rather than contents, are unaffected, except that options which make them read a file as a list of names (`--files0-from`, `--exclude-from`) are refused, since the error output prints that file. |
| **Shell modes** | `SHELL_MODE` controls every call that runs a shell command, including `storage_config` ZFS actions and `network_config apply`. |
| **Hard limits** | Refusals that `confirm: true` can't override: `vm_ssh` needs a literal IP address inside `VM_SSH_ALLOWED_CIDRS` (private ranges by default), and refuses a `password` unless `VM_SSH_PASSWORD_AUTH=on` and a `hostKey` is pinned. |
| **SSH** | `PROXMOX_SSH_HOST_KEY` pins the Proxmox host's key. Output is capped at 1 MiB per command. Past that the channel is closed and the result is marked truncated; the remote command isn't killed and may keep running, and the result says so. Commands time out after 60 seconds, and a timeout says the command may still be running. |
| **Argument validation** | Every tool call is checked against the tool's input schema (types, enums, required fields, no unknown arguments) before policy runs. Values that reach shell commands or API paths (`vmid`, `node`, `iface`, `storage`, `script`, `dataset`, ZFS properties) are restricted to safe formats. |
| **Rate limiting** | OAuth and MCP routes are limited per client IP (`RATE_LIMIT_PER_MINUTE`). Over-limit requests get HTTP 429. `/health` is not limited. |
| **Audit log** | Every tool call and auth event is written as JSON Lines to `AUDIT_LOG`, with user, source IP, arguments (secrets redacted), outcome and duration. The source IP comes from `cf-connecting-ip` only when `TRUST_PROXY_HOPS` is above `0` and `TRUST_CLOUDFLARE_HEADER=true`. Rotate it with logrotate or similar on the host. |

### Modes

| Setting | Values |
| --- | --- |
| `AUTH_MODE` | `enforce` (default), `log` (accept but record failures), `off`. `log` and `off` need `ALLOW_INSECURE_AUTH=yes` and then listen on loopback only |
| `TOOL_MODE` | `full` (default), `readonly` (refuses every call that would need `confirm: true`, whatever the model sends: a look-but-don't-touch deployment) |
| `SHELL_MODE` | `full` (default, risky commands need confirmation), `readonly` (single allowlisted read-only commands, no chaining, no sensitive paths, no follow modes), `off` |
| `VM_SSH_PASSWORD_AUTH` | `off` (default, `vm_ssh` uses the server's key only), `on` |

The server refuses to start if any of these has an unrecognised value, or if `VM_SSH_ALLOWED_CIDRS`, `READONLY_PATHS` or `TOOL_TIMEOUT_SECONDS` is malformed.

### Things to know

- **`confirm: true` is a speed bump, not a hard boundary.** The model sets it. It works alongside the client's own tool-approval prompts and the audit trail.
- **Set `PROXMOX_SSH_HOST_KEY`**, and narrow `VM_SSH_ALLOWED_CIDRS` to your VM subnets. The default allows every private range, which includes the Proxmox host and the rest of your LAN.
- **No tool call holds its HTTP response open longer than `TOOL_TIMEOUT_SECONDS`** (90 by default), because proxies, tunnels and MCP clients cut long responses off on their own. The reply then says the work may still be running on the host.
- **One JSON-RPC request per POST.** Batches (a JSON array) are refused with Invalid Request, as in MCP revision 2025-06-18, so one HTTP request can't fan out into many tool calls. Notifications never get a reply. A tool that fails while running returns a result with `isError: true`, so the model can see what went wrong. Calling a tool that doesn't exist is a protocol error (Invalid params), as the MCP spec requires.
- **Proxmox API calls time out after 30 seconds** and fail if the reply is larger than 5 MiB, with a message to narrow the query.
- **CORS allows any origin** (`Access-Control-Allow-Origin: *`). This is deliberate: clients send a bearer token in the `Authorization` header and the server sets no cookies, so a page on another origin has no ambient credentials to abuse. If you only expect specific browser-based clients, tighten it in `server.js`.

### Residual risks

These hold even with every setting above in place:

- **`confirm: true` is set by the model.** The server can't tell whether the user really approved the action. A prompt-injected model can set it. Rely on your client's own tool-approval prompts for anything that matters, and review the audit log.
- **Read-only means "does not change the host", not "safe to show the model".** Commands on the allowlist run as the SSH user, usually root, and print what they read. The sensitive-path check covers known secret locations; the SSH user's own file permissions are the real limit.
- **Guest configs under `/etc/pve` are readable by default** (`/etc/pve/qemu-server/*.conf` and the `lxc` and `nodes/*` equivalents), and they can hold a cloud-init password hash, the same data `qm config` shows. Set `READONLY_PATHS` without those entries if that matters to you.
- **The read-only allowlist is best effort.** It is a parser for a small set of commands, not a sandbox. Symlinks, hard links, copies of secrets in unexpected places, or an option it doesn't know about can still expose data or change state without confirmation. `qm config` and `pct config` output can include secrets a user stored there. Use `SHELL_MODE=readonly` or `off` where that matters.
- **The shell tools are still root on the host.** Once a command is confirmed, `host_shell`, `lxc_shell`, ZFS and `network_config apply` run with the SSH user's full rights, usually root. Anyone who can sign in, or any model that convinces a user to approve, can do anything root can.
- **`vm_ssh` only verifies a VM's host key when the call includes `hostKey`.** Without it, a machine that can intercept traffic to the VM could impersonate it. Set `PROXMOX_SSH_HOST_KEY` for the Proxmox host itself.

### Protocol support

The transport is written by hand rather than with the MCP SDK, so following new protocol revisions is upkeep that has to be done here. Current decisions:

- **Versions:** `2025-03-26` and `2024-11-05` are negotiated. Batches are refused, as in `2025-06-18`.
- **`Origin` header:** not checked. The spec asks for it against DNS rebinding, but every request here needs a bearer token in the `Authorization` header and there are no cookies, so a page that rebinds a name to this server has no credential to send.
- **`MCP-Protocol-Version` header:** accepted but not required, so older clients keep working.
- **RFC 8707 resource indicators:** not validated. `AUTHENTIK_AUDIENCE` ties tokens to this client instead.

Revisit these when adding support for a newer revision.

## Upgrading

**From a version before the second security audit (November 2026):** the server now refuses to start until these are set, because each was optional before and an upgraded deployment had neither control in force:

- `PROXMOX_SSH_HOST_KEY` (unless `SHELL_MODE=off`): run `ssh-keyscan -p <port> <host> | ssh-keygen -lf -` and use the `SHA256:...` value.
- `AUTHENTIK_AUDIENCE` (unless `AUTH_MODE=off`): the provider's Client ID in Authentik.

The error at startup names the missing setting and how to get it. To start without one anyway, set `ALLOW_UNPINNED_SSH_HOST=yes` or `ALLOW_ANY_AUDIENCE=yes`.

`run_community_script` has been removed: it held one HTTP response open for up to 20 minutes, which proxies and clients cut off long before, leaving the script running with no result. `COMMUNITY_SCRIPTS_REF` is ignored (the server warns if it is set). To run a script deliberately, use `host_shell` with approval.

Behind a Cloudflare Tunnel, set `TRUST_CLOUDFLARE_HEADER=true` to keep recording real client IPs in the audit log; without it the log records the tunnel's address. `ALLOWED_USERS` entries without a prefix now match the username only: write `email:...` or `sub:...` for the others.

Expect more approval prompts for file reads: on the host, `cat`, `head`, `tail` and `grep` run without approval only for files under `READONLY_PATHS`, and inside containers and VMs every file read asks. Add your own log directories to `READONLY_PATHS` if they come up often.

**From a version before the third security audit (November 2026):** every command on the read-only list now names the options it accepts, so a rarely used option to `ls`, `df`, `lsblk` or the others needs approval instead of running, and `free -s` and `free -c` (which repeat until the timeout) always do. `wc` and `du` refuse `--files0-from` and `--exclude-from`. `cat`, `head`, `tail` and `grep` with no file, or with `-`, read standard input and need approval. The default `READONLY_PATHS` no longer includes all of `/etc/pve`, only the cluster and guest configs listed under Configuration, because `domains.cfg` and `sdn/` hold credentials outside `priv`; those two are now on the deny list as well. Other files there need approval to read.

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
| `PROXMOX_SSH_HOST_KEY` | SHA256 fingerprint of the host's SSH key, from `ssh-keyscan -p <port> <host> \| ssh-keygen -lf -`. **Required** unless `SHELL_MODE=off`. A host presenting another key is refused before authenticating. Waive with `ALLOW_UNPINNED_SSH_HOST=yes` (not recommended) |
| `VM_SSH_ALLOWED_CIDRS` | Comma-separated ranges `vm_ssh` may connect to, e.g. `192.168.10.0/24`. Default: private ranges only (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`). Narrow it to your VM subnets |
| `VM_SSH_PASSWORD_AUTH` | `off` (default): `vm_ssh` refuses a `password` argument and uses `PROXMOX_SSH_KEY`, so passwords never pass through the model's context. `on` allows passwords, and only together with a `hostKey` fingerprint |

**Server and OAuth**

| Variable | Notes |
| --- | --- |
| `MCP_PORT` | Port to listen on, default `3000` |
| `MCP_BIND_ADDRESS` | IP address to listen on, default `0.0.0.0` (needed for Docker port publishing). With `AUTH_MODE` `log` or `off` it defaults to, and must be, `127.0.0.1` or `::1` |
| `MCP_BASE_URL` | **Required.** Public HTTPS address of this server. Must be `https://` (`http://` only for localhost); a trailing slash is removed |
| `AUTHENTIK_URL` | **Required.** Base URL of your Authentik instance. Must be `https://` (`http://` only for localhost), since signing keys are fetched from it; a trailing slash is removed |
| `AUTHENTIK_APP_SLUG` | Authentik application slug, e.g. `proxmox-mcp` |
| `AUTHENTIK_AUDIENCE` | The OAuth client ID of the Authentik provider. **Required** unless `AUTH_MODE=off`. A JWT is accepted only if its `aud` claim contains it, so tokens Authentik issued to other applications are refused. Find it under Applications, Providers, your provider, Client ID. Waive with `ALLOW_ANY_AUDIENCE=yes` (not recommended) |
| `ALLOW_UNPINNED_SSH_HOST`, `ALLOW_ANY_AUDIENCE` | Set to `yes` to start without `PROXMOX_SSH_HOST_KEY` or `AUTHENTIK_AUDIENCE`. The server warns at startup while either is in effect |

**Security**

| Variable | Notes |
| --- | --- |
| `AUTH_MODE` | See [Modes](#modes) |
| `TOOL_MODE` | See [Modes](#modes) |
| `SHELL_MODE` | See [Modes](#modes) |
| `AUDIT_LOG` | Path to the JSON Lines audit log |
| `READONLY_PATHS` | Comma-separated absolute paths whose files `cat`, `head`, `tail` and `grep` may read on the host without approval. Default: `/var/log,/sys,/proc,/etc/pve/storage.cfg,/etc/pve/datacenter.cfg,/etc/pve/corosync.conf,/etc/pve/jobs.cfg,/etc/pve/firewall,/etc/pve/ha,/etc/pve/qemu-server,/etc/pve/lxc,/etc/pve/nodes/*/qemu-server,/etc/pve/nodes/*/lxc,/etc/network,/etc/hostname,/etc/hosts,/etc/os-release,/etc/apt/sources.list,/etc/apt/sources.list.d`. A `*` segment matches any one name. Setting it replaces the default. The deny list of secret paths still applies |
| `AUDIT_REQUIRED` | `true` (default): a tool call is refused if its audit entry can't be written, so nothing runs unrecorded. `false` runs it anyway and logs the failure |
| `TOOL_TIMEOUT_SECONDS` | Longest a tool call may hold its HTTP response open, default `90`. Keep it below your proxy's and client's own limits (Cloudflare's is about 100 seconds) |
| `RATE_LIMIT_PER_MINUTE` | Requests per client IP per minute, default `120`. `0` disables. |
| `TRUST_PROXY_HOPS` | Set to `1` behind a tunnel or single reverse proxy so limits apply per real client IP. Leave `0` when exposed directly. |
| `TRUST_CLOUDFLARE_HEADER` | `true` to record Cloudflare's `cf-connecting-ip` as the client IP in the audit log. Needs `TRUST_PROXY_HOPS` above `0`. Default `false`: behind another proxy (nginx, Traefik, Caddy) a client could set that header and forge its address |
| `ALLOWED_USERS` | Optional comma-separated entries, each matching one claim only: `user:alice` (username), `email:alice@example.com`, `sub:<subject id>`. An entry without a prefix matches the username only. Checked on every request, including cached tokens; others are refused with `user not allowed`. Unset allows anyone Authentik signs in. An unknown prefix, or a value with no entries, stops the server at startup. `ALLOWED_GROUPS` is often the simpler choice |
| `ALLOWED_GROUPS` | Optional comma-separated Authentik group names (from the token's `groups` claim). Members are allowed. With both lists set, matching either is enough. |
| `ALLOW_INSECURE_AUTH` | Must be `yes` for `AUTH_MODE=log` or `off` to start. Local testing only |

## Tests

```bash
npm test
```

Uses Node's built-in test runner, with no extra dependencies and no network or Proxmox access (a few tests use servers on `127.0.0.1`). CI runs the suite on Node 22, 24 and 26, enforces a coverage floor, and runs `npm audit` on every pull request and push to `main`. Actions are pinned to commit SHAs and the Docker base image to a digest.

The suite covers:

- the read-only shell allowlist, including the cases it must refuse (chaining, redirects, substitution, `date -s`, `find -delete`, `ss -K`, `ss -D`, abbreviated long options such as `ss --kil` and `journalctl --rot`, `systemctl --host`, `tail -f`, `ip link set` and so on)
- `SHELL_MODE` enforcement across `full`, `readonly` and `off`, including tools that run shell commands indirectly
- which tool calls require `confirm: true` (every non-read call), that only the boolean `true` counts, and that `TOOL_MODE=readonly` refuses them all
- `zfs_create` building only `zfs create`, with every word quoted
- argument validation against the real tool schemas, including shell and path injection attempts
- audit log redaction of secret-looking fields
- sensitive-path reads (including `..` traversal, other roots under `/proc/*/root`, and every `/proc/<pid>` file except a short list such as `status` and `cmdline`), recursive `grep` in its abbreviated forms (`--rec`, `-d rec`), and `ps` limited to shapes that can't fall back to BSD mode (`ps -auxe`)
- option values: a value taken from the next word never starts with `-` unless that option allows it (`journalctl -n --rotate` is refused)
- a regression list of every bypass either audit reported and the `smartctl` set forms behind `-l` and `-d`
- `vm_ssh` IP validation, the private-range default, `VM_SSH_ALLOWED_CIDRS`, `hostKey` and the password gate
- SSH host key pinning, the output cap and that a failing output handler can't crash the process
- JWT verification with locally signed tokens: signature, `kid`, algorithm (`none`, `HS256`), issuer, expiry, `nbf`, audience, `ALLOWED_USERS`, `ALLOWED_GROUPS`, unusable JWKS keys, non-JWT tokens refused without a network call, and the token cache
- typed `ALLOWED_USERS` entries never matching a different claim, `cf-connecting-ip` only with `TRUST_CLOUDFLARE_HEADER`, https-only service URLs, port ranges, and `tools/call` notifications refused
- `AUTH_MODE` `log`/`off` refusing to start without `ALLOW_INSECURE_AUTH=yes`, and binding to loopback
- the `TOOL_TIMEOUT_SECONDS` ceiling on every tool call

## Project layout

```text
server.js                 Entry point: Express setup, CORS, /health, rate limiter, routers
src/
  config.js               Environment-driven CONFIG and SECURITY settings
  cidr.js                 IP address checks and CIDR allowlists for vm_ssh
  constants.js            Timeouts, cache TTLs and limits
  tools.js                Every MCP tool (schema, confirmation rule, implementation) and callTool
  policy.js               SHELL_MODE enforcement and the read-only command allowlist
  apiPolicy.js            Proxmox GET paths that need confirmation
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
    mcp.js                MCP transport: POST /mcp (one request per POST, no batches) and GET /mcp
    oauth.js              OAuth discovery and proxy endpoints
    middleware.js         Body parsing, async handler wrapper, error handlers
test/                     Unit tests (npm test)
docs/SETUP.md             Step-by-step setup guide
SECURITY.md               How to report a vulnerability
deploy/                   systemd unit file
Dockerfile                Container image
```

## License and privacy

MIT. See [LICENSE](LICENSE).

See [PRIVACY.md](PRIVACY.md) for what this server logs and where data goes.

To report a security problem, see [SECURITY.md](SECURITY.md). Please don't open a public issue for it.
