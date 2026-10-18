# Proxmox MCP Server

Remote MCP server that lets an AI assistant (Claude) manage a Proxmox VE host through tool calling. Node.js + Express, JSON-RPC over HTTP, OAuth via Authentik, exposed through a Cloudflare Tunnel.

## Tools (13)
`get_status`, `proxmox_api`, `manage_vm`, `create_lxc`, `backup_vm`, `set_boot_order`, `firewall_rule`, `network_config`, `storage_config`, `host_shell`, `lxc_shell`, `vm_ssh`, `run_community_script`

Every tool declares all four MCP annotation hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) in `tools/list`, so clients can warn before risky calls. Only `get_status` is read-only; everything that can delete, stop or overwrite something is marked destructive. `initialize` negotiates the protocol version (`2025-03-26` or `2024-11-05`, using the client's if supported, otherwise `2025-03-26`). The shell tools, `run_community_script` and `vm_ssh` are marked open-world because they can reach beyond the Proxmox host. A test keeps the hints consistent with each tool's confirmation and shell policy.

## Security model
- **Authentication:** every `/mcp`, `/sse` and `/messages` request must carry a bearer token. JWTs are verified locally against Authentik's signing keys (RS256, issuer, expiry); opaque tokens are checked via Authentik's userinfo endpoint. Results are cached for up to 5 minutes per token hash. `AUTH_MODE=enforce|log|off`.
- **Destructive-action confirmation:** deletes, hard stops, network apply, ZFS commands, community scripts, every non-GET `proxmox_api` call, and every shell command that isn't on the read-only allowlist are rejected unless called with `confirm: true`. The rejection tells the model to get explicit user approval first.
- **Shell modes:** `SHELL_MODE=full` (default, with confirmation), `readonly` (single allowlisted read-only commands, no chaining), or `off`. This covers every call that runs a shell command, including `storage_config` ZFS actions and `network_config apply`. The server refuses to start if `AUTH_MODE` or `SHELL_MODE` has an unrecognised value.
- **Argument validation:** every tool call is checked against the tool's input schema before policy runs (types, enums, required fields, no unknown arguments). Values that reach shell commands or API paths (`vmid`, `node`, `iface`, `storage`, `script`, `zfsCommand`) are restricted to safe formats.
- **Rate limiting:** OAuth and MCP routes are limited per client IP (`RATE_LIMIT_PER_MINUTE`); over-limit requests get HTTP 429. `/health` is not limited.
- **Audit log:** every tool call and auth event is written as JSON Lines to `AUDIT_LOG` with user, source IP, arguments (secrets redacted), outcome and duration. Rotated weekly via logrotate.

Notes:
- `confirm: true` is a speed bump, not a hard boundary, since the model sets it. It works together with the client's own tool-approval prompts and the audit trail.
- CORS allows any origin (`Access-Control-Allow-Origin: *`). That is deliberate: clients authenticate with a bearer token in the `Authorization` header and the server sets no cookies, so a page on another origin has no ambient credentials to abuse. If you only expect specific browser-based clients, restrict it in `server.js`.

## Configuration
Copy `.env.example` to `.env` (never committed) and fill it in. The server refuses to start unless `PROXMOX_HOST`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET`, `PROXMOX_SSH_HOST`, `MCP_BASE_URL` and `AUTHENTIK_URL` are set, so a run without configuration can't reach real infrastructure by accident. The full list: `PROXMOX_HOST`, `PROXMOX_PORT`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET`, `PROXMOX_NODE`, `PROXMOX_CA_CERT` (CA to trust for the Proxmox API, e.g. `/etc/pve/pve-root-ca.pem`), `PROXMOX_SSH_HOST`, `PROXMOX_SSH_PORT`, `PROXMOX_SSH_USER`, `PROXMOX_SSH_KEY`, `MCP_PORT`, `MCP_BASE_URL`, `AUTHENTIK_URL`, `AUTHENTIK_APP_SLUG`, `AUTH_MODE`, `SHELL_MODE`, `AUDIT_LOG`, `RATE_LIMIT_PER_MINUTE` (default 120 requests per client IP per minute, 0 disables), `TRUST_PROXY_HOPS` (set to 1 behind a tunnel or single reverse proxy so limits apply per real client IP).

## Run
Requires Node 20.6 or newer.
```
npm install
node --env-file=.env server.js
```

## Tests
```
npm test
```
Uses Node's built-in test runner, with no extra dependencies and no network or Proxmox access. The suite covers:
- the read-only shell allowlist, including the cases it must refuse (chaining, redirects, substitution, `date -s`, `find -delete`, `ss -K`, `ip link set`, and so on)
- `SHELL_MODE` enforcement across `full`, `readonly` and `off`, including tools that run shell commands indirectly
- which tool calls require `confirm: true`, and that only the boolean `true` counts
- argument validation against the real tool schemas, including shell and path injection attempts
- audit log redaction of secret-looking fields

## Project layout
- `server.js`: entry point. Express setup, CORS, `/health`, mounts the routers.
- `src/config.js`: environment-driven `CONFIG` and `SECURITY` settings.
- `src/constants.js`: timeouts, cache TTLs and limits.
- `src/tools.js`: every MCP tool (schema, confirmation rule and implementation together) and `callTool`.
- `src/policy.js`: `SHELL_MODE` enforcement and the read-only command allowlist.
- `src/jsonrpc.js`: MCP JSON-RPC method handling and tool-call auditing.
- `src/auth.js`: bearer token verification (local JWKS for JWTs, userinfo for opaque tokens) and the `requireAuth` middleware.
- `src/proxmox.js`, `src/ssh.js`: Proxmox REST API and SSH clients.
- `src/audit.js`: JSON Lines audit log with secret redaction.
- `src/routes/mcp.js`, `src/routes/oauth.js`: MCP transports (`/mcp`, `/sse`, `/messages`) and the OAuth discovery/proxy endpoints.
- `src/utils.js`: small shared helpers.
- `test/`: unit tests (`npm test`).

## License
MIT. See `LICENSE`.

## Privacy

See [PRIVACY.md](PRIVACY.md) for what this server logs and where data goes.
