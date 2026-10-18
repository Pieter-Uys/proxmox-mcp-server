# Getting started

This guide takes you from nothing to a working server. Allow about 30 minutes if you already run Proxmox and Authentik.

## What you need

| Requirement | Why |
| --- | --- |
| Proxmox VE host | The thing being managed |
| Node.js 20.6 or newer, or Docker | To run the server |
| [Authentik](https://goauthentik.io) | The server uses it as its OAuth login provider |
| A public HTTPS address for the server | Claude's remote connectors must reach it over the internet. A Cloudflare Tunnel works well and needs no open ports |

The server is built around Authentik. Other OpenID providers are not supported. `AUTH_MODE=off` disables login entirely and is only suitable for local testing, never for a server reachable from the internet.

## 1. Create a Proxmox API token

1. In the Proxmox web UI, go to **Datacenter, Permissions, API Tokens, Add**.
2. Choose a user (for example `root@pam`, or a dedicated user) and a token name such as `mcp`.
3. Decide on **Privilege Separation**. If it is ticked, the token has no permissions until you grant them under **Datacenter, Permissions, Add, API Token Permission**.
4. Copy the secret when it is shown. It is displayed once.

Your `PROXMOX_TOKEN_ID` is `user@realm!tokenname`, for example `root@pam!mcp`.

Permissions: for read-only use (`get_status` and GET calls through `proxmox_api`) the `PVEAuditor` role on path `/` is enough. The tools that create, stop, back up or reconfigure things need a role that can do those actions, for example `PVEAdmin`. Grant the minimum you need.

If Proxmox uses its own self-signed certificate, copy `/etc/pve/pve-root-ca.pem` to the server and set `PROXMOX_CA_CERT` to its path.

## 2. Give the server SSH access to the host

The shell tools (`host_shell`, `lxc_shell`, `vm_ssh`, ZFS and `network_config apply`) run commands over SSH.

```
ssh-keygen -t ed25519 -f ./mcp_key -N ""
ssh-copy-id -i ./mcp_key.pub root@your-proxmox-host
```

Set `PROXMOX_SSH_KEY` to the private key's path and `PROXMOX_SSH_HOST` to the host. If you only want API tools, set `SHELL_MODE=off`. `SHELL_MODE=readonly` allows only a short allowlist of read-only commands.

## 3. Set up Authentik

In Authentik, create an **OAuth2/OpenID Provider** and an **Application** that uses it:

- **Application slug:** must match `AUTHENTIK_APP_SLUG` (default `proxmox-mcp`). The server derives its issuer and key URLs from it.
- **Client type:** public is fine for MCP clients that use PKCE. Note the **client ID** it generates, because you enter it in your MCP client.
- **Redirect URIs:** the callback URL of your MCP client. For Claude's connectors this is `https://claude.ai/api/mcp/auth_callback`. Check your client's documentation if you use another.
- **Signing key:** choose a certificate-based key so tokens are signed with RS256. The default self-signed Authentik certificate works.
- **Issuer mode:** use the default, where each provider has its own issuer.
- **Scopes:** `openid`, `profile`, `email` and `offline_access`. `offline_access` lets clients renew tokens without signing in again, so make sure it is enabled for the provider.

Then bind the application to the users or groups allowed to use it.

## 4. Configure the server

```
cp .env.example .env
```

Fill in at least `PROXMOX_HOST`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET`, `PROXMOX_SSH_HOST`, `MCP_BASE_URL` (your public address) and `AUTHENTIK_URL`. The server refuses to start if any of them is missing. All settings are listed in the README.

If the server sits behind a tunnel or reverse proxy, set `TRUST_PROXY_HOPS=1`, or every client will share one rate limit.

## 5. Run it

### Directly with Node

```
npm ci --omit=dev
node --env-file=.env server.js
```

### As a systemd service

See [`deploy/proxmox-mcp.service`](../deploy/proxmox-mcp.service). It expects the code in `/opt/proxmox-mcp` with the `.env` next to it.

### With Docker

```
docker build -t proxmox-mcp .
docker run -d --name proxmox-mcp --restart unless-stopped \
  --env-file .env -p 3000:3000 \
  -v proxmox-mcp-data:/data \
  -v /path/to/mcp_key:/keys/mcp_key:ro \
  proxmox-mcp
```

Use `PROXMOX_SSH_KEY=/keys/mcp_key` and, if needed, `PROXMOX_CA_CERT=/keys/pve-root-ca.pem` in the `.env`, and mount those files the same way. The audit log goes to `/data/audit.jsonl` by default. Docker's `--env-file` does not strip quotes, so write values without quotes.

Check it is up:

```
curl http://localhost:3000/health
```

You should see `{"status":"ok","tools":13}`.

## 6. Expose it with a Cloudflare Tunnel

1. In Cloudflare Zero Trust, go to **Networks, Tunnels, Create a tunnel** and install `cloudflared` on the machine running the server.
2. Add a public hostname, for example `mcp.example.com`, pointing at `http://localhost:3000`.
3. Set `MCP_BASE_URL=https://mcp.example.com` in `.env` and restart the server.
4. Set `TRUST_PROXY_HOPS=1`.

## 7. Connect Claude

Add a custom connector in Claude with the URL `https://mcp.example.com/mcp`. When prompted, enter the Authentik client ID and sign in. Ask Claude to run `get_status` to confirm it works.

## Troubleshooting

- **Server exits at startup:** read the message. It names the missing or invalid setting.
- **401 on every request:** the token issuer or signing key does not match. Check `AUTHENTIK_URL` and that the application slug equals `AUTHENTIK_APP_SLUG`.
- **429 responses:** the rate limit was reached. Raise `RATE_LIMIT_PER_MINUTE`, and check `TRUST_PROXY_HOPS` behind a proxy.
- **Proxmox calls fail with a TLS error:** set `PROXMOX_CA_CERT` as described above.
- **Shell tools are blocked:** check `SHELL_MODE`, and that the SSH key works with `ssh -i <key> root@<host>`.
- **No audit entries:** the `AUDIT_LOG` directory must be writable by the user running the server.
