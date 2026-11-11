# Getting started

This guide takes you from nothing to a working server. Allow about 30 minutes if you already run Proxmox and Authentik.

## What you need

| Requirement | Why |
| --- | --- |
| Proxmox VE host | The thing being managed |
| Node.js 22 or newer, or Docker | To run the server |
| [Authentik](https://goauthentik.io) | The server uses it as its OAuth login provider |
| A public HTTPS address for the server | Claude's remote connectors must reach it over the internet. A Cloudflare Tunnel works well and needs no open ports |

The server is built around Authentik. Other OpenID providers are not supported. `AUTH_MODE=off` disables login entirely and is only suitable for local testing, never for a server reachable from the internet. The server refuses to start in `off` or `log` mode unless you also set `ALLOW_INSECURE_AUTH=yes`, and then listens on `127.0.0.1` only.

## 1. Create a Proxmox API token

Use a dedicated Proxmox user, not `root@pam`, and give its token only the rights you need. Start read-only, then add rights as you decide which tools the assistant may use. On the Proxmox host:

```
# A user in the Proxmox realm, with no shell login
pveum user add mcp@pve --comment "MCP server"

# A privilege-separated token: it starts with no rights of its own
pveum user token add mcp@pve mcp --privsep 1

# Read-only: enough for get_status and GET calls through proxmox_api
pveum acl modify / --tokens 'mcp@pve!mcp' --roles PVEAuditor
```

Copy the token secret when it is shown. It is displayed once. Your `PROXMOX_TOKEN_ID` is `mcp@pve!mcp`.

To let the assistant act, add a custom role with just those privileges rather than `PVEAdmin`. For example, to start and stop guests and take backups:

```
pveum role add MCPOperator --privs "VM.Audit VM.PowerMgmt VM.Backup Datastore.Audit Datastore.AllocateSpace Sys.Audit"
pveum acl modify / --tokens 'mcp@pve!mcp' --roles MCPOperator
```

Grant it on a narrower path (`/vms/101`, `/storage/local`) where you can. Using `root@pam` instead gives the assistant every right on the cluster; make that a deliberate choice, not the default.

If Proxmox uses its own self-signed certificate, copy `/etc/pve/pve-root-ca.pem` to the server and set `PROXMOX_CA_CERT` to its path.

## 2. Give the server SSH access to the host

The shell tools (`host_shell`, `lxc_shell`, `vm_ssh`, ZFS and `network_config apply`) run commands over SSH, as the SSH user, directly (the server does not use `sudo`). That user's own rights are the real limit on what they can do, so choose it first:

- **No shell tools:** set `SHELL_MODE=off` and skip this step.
- **Read-only checks only:** create a non-root user (for example `mcp`), add it to the `systemd-journal` and `adm` groups so it can read logs, and set `SHELL_MODE=readonly`. Commands like `uptime`, `df`, `journalctl` and `ss` work; `pct`, `qm`, `zfs` and anything under `/etc/pve` won't, which is the point.
- **Full shell tools:** `pct exec`, `zfs`, `ifreload` and friends need root. Use `root` only if you want the assistant to have them, and keep `SHELL_MODE=full` so anything off the read-only list needs approval.

```
ssh-keygen -t ed25519 -f ./mcp_key -N ""
ssh-copy-id -i ./mcp_key.pub <user>@your-proxmox-host
```

Then restrict the key on the host. In that user's `~/.ssh/authorized_keys`, put options in front of the key so it only works from the server's address and can't forward ports or open a terminal:

```
from="203.0.113.10",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... mcp
```

The server never requests a terminal, so `no-pty` costs nothing.

Set `PROXMOX_SSH_KEY` to the private key's path and `PROXMOX_SSH_HOST` to the host.

Pin the host's own key so the server can't be talked into connecting to an impostor. On a machine that already trusts the host (or on the host itself), run:

```
ssh-keyscan your-proxmox-host | ssh-keygen -lf -
```

and set `PROXMOX_SSH_HOST_KEY` to the `SHA256:...` value for the key type the server will use (ed25519 if present). The server refuses to start without it while shell tools are enabled. `ALLOW_UNPINNED_SSH_HOST=yes` skips the check, which means any machine that answers as the host gets every shell command.

If you only want API tools, set `SHELL_MODE=off`. File reads (`cat`, `head`, `tail`, `grep`) run without approval only for files under `READONLY_PATHS` on the host, and always ask inside containers and VMs; add your own log directories to `READONLY_PATHS` if needed. If you want the assistant to look but never change anything, set `TOOL_MODE=readonly`: every call that would need approval is refused. `SHELL_MODE=readonly` allows only a short allowlist of read-only commands.

`vm_ssh` logs in to VMs with the same key, so add the public key to each VM you want it to reach (`ssh-copy-id -i ./mcp_key.pub root@<vm-ip>`). Two settings limit it:

- `VM_SSH_ALLOWED_CIDRS`: the address ranges `vm_ssh` may connect to, for example `192.168.10.0/24`. The default is every private range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), which keeps it off the internet but still includes your Proxmox host and the rest of your LAN, so narrow it to your VM subnets.
- `VM_SSH_PASSWORD_AUTH`: `off` by default, which means a `password` argument is refused. Passwords given to `vm_ssh` would pass through the model's context and the client's chat history, so use the key. Set `on` only if you accept that. Even then a password is only sent when the call includes the VM's `hostKey` fingerprint.

`vm_ssh` checks a VM's host key only when the call passes `hostKey`. There is no per-VM setting; without it, the VM's key is accepted as presented.

## 3. Set up Authentik

In Authentik, create an **OAuth2/OpenID Provider** and an **Application** that uses it:

- **Application slug:** must match `AUTHENTIK_APP_SLUG` (default `proxmox-mcp`). The server derives its issuer and key URLs from it.
- **Client type:** public is fine for MCP clients that use PKCE. Note the **client ID** it generates, because you enter it in your MCP client.
- **Redirect URIs:** the callback URL of your MCP client. For Claude's connectors this is `https://claude.ai/api/mcp/auth_callback`. Check your client's documentation if you use another.
- **Signing key:** choose a certificate-based key so tokens are signed with RS256. The default self-signed Authentik certificate works.
- **Issuer mode:** use the default, where each provider has its own issuer.
- **Scopes:** `openid`, `profile`, `email` and `offline_access`. `offline_access` lets clients renew tokens without signing in again, so make sure it is enabled for the provider.

Then bind the application to the users or groups allowed to use it.

Two settings tighten this further:

- `AUTHENTIK_AUDIENCE` (**required**): set it to the provider's Client ID, under Applications, Providers, your provider. The server then accepts a JWT only if it was issued for this client, rather than any token signed by the same provider. It refuses to start without it, unless `ALLOW_ANY_AUDIENCE=yes`.
- `ALLOWED_USERS`: a comma-separated list of usernames, emails or subject IDs. It is a second check after the application binding, applied on every request. Usernames or subject IDs are the safer choice: depending on your Authentik flows, users may be able to change their own email address.
- `ALLOWED_GROUPS`: a comma-separated list of Authentik group names. Members of any of them are allowed. The names come from the token's `groups` claim, which Authentik's default `profile` scope mapping includes. With both lists set, a match on either is enough.

## 4. Configure the server

```
cp .env.example .env
```

Fill in at least `PROXMOX_HOST`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET`, `PROXMOX_SSH_HOST`, `MCP_BASE_URL` (your public address) and `AUTHENTIK_URL`. The server refuses to start if any of them is missing. All settings are listed in the README.

If the server sits behind a tunnel or reverse proxy, set `TRUST_PROXY_HOPS=1`, or every client will share one rate limit. With it set, the audit log records the client IP from Cloudflare's `cf-connecting-ip` header. Behind a proxy other than Cloudflare, make sure the proxy removes any `cf-connecting-ip` header sent by clients.

## 5. Run it

### Directly with Node

```
npm ci --omit=dev
node --env-file=.env server.js
```

### As a systemd service

See [`deploy/proxmox-mcp.service`](../deploy/proxmox-mcp.service). It expects the code in `/opt/proxmox-mcp` with the `.env` next to it, and runs as a dedicated `proxmox-mcp` user. Set up in this order:

```
# 1. Service account with no login shell
sudo useradd --system --home-dir /opt/proxmox-mcp --shell /usr/sbin/nologin proxmox-mcp

# 2. Code, .env and SSH key owned by root, readable by the service group only
sudo chown -R root:proxmox-mcp /opt/proxmox-mcp
sudo chmod 640 /opt/proxmox-mcp/.env /opt/proxmox-mcp/mcp_key

# 3. Audit log: set this in .env, systemd creates the directory for the service user
#    AUDIT_LOG=/var/log/proxmox-mcp/audit.jsonl

# 4. Install and start
sudo cp deploy/proxmox-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proxmox-mcp
```

The unit sets `LogsDirectory=proxmox-mcp`, so `/var/log/proxmox-mcp` is created and owned by the service user on start. Keep `AUDIT_LOG` pointing there, because a relative path like the `./logs/audit.jsonl` in `.env.example` would not be writable.

### With Docker

```
docker build -t proxmox-mcp .

# Use a dedicated host account for the container, so no login user ever owns the SSH key.
# Skip this line if you already created proxmox-mcp for systemd above.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin proxmox-mcp
UID_MCP=$(id -u proxmox-mcp); GID_MCP=$(id -g proxmox-mcp)

# Key and audit-log directory owned by that account only
sudo install -d -m 700 -o $UID_MCP -g $GID_MCP /etc/proxmox-mcp /var/lib/proxmox-mcp
sudo install -m 400 -o $UID_MCP -g $GID_MCP ./mcp_key /etc/proxmox-mcp/mcp_key

docker run -d --name proxmox-mcp --restart unless-stopped \
  --user $UID_MCP:$GID_MCP \
  --env-file .env -p 127.0.0.1:3000:3000 \
  -v /var/lib/proxmox-mcp:/data \
  -v /etc/proxmox-mcp/mcp_key:/keys/mcp_key:ro \
  proxmox-mcp
```

In the `.env` you pass to Docker, set these paths, because the relative `AUDIT_LOG=./logs/audit.jsonl` from `.env.example` would not be writable inside the container:

```
AUDIT_LOG=/data/audit.jsonl
PROXMOX_SSH_KEY=/keys/mcp_key
# PROXMOX_CA_CERT=/keys/pve-root-ca.pem   (mount that file the same way, same ownership)
```

The container runs as the dedicated `proxmox-mcp` account, which is not a login user, so the private key is readable only by that account (and root). Docker's `--env-file` does not strip quotes, so write values without quotes.

**Keep port 3000 off the network.** The server speaks plain HTTP and expects HTTPS to be terminated in front of it. `127.0.0.1:3000:3000` publishes the port to the same machine only, which is right when `cloudflared` runs on the same host. If your tunnel or reverse proxy runs elsewhere, do not publish on all interfaces. Either put both containers on a shared Docker network and drop `-p` entirely (point the tunnel at `http://proxmox-mcp:3000`), or bind to a private interface address and restrict it with a firewall to the proxy's address.

Check it is up:

```
curl http://localhost:3000/health
```

You should see `{"status":"ok","tools":12}`.

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
