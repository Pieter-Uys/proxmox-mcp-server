# Privacy

Proxmox MCP Server is self-hosted software. It runs on your own infrastructure and has no telemetry. The maintainer does not receive any data from your installation.

## What the server processes

- **Tool calls from your AI assistant.** Arguments are used to call your Proxmox VE API and, for shell-style tools, to run commands over SSH on your Proxmox host.
- **Credentials you configure.** The Proxmox API token and SSH key stay on the server and are sent only to your configured Proxmox host. They are never written to logs.
- **Sign-in data.** Bearer tokens are verified locally against the signing keys of your own Authentik instance, fetched from its JWKS endpoint. Tokens are not sent to Authentik. Verification results are cached in memory for up to 5 minutes, keyed by a hash of the token.

## What the server logs

- **Audit log** (`AUDIT_LOG`, JSON Lines on local disk): timestamp, authenticated user, source IP, tool name, arguments, outcome and duration. For community scripts it also records the script URL and git ref. Fields named like passwords, secrets, tokens or private keys are redacted. Redaction is by field name only: a secret typed into a command string (for example `host_shell` with `mysql -pSecret`) is logged as written. Each tool call gets a `started` entry before it runs and an outcome entry after; with `AUDIT_REQUIRED=true` (the default) a call whose entry can't be written is refused. You control retention and rotation.
- **Process logs** (stdout or journald): the JSON-RPC method, the tool name, the request id and whether the reply was an error, with control characters stripped. Tool arguments and results are never written to the process log.

## Network destinations

- Your Proxmox host (API and SSH).
- Your Authentik instance.
- `raw.githubusercontent.com`, only when the `run_community_script` tool is used, to fetch the requested community script. It is fetched from the commit or tag in `COMMUNITY_SCRIPTS_REF`, or from the `main` branch if that is unset. The script itself then fetches further files from GitHub (the shared helpers in `community-scripts/core`), from the Proxmox host.

The server does not use analytics or advertising services. When `run_community_script` fetches a script, `raw.githubusercontent.com` receives the request and its network metadata.

## Your responsibilities

Because tool arguments and your user identity are recorded in the audit log, treat that file as sensitive. Delete or rotate it according to your own retention needs.

## Questions

Open an issue at https://github.com/Pieter-Uys/proxmox-mcp-server/issues.
