# Privacy

Proxmox MCP Server is self-hosted software. It runs on your own infrastructure and has no telemetry. The maintainer does not receive any data from your installation.

## What the server processes

- **Tool calls from your AI assistant.** Arguments are used to call your Proxmox VE API and, for shell-style tools, to run commands over SSH on your Proxmox host.
- **Credentials you configure.** The Proxmox API token and SSH key stay on the server and are sent only to your configured Proxmox host. They are never written to logs.
- **Sign-in data.** Bearer tokens are verified against your own Authentik instance. Verification results are cached in memory for up to 5 minutes, keyed by a hash of the token.

## What the server logs

- **Audit log** (`AUDIT_LOG`, JSON Lines on local disk): timestamp, authenticated user, source IP, tool name, arguments, outcome and duration. Fields named like passwords, secrets, tokens or private keys are redacted. You control retention and rotation.
- **Process logs** (stdout or journald): request method names and truncated request or response summaries, with control characters stripped.

## Network destinations

- Your Proxmox host (API and SSH).
- Your Authentik instance.
- `raw.githubusercontent.com`, only when the `run_community_script` tool is used, to fetch the requested community script.

No data is sent to analytics, advertising or other third-party services.

## Your responsibilities

Because tool arguments and your user identity are recorded in the audit log, treat that file as sensitive. Delete or rotate it according to your own retention needs.

## Questions

Open an issue at https://github.com/Pieter-Uys/proxmox-mcp-server/issues.
