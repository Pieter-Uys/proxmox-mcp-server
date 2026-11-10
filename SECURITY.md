# Security policy

This server gives an AI assistant control of a Proxmox VE host, so security reports are taken seriously.

## Supported versions

Only the latest release on the `main` branch gets security fixes. There are no maintained older branches.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub's private vulnerability reporting: on the repository page, open **Security**, then **Report a vulnerability**. That opens a private advisory visible only to you and the maintainer.

Useful things to include:

- what an attacker can do, and from where (the internet, an authenticated client, or a prompt-injected model)
- the smallest request or tool call that shows it
- the commit you tested against

You can expect an acknowledgement within a week. Fixes are released on `main`, and the advisory is published once a fix is available, crediting you unless you ask otherwise.

## Scope

In scope: authentication and token handling, the read-only allowlist and confirmation policy, argument validation, SSH and Proxmox API handling, and anything that lets a caller do more than the documented settings allow.

Known limits are listed under [Residual risks](README.md#residual-risks) in the README. Reports that only restate one of those are welcome as discussion, but are not treated as vulnerabilities.
