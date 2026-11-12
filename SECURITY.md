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

## Docker image

The `Dockerfile` follows a Node LTS line by tag (`node:26-alpine`), not by digest. A build with `--pull` fetches the latest patch release of that line, which brings security fixes without a code change; a plain `docker build` can reuse an older cached base image. Either way, two builds of the same commit can use different base images, so builds are not reproducible. Rebuild regularly (at least monthly, and after a Node security release) with `docker build --pull` to stay patched.

The digest pin was dropped on purpose: SonarCloud's rule S8431 refuses a tag and a digest together, its automatic analysis can't exclude a rule from the repository, and a digest alone would leave Dependabot unable to tell which image to track. If you need reproducible builds, pin `node:26-alpine@sha256:...` in your own copy and accept the S8431 finding.

## Scope

In scope: authentication and token handling, the read-only allowlist and confirmation policy, argument validation, SSH and Proxmox API handling, and anything that lets a caller do more than the documented settings allow.

Known limits are listed under [Residual risks](README.md#residual-risks) in the README. Reports that only restate one of those are welcome as discussion, but are not treated as vulnerabilities.
