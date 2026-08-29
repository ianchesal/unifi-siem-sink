# Security Policy

## Supported Versions

Only the latest release is supported with security fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately via [GitHub's private vulnerability reporting](https://github.com/ianchesal/unifi-siem-sink/security/advisories/new).

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested remediation, if you have one

I'll acknowledge receipt within 7 days and aim to release a fix within 30 days for confirmed issues.

## Scope

This project runs on a private homelab network and is not intended for public internet exposure. There are two trust boundaries to be aware of:

- **The syslog UDP listener has no authentication.** Anything that can reach this host on the configured syslog port (514 by default) can write events into the store. Bind it to a trusted interface/VLAN, or otherwise ensure only your UDM Pro (or other trusted senders) can reach it.
- **The MCP endpoint is protected by a Bearer token** (`MCP_SECRET`). Protect this secret and do not expose port 3000 to the internet.
