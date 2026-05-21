# Security Policy

## Reporting a Vulnerability

Please report security issues privately via GitHub's "Report a vulnerability"
button on the Security tab of this repository. We aim to acknowledge new
reports within 5 business days.

## Default Security Posture

Greyproxy is designed to run on the same host as the workloads it proxies. By
default it binds **only to the loopback interface (`127.0.0.1`)** on every
port:

| Service       | Default bind        |
|---------------|---------------------|
| Dashboard/API | `127.0.0.1:43080`   |
| HTTP Proxy    | `127.0.0.1:43051`   |
| SOCKS5 Proxy  | `127.0.0.1:43052`   |
| DNS Proxy     | `127.0.0.1:43053`   |

This prevents the dashboard, REST API, and proxy ports from being reachable
from other machines on the network without explicit operator action — the
proxies cannot be abused as an open relay, the DNS resolver cannot be used
for amplification, and the management API cannot be reached by other hosts.

To expose greyproxy on a network interface, either:

- pass `--host <ip>` to `greyproxy serve` (IP literal only; hostnames are
  rejected), or
- set the top-level `host:` field in the config file.

The CLI flag wins over the YAML field. Explicit hosts in individual `addr:`
entries (e.g. `addr: "0.0.0.0:43080"`) are honoured as-is.

When the resolved host is an unspecified address (`0.0.0.0` or `::`),
greyproxy logs a warning at startup so the choice is visible in the logs.

## Supported Versions

Security fixes target the latest tagged release.
