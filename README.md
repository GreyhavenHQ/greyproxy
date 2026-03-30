# Greyproxy

A managed network proxy with a built-in web dashboard, rule engine, and REST API. Greyproxy wraps powerful multi-protocol tunneling capabilities with an intuitive management layer for controlling and monitoring network traffic.

This software is meant to be used with [**greywall**](https://github.com/GreyhavenHQ/greywall), a deny-by-default sandbox that wraps commands with filesystem and network isolation.

  <table>
    <tr>
      <td align="center" width="25%"><img src="https://github.com/user-attachments/assets/a4d1f40a-153e-4815-bcd2-c8b23d91cf54"
  width="100%" /><br /><sub>Dashboard</sub></td>
      <td align="center" width="25%"><img width="1752" height="1216" alt="image" src="https://github.com/user-attachments/assets/9100172e-b23e-4d78-aaba-5adba1029bb2" /><br /><sub>Pending Requests</sub></td>
      <td align="center" width="25%"><img src="https://github.com/user-attachments/assets/4108b7b7-20b0-4a43-b2bb-913bf70a0dd0"
  width="100%" /><br /><sub>Rules</sub></td>
      <td align="center" width="25%"><img src="https://github.com/user-attachments/assets/c707c7c5-396c-4830-a65f-7250c2041f48"
  width="100%" /><br /><sub>Logs</sub></td>
    </tr>
  </table>

## Features

- **Web Dashboard**: Real-time overview of proxy traffic, pending requests, and rule management, all served from a single binary
- **Rule Engine**: Define allow/deny rules with pattern matching on container, destination, and port
- **Pending Requests**: Review and approve/deny network requests awaiting a policy decision
- **Multi-Protocol Proxy**: HTTP, SOCKS5, and DNS proxies with forwarding chain support
- **DNS Caching**: Built-in DNS resolution and caching with hostname enrichment on requests
- **Sensitive Header Redaction**: Automatically strips Authorization, Cookie, API keys, and tokens from stored HTTP transactions. Configurable patterns via the API.
- **REST API**: Full HTTP API for automation and integration
- **Real-Time Updates**: WebSocket-based live updates on the dashboard
- **Single Binary**: Web UI, fonts, icons, and assets are all embedded, no separate frontend to deploy

## Quick Start

### Homebrew (macOS)

```bash
brew tap greyhavenhq/tap
brew install greyproxy
greyproxy install
```

### Build from Source

```bash
git clone https://github.com/greyhavenhq/greyproxy.git
cd greyproxy
go build ./cmd/greyproxy
./greyproxy install
```

**macOS only:** after building, codesign the binary before installing to avoid Gatekeeper quarantine:

```bash
codesign --sign - --force ./greyproxy
```

Alternatively, use [`greywall setup`](https://github.com/GreyhavenHQ/greywall) to handle the full build and install automatically.

### What `install` Does

`greyproxy install` handles the full setup in one step:

1. Copies the binary to `~/.local/bin/` (skipped for Homebrew installs)
2. Registers a launchd user agent (macOS) or systemd user service (Linux)
3. Generates a CA certificate for HTTPS inspection (if not already present)
4. Installs the CA certificate into the OS trust store (requires sudo)
5. Starts the service

The dashboard will be available at `http://localhost:43080`.

If you decline the sudo prompt for certificate trust, HTTPS inspection will not work until you run `greyproxy cert install` manually.

To remove everything:

```bash
greyproxy uninstall
```

### Certificate Management

The CA certificate is generated and trusted automatically during `greyproxy install`. For manual control:

```bash
greyproxy cert generate    # regenerate the CA certificate
greyproxy cert install     # trust it on the OS (requires sudo)
greyproxy cert uninstall   # remove from OS trust store
greyproxy cert reload      # reload cert in running server (no restart needed)
```

If you regenerate the certificate, greyproxy detects the file change and reloads it automatically.

### Run in Foreground

To run the server directly without installing as a service:

```bash
greyproxy serve
```

Or with a custom configuration file:

```bash
greyproxy serve -C greyproxy.yml
```

### Service Management

Once installed, manage the service with:

```bash
greyproxy service status
greyproxy service start
greyproxy service stop
greyproxy service restart
```

### Configuration

Greyproxy ships with a sensible default configuration embedded in the binary. To customize, pass a YAML config file with `-C`. See [`greyproxy.yml`](greyproxy.yml) for a full example.

```yaml
greyproxy:
  addr: ":43080"        # Dashboard and API
  db: "./greyproxy.db"  # SQLite database

services:
  - name: http-proxy
    addr: ":43051"
    handler:
      type: http
    listener:
      type: tcp

  - name: socks5-proxy
    addr: ":43052"
    handler:
      type: socks5
    listener:
      type: tcp
```

## Default Ports

| Service       | Port    |
|---------------|---------|
| Dashboard/API | `43080` |
| HTTP Proxy    | `43051` |
| SOCKS5 Proxy  | `43052` |
| DNS Proxy     | `43053` |

## Documentation

Full documentation is available at [docs.greywall.io/greyproxy](https://docs.greywall.io/greyproxy):

- [Quick Start](https://docs.greywall.io/greyproxy/quickstart)
- [Configuration Reference](https://docs.greywall.io/greyproxy/configuration)
- [Rule Engine](https://docs.greywall.io/greyproxy/rules)
- [REST API](https://docs.greywall.io/greyproxy/api)
- [Dashboard](https://docs.greywall.io/greyproxy/dashboard)
- [Multi-Protocol Proxy](https://docs.greywall.io/greyproxy/proxy)
- [Service Management](https://docs.greywall.io/greyproxy/service)
- [Architecture](https://docs.greywall.io/greyproxy/architecture)
- [Troubleshooting](https://docs.greywall.io/greyproxy/troubleshooting)

## Acknowledgments

Greyproxy is a fork of [**GOST** (GO Simple Tunnel)](https://github.com/go-gost/gost) by [ginuerzh](https://github.com/ginuerzh). GOST is an excellent and feature-rich tunnel and proxy toolkit written in Go, and its solid foundation made this project possible. We are grateful to ginuerzh and all GOST contributors for their work and for releasing it under the MIT license.

The core tunneling, protocol handling, and proxy infrastructure in Greyproxy originates from GOST v3. For documentation on the underlying proxy and tunnel capabilities, refer to the [GOST documentation](https://gost.run/en/).

## License

This project is licensed under the [MIT License](LICENSE), the same license as the original GOST project.

Copyright (c) 2026 The Greyproxy Authors. Original copyright (c) 2016 ginuerzh.
