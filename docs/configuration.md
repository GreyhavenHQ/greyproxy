---
id: configuration
title: Configuration
---

# Greyproxy Configuration

Greyproxy ships with a sensible default configuration embedded in the binary. To customize, pass a YAML config file with `-C`:

```bash
greyproxy serve -C greyproxy.yml
```

The config format is inherited from [GOST v3](https://gost.run/en/); greyproxy adds its own top-level `greyproxy` block on top for management settings.

## Example Configuration

```yaml
# Default bind interface for any listener written as a bare port (":43080").
# Loopback by default so the proxy and dashboard aren't reachable from other
# machines. See "Bind Interface" below for details.
host: 127.0.0.1

log:
  level: info
  format: json
  output: stdout

# Management UI, REST API, and dashboard.
greyproxy:
  addr: ":43080"
  pathPrefix: /
  auther: auther-0
  admission: admission-0
  bypass: bypass-0
  resolver: resolver-0
  notifications:
    enabled: true
  docker:
    enabled: false
    socket: /var/run/docker.sock
    cacheTTL: 30s

services:
  - name: http-proxy
    addr: ":43051"
    handler:
      type: http
      auther: auther-0
      metadata:
        sniffing: true
        sniffing.websocket: true
    listener:
      type: tcp
    admission: admission-0
    bypass: bypass-0
    resolver: resolver-0

  - name: socks5-proxy
    addr: ":43052"
    handler:
      type: socks5
      auther: auther-0
      metadata:
        sniffing: true
        sniffing.websocket: true
    listener:
      type: tcp
    admission: admission-0
    bypass: bypass-0
    resolver: resolver-0

  - name: dns-proxy-udp
    addr: ":43053"
    handler:
      type: dns
    listener:
      type: dns
      metadata:
        mode: udp
    resolver: resolver-0

  - name: dns-proxy-tcp
    addr: ":43053"
    handler:
      type: dns
    listener:
      type: tcp
    resolver: resolver-0
```

## Bind Interface

By default greyproxy binds **only to the loopback interface** (`127.0.0.1`).
Any listener whose address is a bare port (`":43080"`, `"43080"`) is rewritten
to `127.0.0.1:<port>` at startup. Addresses that already carry an explicit
host (`"0.0.0.0:43080"`, `"192.168.1.10:43080"`, `"[::1]:43080"`) are left
alone.

Override the default at the top of the config file:

```yaml
host: 0.0.0.0   # bind to every interface
```

Or pass `--host <ip>` to `greyproxy serve` (IP literal only; hostnames are
rejected). The CLI flag wins over the YAML field, which wins over the
built-in `127.0.0.1` default.

When the resolved host is unspecified (`0.0.0.0` or `::`), greyproxy logs a
warning at startup so the operator can confirm the choice was deliberate.

## The `greyproxy` Block

| Field | Type | Description |
|-------|------|-------------|
| `addr` | string | Address for the dashboard and REST API (default `:43080`). |
| `pathPrefix` | string | Optional path prefix for the dashboard (useful behind a reverse proxy). |
| `db` | string | Path to the SQLite database. Defaults to `greyproxy.db` in the data directory. |
| `auther` / `admission` / `bypass` / `resolver` | string | Names of the GOST plugins greyproxy should attach its auther, admission, bypass, and resolver implementations to. |
| `notifications.enabled` | bool | Whether the proxy emits OS desktop notifications for pending requests. Can be overridden at runtime via the settings API. |
| `docker.enabled` | bool | When true, greyproxy queries the Docker or Podman socket to resolve source IPs to container names in the activity log and rule matcher. |
| `docker.socket` | string | Path to the Docker/Podman socket. Defaults to `/var/run/docker.sock`. |
| `docker.cacheTTL` | duration | How long resolved container names are cached. Go duration syntax (for example `30s`, `1m`). |

## Default Ports

| Service       | Port    | Description |
|---------------|---------|-------------|
| Dashboard/API | `43080` | Web UI, REST API, and WebSocket |
| HTTP Proxy    | `43051` | HTTP/HTTPS proxy (MITM capable) |
| SOCKS5 Proxy  | `43052` | SOCKS5 proxy, used by greywall |
| DNS Proxy     | `43053` | DNS proxy and cache (UDP and TCP) |

## DNS Upstream

Greyproxy auto-detects the system DNS resolver at startup (`/etc/resolv.conf` on Linux and macOS, registry on Windows) and injects it as the forwarder for the DNS proxy. If detection fails, it falls back to `1.1.1.1:53`. To pin a specific upstream, add a `forwarder` block to the DNS service:

```yaml
- name: dns-proxy-udp
  addr: ":43053"
  handler:
    type: dns
  listener:
    type: dns
    metadata:
      mode: udp
  resolver: resolver-0
  forwarder:
    nodes:
      - name: dns-upstream
        addr: 9.9.9.9:53
```

The DNS cache is persisted to SQLite so that resolutions survive restarts.

## Runtime Settings

Some settings are not part of the YAML file and are managed at runtime from the dashboard or via `PUT /api/settings`:

| Setting | Description |
|---------|-------------|
| `theme` | UI theme for the dashboard. |
| `notificationsEnabled` | Overrides `greyproxy.notifications.enabled`. |
| `mitmEnabled` | Whether HTTPS interception is active. |
| `conversationsEnabled` | Whether the LLM conversation assembler is running. |
| `redactedHeaders` | Extra header patterns to redact in stored transactions. See [Header Redaction](./header-redaction). |

Runtime settings are stored in `settings.json` inside greyproxy's data directory (`~/.local/share/greyproxy/` on Linux, `~/Library/Application Support/greyproxy/` on macOS).

## Data Directory

Greyproxy keeps its SQLite database, CA certificate, runtime settings, and encryption key under a single OS-specific data directory:

| Platform | Location |
|----------|----------|
| Linux | `~/.local/share/greyproxy/` |
| macOS | `~/Library/Application Support/greyproxy/` |

Typical files inside that directory:

- `greyproxy.db`: main SQLite database (rules, pending, logs, transactions, conversations, DNS cache).
- `ca-cert.pem` and `ca-key.pem`: MITM certificate authority.
- `settings.json`: runtime settings overrides.
- `session.key`: per-installation encryption key used for global credentials.

## Full Configuration Reference

See [`greyproxy.yml`](https://github.com/GreyhavenHQ/greyproxy/blob/main/greyproxy.yml) in the repository for the complete annotated example. For the underlying service, listener, handler, and chain options, refer to the [GOST documentation](https://gost.run/en/); greyproxy is built on GOST v3.
