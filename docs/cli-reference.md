---
id: cli-reference
title: CLI Reference
---

# Greyproxy CLI Reference

## Synopsis

```
greyproxy <command> [flags]
```

Run `greyproxy --version` (or `greyproxy -V`) to print version information.

## Commands

### `greyproxy serve`

Start the proxy server in the foreground. The server starts all configured proxy services and the dashboard/API; press `Ctrl+C` to stop.

```bash
greyproxy serve
greyproxy serve -C greyproxy.yml
```

| Flag | Description |
|------|-------------|
| `-C <path>` | Path to a YAML config file. Defaults to the embedded default config. |
| `-L <service>` | Append a service definition inline (can be repeated). |
| `-F <node>` | Append a chain forwarder node inline (can be repeated). |
| `-D` | Enable debug logging. |
| `-DD` | Enable trace logging (more verbose than `-D`). |
| `-O <format>` | Dump the resolved config and exit. One of `yaml` or `json`. |
| `-metrics <addr>` | Expose Prometheus-style metrics on the given address. |
| `-silent-allow` | Enter silent allow-all mode at startup. Requests pass through without prompting until the process restarts. |
| `--host <ip>` | Default bind interface for listeners written as a bare port (e.g. `:43080`). IP literal only (hostnames are rejected). Defaults to `127.0.0.1`. Pass `--host 0.0.0.0` to bind every interface — the choice is logged with a warning at startup. |
| `-V` | Print version information and exit. |

### `greyproxy cert`

Manage the MITM CA certificate used for HTTPS interception. HTTPS inspection, LLM conversation tracking, header redaction, and credential substitution all require the CA to be trusted by the operating system.

```bash
greyproxy cert generate            # generate a new CA keypair
greyproxy cert install             # trust the CA in the OS trust store
greyproxy cert uninstall           # remove the CA from the OS trust store
greyproxy cert reload              # reload the running greyproxy with a new cert
greyproxy cert generate -f         # overwrite an existing keypair
greyproxy cert install -f          # force re-install
```

| Subcommand | Description |
|------------|-------------|
| `generate` | Generate a CA certificate and key under greyproxy's data directory. |
| `install` | Trust the generated CA in the OS trust store (requires sudo). |
| `uninstall` | Remove the CA from the OS trust store. |
| `reload` | Tell the running greyproxy instance to reload its CA certificate, with no restart. |

`greyproxy install` runs `cert generate` and `cert install` automatically when the certificate is missing, so most users never need to call these subcommands directly.

### `greyproxy install`

Install greyproxy as a persistent background service. This copies the binary to `~/.local/bin/greyproxy` (unless it is already managed by Homebrew or a symlink manager such as mise), registers a systemd user service on Linux or a launchd user agent on macOS, generates and trusts the CA certificate if needed, and starts the service.

```bash
greyproxy install
greyproxy install -f        # skip confirmation prompts
```

| Flag | Description |
|------|-------------|
| `-f`, `--force` | Skip interactive confirmation prompts. |

The dashboard is available at [http://localhost:43080](http://localhost:43080) once the service is running. The installed service binds to loopback only; to expose it on a network interface, edit the systemd unit (Linux) or launchd plist (macOS) to add `--host <ip>` to the `serve` command line.

### `greyproxy uninstall`

Stop greyproxy, remove the systemd/launchd registration, delete the binary from `~/.local/bin/` (unless it is a symlink), and optionally remove the CA certificate from the OS trust store.

```bash
greyproxy uninstall
greyproxy uninstall -f
```

| Flag | Description |
|------|-------------|
| `-f`, `--force` | Skip interactive confirmation prompts. |

### `greyproxy service`

Manage the installed greyproxy service without uninstalling it. This is a thin wrapper around the underlying OS service manager.

```bash
greyproxy service status
greyproxy service start
greyproxy service stop
greyproxy service restart
greyproxy service install -C /etc/greyproxy/greyproxy.yml
greyproxy service uninstall
```

| Action | Description |
|--------|-------------|
| `status` | Show whether the service is running. |
| `start` | Start the service. |
| `stop` | Stop the service. |
| `restart` | Restart the service. |
| `install` | Register the service with the OS. When used with `-C`, the path is embedded in the service arguments. |
| `uninstall` | Remove the service registration. |

Flags:

- `-C`, `--config <path>`: only used with `install`, baked into the service arguments.
- `--name <name>`: override the service name (defaults to `greyproxy`).

## Default Ports

| Service | Port | Protocol |
|---------|------|----------|
| Dashboard / API | `43080` | HTTP + WebSocket |
| HTTP Proxy | `43051` | TCP |
| SOCKS5 Proxy | `43052` | TCP |
| DNS Proxy | `43053` | UDP + TCP |

These can be changed in a custom config file passed with `-C`. See [Configuration](./configuration).

## Service File Locations

After `greyproxy install`:

| Platform | Service type | Location |
|----------|--------------|----------|
| Linux | systemd user unit | `~/.config/systemd/user/greyproxy.service` |
| macOS | launchd user agent | `~/Library/LaunchAgents/co.greyhaven.greyproxy.plist` |

You can inspect or modify these files manually if needed.

## Data Directory

Greyproxy stores its database, CA certificate, settings, and other state under an OS-specific data directory:

| Platform | Location |
|----------|----------|
| Linux | `~/.local/share/greyproxy/` |
| macOS | `~/Library/Application Support/greyproxy/` |

## Examples

```bash
# Start in foreground with the embedded default config
greyproxy serve

# Start with a custom config file and debug logging
greyproxy serve -C ~/my-greyproxy.yml -D

# Install as a service (starts automatically on login)
greyproxy install

# Generate and trust the CA certificate (only needed if install skipped it)
greyproxy cert generate
greyproxy cert install

# Check service status and tail logs
greyproxy service status
journalctl --user -u greyproxy -f          # Linux
tail -f ~/Library/Logs/greyproxy.log       # macOS
```
