# Research 001: mitmproxy Traffic Capture & Decoding

## 1. Traffic Capture: The Underlying Principle

### macOS — pf (Packet Filter)

**How it works:**

1. macOS's **pf firewall** is configured with `rdr` rules to redirect traffic (e.g., ports 80/443) to mitmproxy's listening port (8080):
   ```
   rdr pass on en0 inet proto tcp to any port {80, 443} -> 127.0.0.1 port 8080
   ```
2. When a redirected connection arrives, mitmproxy needs to know the **original destination** (since pf rewrote it). It does this by shelling out to `sudo /sbin/pfctl -s state` and **parsing the pf state table** to find the original destination IP:port.

**Key files:**

- `mitmproxy/platform/osx.py` — calls `pfctl -s state`
- `mitmproxy/platform/pf.py` — parses the state table output, looks for `ESTABLISHED:ESTABLISHED` lines, extracts original dst from the connection tuple

**Limitation:** pf's `rdr` rules only apply to **inbound** traffic on an interface, so you can't transparently intercept traffic originating from the mitmproxy machine itself without extra `route-to` workarounds.

### Linux — iptables REDIRECT + `SO_ORIGINAL_DST`

**How it works:**

1. **iptables** `REDIRECT` rules are set up in the `nat` table:
   ```bash
   iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
   iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
   ```
2. When a redirected connection arrives, mitmproxy recovers the original destination using the **`SO_ORIGINAL_DST` socket option** (constant `80`). This is a kernel-level `getsockopt()` call — no subprocess needed, much cleaner than macOS.

**Key file:**

- `mitmproxy/platform/linux.py` — calls `socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)` and unpacks the struct to get the original IP:port

**Note:** mitmproxy does **not** use `TPROXY` or `nftables` — only classic iptables `REDIRECT`.

### Common Abstraction

`mitmproxy/platform/__init__.py` detects the OS and exposes a unified `original_addr(socket)` function. In `mitmproxy/proxy/mode_servers.py` (lines ~197-209), when a transparent mode connection arrives:

```python
original_dst = platform.original_addr(s)
handler.layer.context.server.address = original_dst
```

### Modern Alternatives (both platforms)

The codebase includes newer capture methods that avoid manual iptables/pf setup:

- **LocalMode** — uses Rust-based `mitmproxy_rs.local.LocalRedirector` for OS-level redirection
- **TunMode** — creates a virtual TUN interface (`utun` on macOS)
- **WireGuardMode** — WireGuard-based tunnel

---

## 2. Traffic Decoding Pipeline

Once a connection is captured, the processing is **layer-based** (generator-driven async):

```
Raw Socket Bytes
    |
    v
ConnectionHandler (server.py) -- reads chunks, emits DataReceived events
    |
    v
Mode Layer (TransparentProxy / Socks5Proxy / RegularProxy)
    |  -- determines original destination
    v
NextLayer -- protocol detection (is it TLS? HTTP? raw TCP?)
    |
    +---> TLSLayer (tls.py)
    |      - Parses ClientHello -> extracts SNI
    |      - Connects to real server over TLS
    |      - Generates a forged certificate signed by mitmproxy's CA
    |      - Decrypts client<->proxy, re-encrypts proxy<->server
    |      |
    |      v
    |   HTTP Layer (http/__init__.py, _http1.py)
    |      - Parses HTTP/1.1 using h11 library (or HTTP/2 via hyper-h2)
    |      - Emits RequestHeaders, RequestData, ResponseHeaders, etc.
    |      - Constructs HTTPFlow objects
    |      |
    |      v
    |   Addon Hooks (request, response, etc.)
    |      - Scripts/addons can inspect, modify, or block flows
    |
    +---> TCP Layer (tcp.py) -- raw TCP passthrough for non-HTTP
```

### Certificate MITM Mechanics

Key files: `certs.py` + `addons/tlsconfig.py`

- On first run, mitmproxy creates a CA in `~/.mitmproxy/mitmproxy-ca.pem`
- For each intercepted TLS connection, it dynamically generates a certificate with matching CN/SANs, signed by this CA
- If the client trusts mitmproxy's CA, TLS interception is seamless

### Event and Command Architecture

The proxy uses a generator-based blocking model:

**Events** (data flowing from IO to layers):
- `Start` — connection initialization
- `DataReceived(connection, bytes)` — raw data from socket
- `ConnectionClosed` — remote closed connection
- `CommandCompleted` — reply to a blocking command

**Commands** (instructions flowing from layers to server):
- `SendData(connection, bytes)` — send bytes on connection
- `OpenConnection(server)` — establish server connection (blocking)
- `CloseConnection(connection)` — close connection
- `StartHook` — execute addon hook (blocking)

Layers use Python generators with `yield` for blocking operations. When a layer yields a blocking command, execution pauses. Events are buffered until `CommandCompleted` arrives. Execution resumes from the yield point with the reply value.

---

## 3. SOCKS5 Support

### mitmproxy AS a SOCKS5 proxy: Fully supported

```bash
mitmproxy --mode socks5          # default port 1080
mitmproxy --mode socks5@9050     # custom port
```

**Implementation:** `mitmproxy/proxy/layers/modes.py` lines 99-303 (`Socks5Proxy` class)

- Full SOCKSv5 handshake: greeting -> optional auth -> CONNECT
- Supports no-auth and username/password auth (RFC 1929)
- IPv4, IPv6, and domain name address types
- After CONNECT, traffic flows through the same TLS -> HTTP decoding pipeline

This means any SOCKS5-aware application can be pointed at mitmproxy and it will intercept+decode the traffic.

### Forwarding decoded traffic TO a SOCKS5 upstream: NOT supported

The `upstream:` mode only accepts HTTP/HTTPS schemes:

```bash
mitmproxy --mode upstream:http://proxy:8080   # works
mitmproxy --mode upstream:socks5://proxy:1080  # NOT supported
```

The `ServerSpec` type (`mitmproxy/net/server_spec.py`) only allows: `http`, `https`, `http3`, `tls`, `dtls`, `tcp`, `udp`, `dns`, `quic`.

---

## 4. Options for Redirecting to a SOCKS5 Proxy

Since mitmproxy doesn't natively support SOCKS5 upstream, here are the practical options:

### Option A: Chain mitmproxy -> SOCKS5 at the OS/network level

Run mitmproxy normally (any mode) and route its **outgoing** traffic through a SOCKS5 proxy:

```bash
proxychains mitmproxy --mode socks5
```

Or use iptables `REDIRECT` rules targeting mitmproxy's UID to a local `redsocks` instance that forwards to SOCKS5.

### Option B: Write an addon script

Use mitmproxy's addon API to manually tunnel server connections through SOCKS5. Hook into the connection lifecycle and wrap the outgoing socket with a SOCKS5 handshake before mitmproxy does its TLS/HTTP work. Non-trivial but possible.

### Option C: Use mitmproxy as SOCKS5 proxy + external SOCKS5 chaining

```
App -> mitmproxy (socks5@1080, intercepts/decodes) -> redsocks/proxychains -> your SOCKS5 proxy -> internet
```

**Option A with `proxychains`** is the simplest path — zero code changes, full decoded traffic inspection while routing everything through a SOCKS5 proxy.

---

## 5. Key Files Reference

| File | Purpose |
|------|---------|
| `mitmproxy/platform/__init__.py` | Platform detection, unified `original_addr()` |
| `mitmproxy/platform/linux.py` | `SO_ORIGINAL_DST` socket option retrieval |
| `mitmproxy/platform/osx.py` | `pfctl -s state` subprocess call |
| `mitmproxy/platform/pf.py` | pf state table parsing |
| `mitmproxy/proxy/server.py` | Main async event loop, connection management |
| `mitmproxy/proxy/layer.py` | Base layer architecture (generator-based) |
| `mitmproxy/proxy/mode_specs.py` | Proxy mode definitions (Transparent, Socks5, etc.) |
| `mitmproxy/proxy/mode_servers.py` | Mode-specific server instances, `original_addr` call site |
| `mitmproxy/proxy/layers/tls.py` | TLS encryption/decryption layer |
| `mitmproxy/proxy/layers/modes.py` | Socks5Proxy, TransparentProxy implementations |
| `mitmproxy/proxy/layers/http/__init__.py` | HTTP parsing orchestration |
| `mitmproxy/proxy/layers/http/_http1.py` | HTTP/1 state machine (h11-based) |
| `mitmproxy/proxy/layers/tcp.py` | TCP passthrough layer |
| `mitmproxy/addons/tlsconfig.py` | TLS setup and certificate generation |
| `mitmproxy/certs.py` | Certificate store and CA management |
| `mitmproxy/net/server_spec.py` | Upstream proxy scheme definitions |
| `docs/src/content/howto/transparent.md` | Transparent proxy setup docs |
