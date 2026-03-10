# Research 002: greyproxy — HTTP Traffic Interception Architecture

## Executive Summary

Greyproxy (Go, based on gost) already implements the core mitmproxy-equivalent pipeline for HTTP traffic inspection: protocol sniffing, TLS MITM with dynamic cert generation, full HTTP/1.1 and HTTP/2 request/response parsing, WebSocket frame capture, and body recording. The gap is in product features (interactive editing, scripting, replay), not in the decoding infrastructure.

---

## 1. Traffic Flow Architecture

### Entry Points

Greyproxy accepts traffic via two proxy protocols, both feeding into the same sniffing/decoding pipeline:

```
                    +-- HTTP CONNECT --> Sniff --> HandleTLS / HandleHTTP
Client --> HTTP Proxy Handler
                    +-- Plain HTTP ----> handleProxy (RoundTrip)

Client --> SOCKS5 Handler --> CONNECT --> Sniff --> HandleTLS / HandleHTTP
```

### Plain HTTP (no CONNECT)

**File:** `internal/gostx/handler/http/handler.go` — `handleProxy()`

```
Client request --> http.ReadRequest()
  --> Record: method, URI, host, headers, body
  --> h.transport.RoundTrip(req) forwards to target
  --> Record: status code, response headers, body
  --> Write response back to client
  --> Loop for keep-alive
```

Uses Go's `http.Transport` as a standard HTTP client — handles connection pooling, redirects, etc.

### HTTPS via CONNECT

**File:** `internal/gostx/handler/http/handler.go` lines ~355-446

```
Client sends: CONNECT example.com:443 HTTP/1.1
  --> Handler responds: HTTP/1.1 200 Connection established
  --> If sniffing enabled:
      Peek first 5 bytes (sniff.go)
      --> 0x16 + TLS version? --> sniffer.HandleTLS()
      --> HTTP method prefix?  --> sniffer.HandleHTTP()
      --> Neither?             --> xnet.Pipe() (raw relay)
  --> If sniffing disabled:
      --> xnet.Pipe() (raw relay, no inspection)
```

### SOCKS5 CONNECT

**File:** `internal/gostx/handler/socks/v5/connect.go`

Same flow as HTTP CONNECT after the SOCKS5 handshake completes:
```
SOCKS5 negotiation --> dial target --> reply success --> Sniff --> HandleTLS / HandleHTTP / Pipe
```

---

## 2. Protocol Detection

**File:** `internal/gostx/internal/util/sniffing/sniff.go`

Peeks at the first 5 bytes (`bufio.Reader.Peek`) without consuming them:

```go
func Sniff(ctx context.Context, r *bufio.Reader) (proto string, err error) {
    hdr, _ := r.Peek(dissector.RecordHeaderLen)  // 5 bytes

    // TLS: first byte 0x16 (Handshake) + valid TLS version
    if hdr[0] == 0x16 && (version >= TLS1.0 && version <= TLS1.3) --> "tls"

    // HTTP: starts with GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD, CONNECT, TRACE, or "PRI *"
    if isHTTP(hdr) --> "http"

    // SSH: starts with "SSH-2"
    if hdr == "SSH-2" --> "ssh"
}
```

---

## 3. TLS MITM Engine

**File:** `internal/gostx/internal/util/sniffing/sniffer.go` — `HandleTLS()` (line 574) and `terminateTLS()` (line 676)

### Step 1: Parse ClientHello (passive)

```go
clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
```

Extracts from the unencrypted ClientHello:
- **ServerName** (SNI)
- **SupportedProtos** (ALPN — h2, http/1.1)
- **CipherSuites**
- **SupportedVersions**
- **SessionID**, **CompressionMethods**

Records raw ClientHello hex for forensic logging.

### Step 2: Decide MITM or passthrough

MITM is performed **only when**:
- CA certificate + private key are configured (`h.Certificate != nil && h.PrivateKey != nil`)
- Client advertises HTTP-compatible ALPN (`h2` or `http/1.1`)
- Host is not in the MITM bypass list

If MITM is skipped: forwards raw ClientHello to server, parses ServerHello passively, then does `xnet.Pipe()` for raw relay.

### Step 3: terminateTLS (the actual MITM)

```
1. Dial real server
2. tls.Client(cc, cfg) — TLS handshake with real server
   - Uses client's SNI, ALPN, cipher suites
3. Read negotiated parameters (cipher suite, protocol, version)
4. Generate forged certificate:
   - certPool.Get(serverName) — check cache
   - tls_util.GenerateCertificate(serverName, 7*24h, caCert, caKey) — create if not cached
   - certPool.Put(serverName, cert) — cache it
5. tls.Server(conn, cfg) — TLS handshake with client using forged cert
   - GetCertificate callback serves the forged cert
6. Call HandleHTTP(ctx, network, serverConn, ...) on the decrypted streams
   - dial function is overridden to return the already-established server TLS conn
```

### Certificate Caching

**File:** `internal/gostx/internal/util/tls/` (referenced as `tls_util`)

- `MemoryCertPool` — in-memory cert cache keyed by server name
- Certs are verified against the CA before reuse (checks expiry, DNS name match)
- Generated certs have 7-day validity

---

## 4. HTTP Request/Response Decoding

**File:** `internal/gostx/internal/util/sniffing/sniffer.go` — `HandleHTTP()` (line 121) and `httpRoundTrip()` (line 280)

### HandleHTTP — entry point

```go
br := bufio.NewReader(conn)
req, err := http.ReadRequest(br)  // Go stdlib HTTP parsing
```

Records:
- `Host`, `Proto`, `Scheme`, `Method`, `URI`
- `Request.Header` (cloned)
- `Request.ContentLength`
- Client IP (from X-Forwarded-For if present)

Detects HTTP/2 connection preface (`PRI * HTTP/2.0`) and branches to `serveH2()`.

### httpRoundTrip — full request/response cycle

```
1. Capture request body (up to configurable limit, default 64KB, max 1MB)
   - Wraps req.Body with xhttp.NewBody(req.Body, bodySize)
   - Tee-reads: body goes to both the target and the recorder

2. req.Write(cc) — forward raw request to target server

3. http.ReadResponse(br, req) — read response from target
   - Handles 100 Continue (loops until non-100)

4. Record response metadata:
   - StatusCode, Response.Header, ContentLength

5. Capture response body (same size-limited tee-read)

6. resp.Write(rw) — forward response back to client

7. Record everything via ro.Record(ctx, h.Recorder):
   - Duration, InputBytes, OutputBytes, Errors
```

### Keep-alive support

After the first round-trip, loops to read subsequent requests on the same connection:
```go
for {
    req, err := http.ReadRequest(br)
    // ... httpRoundTrip again
}
```

### HTTP/1.0 compat

- Handles `Connection: keep-alive` / `Connection: close` semantics
- Downgrades proto version in response to match request

---

## 5. HTTP/2 Support

**File:** `internal/gostx/internal/util/sniffing/sniffer.go` — `serveH2()` (line 228)

Uses Go's `x/net/http2` package:

```go
// Server side: accept HTTP/2 from client
(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
    Handler: &h2Handler{transport: tr, ...},
})

// Client side: forward to target via HTTP/2 transport
tr := &http2.Transport{
    DialTLSContext: func(...) { /* dial + TLS to real server */ },
}
resp, err := h.transport.RoundTrip(req)
```

The `h2Handler` implements `http.Handler`, so each HTTP/2 stream becomes a standard `ServeHTTP(w, r)` call with full request/response capture.

---

## 6. WebSocket Frame Capture

**File:** `internal/gostx/internal/util/sniffing/sniffer.go` — `sniffingWebsocketFrame()` (line 456)

When an HTTP upgrade to WebSocket is detected:

```
1. Forward the 101 Switching Protocols response
2. Spawn two goroutines:
   - Client -> Server: copyWebsocketFrame(cc, rw) — "client" direction
   - Server -> Client: copyWebsocketFrame(rw, cc) — "server" direction
3. Each goroutine:
   - Reads a WebSocket frame (header + payload)
   - Records: Fin, RSV bits, OpCode, Masked, MaskKey, PayloadLength, Payload body
   - Rate-limited recording (default 10 samples/sec, configurable)
   - Forwards the frame to the other side
```

---

## 7. TLS Dissector (Passive Inspection)

**Directory:** `internal/tlsdissector/`

This is used for **non-MITM mode** — when MITM is disabled or bypassed, greyproxy still extracts metadata from the TLS handshake:

| File | Purpose |
|------|---------|
| `dissector.go` | `ParseClientHello()` and `ParseServerHello()` — top-level parsers |
| `record.go` | TLS record layer parsing (type, version, payload) |
| `msg.go` | Handshake message parsing (ClientHello, ServerHello structures) |
| `extension.go` | TLS extension parsing (SNI, ALPN, SupportedVersions, etc.) |

**Supported extensions:**
- ServerName (0x00) — SNI
- SupportedGroups (0x0a)
- ECPointFormats (0x0b)
- SignatureAlgorithms (0x0d)
- ALPN (0x10)
- SessionTicket (0x23)
- SupportedVersions (0x2b)
- RenegotiationInfo (0xff01)

Even without MITM, greyproxy records: SNI, negotiated cipher suite, TLS version, ALPN protocol, raw ClientHello/ServerHello hex.

---

## 8. Bidirectional Relay (Raw Passthrough)

**File:** `internal/gostx/internal/net/pipe.go`

For non-HTTP traffic or when sniffing is disabled:

```go
func Pipe(ctx context.Context, rw1, rw2 io.ReadWriteCloser) error {
    // Two goroutines: rw1->rw2 and rw2->rw1
    // io.CopyBuffer with pooled buffers
    // TCP half-close support (CloseRead/CloseWrite)
    // 10-second half-close timeout
    // Context cancellation closes both sides
}
```

---

## 9. Recording Infrastructure

All decoded data flows into a `recorder.Recorder` via `HandlerRecorderObject`:

```go
type HandlerRecorderObject struct {
    // Connection metadata
    Service, Network, RemoteAddr, SrcAddr, DstAddr, Host, ClientIP string
    Time     time.Time
    Duration time.Duration
    InputBytes, OutputBytes uint64
    Err string

    // Protocol-specific
    TLS       *TLSRecorderObject       // SNI, ciphers, versions, raw hello hex
    HTTP      *HTTPRecorderObject      // method, URI, headers, body, status
    Websocket *WebsocketRecorderObject // frame headers, payload
}
```

---

## 10. Comparison with mitmproxy

### What greyproxy already does (equivalent to mitmproxy)

| Capability | mitmproxy | greyproxy |
|-----------|-----------|-----------|
| HTTP proxy mode | Yes | Yes |
| SOCKS5 proxy mode | Yes | Yes |
| TLS MITM (forged certs) | Yes (OpenSSL) | Yes (Go crypto/tls) |
| SNI extraction | Yes | Yes |
| Dynamic cert generation | Yes | Yes |
| Cert caching | Yes (by CN/SAN) | Yes (by server name, MemoryCertPool) |
| HTTP/1.1 parsing | Yes (h11 lib) | Yes (net/http stdlib) |
| HTTP/2 support | Yes (hyper-h2) | Yes (x/net/http2) |
| WebSocket capture | Yes | Yes (frame-level, rate-sampled) |
| Body capture | Yes | Yes (configurable size, default 64KB) |
| Header recording | Yes | Yes |
| Keep-alive | Yes | Yes |
| Non-MITM TLS metadata | Yes | Yes (ClientHello/ServerHello passive parse) |

### What mitmproxy has that greyproxy does NOT

| Feature | Difficulty to add |
|---------|------------------|
| Interactive flow editing (modify request/response in-flight) | Medium |
| Request replay | Easy |
| Addon/scripting system (Python scripts) | Medium-Hard |
| Transparent proxy mode (iptables/pf) | Medium (but unnecessary — greyproxy is an explicit proxy) |
| Content decompression (gzip/brotli) before recording | Easy |
| Flow search/filter UI | Easy (data already captured) |
| Composable protocol layer stack | Hard (architectural change) |

---

## 11. Upstream SOCKS5 Forwarding — Implementation Path

Greyproxy's architecture makes this easy because `dial` functions are already injectable:

```go
// HandleOptions already has:
type HandleOptions struct {
    dial    func(ctx context.Context, network, address string) (net.Conn, error)
    dialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)
}
```

Every outgoing connection goes through these dial functions:
- `HandleHTTP` line 189: `cc, err := dial(ctx, network, host)`
- `HandleTLS` line 619: `cc, err := dial(ctx, network, host)`
- `handleProxy` uses `h.transport.RoundTrip()` which can be configured with a custom `DialContext`

**To add SOCKS5 upstream:**

```go
import "golang.org/x/net/proxy"

dialer, _ := proxy.SOCKS5("tcp", "socks5-proxy:1080", nil, proxy.Direct)
// Wrap as the dial function passed through handler chain
```

**Estimated effort:** Small — the injection points already exist. Need:
1. Config option for upstream SOCKS5 address
2. SOCKS5-wrapping dial function
3. Pass it through the handler chain to HandleOptions

---

## 12. Key Files Reference

### Traffic Handling
| File | Purpose |
|------|---------|
| `internal/gostx/internal/util/sniffing/sniff.go` | Protocol detection (TLS/HTTP/SSH) from first 5 bytes |
| `internal/gostx/internal/util/sniffing/sniffer.go` | Core engine: HandleTLS, HandleHTTP, terminateTLS, serveH2, WebSocket |
| `internal/gostx/handler/http/handler.go` | HTTP proxy handler (CONNECT + plain HTTP + WebSocket upgrade) |
| `internal/gostx/handler/socks/v5/connect.go` | SOCKS5 CONNECT handler |
| `internal/gostx/handler/socks/v5/handler.go` | SOCKS5 protocol negotiation |
| `internal/tlsdissector/` | Passive TLS ClientHello/ServerHello parsing |
| `internal/gostx/internal/net/pipe.go` | Bidirectional TCP relay |

### Policy & Recording
| File | Purpose |
|------|---------|
| `internal/greyproxy/greyproxy.go` | Main service orchestration |
| `internal/greyproxy/models.go` | Rule, PendingRequest, RequestLog models |
| `internal/greyproxy/events.go` | Event bus (pub/sub for real-time UI) |
| `internal/greyproxy/conn_tracker.go` | Active connection tracking + rule-based cancellation |
| `internal/greyproxy/plugins/admission.go` | Policy admission control |
| `internal/greyproxy/db.go` | SQLite persistence |

### mitmproxy Equivalence Map
| mitmproxy file | greyproxy equivalent |
|----------------|---------------------|
| `proxy/layers/tls.py` | `sniffing/sniffer.go:HandleTLS + terminateTLS` |
| `proxy/layers/http/_http1.py` | `sniffing/sniffer.go:HandleHTTP + httpRoundTrip` |
| `proxy/layers/modes.py` (Socks5Proxy) | `handler/socks/v5/handler.go` |
| `certs.py` | `internal/gostx/internal/util/tls/` |
| `proxy/server.py` | `handler/http/handler.go` (connection lifecycle) |
| `platform/linux.py` | N/A (greyproxy is explicit proxy, not transparent) |
