# Middleware

Greyproxy supports an external middleware service that can inspect, block, or rewrite HTTP requests and responses in real time. The middleware connects over a persistent WebSocket and receives JSON messages for each intercepted request/response.

## Overview

```
 Client              Greyproxy                  Middleware           Upstream
+------+            +---------+                +----------+         +--------+
| App  | -- req --> | Proxy   | -- JSON/WS --> | Your     |         | API    |
|      |            |         | <-- decision - | Service  |         |        |
|      |            |         | -------------- req -----> |         |        |
|      | <-- resp - |         | <-- JSON/WS -- |          | <-resp- |        |
+------+            +---------+                +----------+         +--------+
```

The middleware never handles raw TCP or TLS. It receives structured JSON descriptions of requests/responses and returns decisions. Greyproxy handles all networking, TLS termination, and MITM cert generation.

## Quick start

1. Pick an example and start it (no install needed, uv handles dependencies):

```bash
cd examples/middleware-passthrough-py
uv run middleware.py
```

2. Start greyproxy with the `--middleware` flag:

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```

That is all that is needed. Greyproxy connects to the middleware on startup, performs a capability handshake, and starts routing matching traffic through it.

## Examples

Six example middleware are included under `examples/`. Each is a self-contained single file that runs with `uv run middleware.py`.

| Example | What it does | Hooks |
|---|---|---|
| `middleware-passthrough-py` | Logs and allows everything. Copy this as a starting point. | request + response |
| `middleware-command-stripper-py` | Strips dangerous shell commands (`rm -rf /`, `curl\|bash`, fork bombs, etc.) from LLM responses and replaces them with a warning marker. | response only |
| `middleware-pii-redactor-py` | Bidirectional PII redaction: replaces names, emails, SSNs, and phone numbers with placeholders in requests, then restores originals in responses. The upstream LLM never sees real PII. | request + response |
| `middleware-secret-scanner-py` | Blocks outbound requests that contain leaked secrets (AWS keys, API tokens, private keys, passwords). | request only |
| `middleware-cost-tracker-py` | Parses OpenAI/Anthropic response bodies for token usage, estimates cost, and logs cumulative spend per container to a JSONL file. Read-only, never blocks. | response only |
| `middleware-audit-log-py` | Writes every request/response to a structured JSONL audit trail with timestamps, containers, durations, and body sizes. Read-only, never blocks. | request + response |

All examples are intentionally simplified for illustration and are **not meant for production use**. See each file's docstring for specific limitations.

## Configuration

### CLI flag

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```

The flag accepts `http://` and `https://` as aliases (automatically converted to `ws://` and `wss://`).

### Config file (greyproxy.yml)

```yaml
greyproxy:
  middleware:
    url: "ws://localhost:9000/middleware"
    timeout_ms: 2000              # per-request timeout (default: 2000)
    on_disconnect: allow          # allow | deny (default: allow)
    auth_header: "X-Secret: mysecret"  # optional, sent as WS header
```

The CLI flag takes precedence over the config file.

## Protocol

### Connection lifecycle

Greyproxy initiates a WebSocket connection to the configured URL. On connect:

1. Greyproxy sends a `hello` message with its protocol version.
2. The middleware responds with a `hello` declaring which hooks it wants and optional filters.
3. The connection stays open. Greyproxy sends request/response messages; the middleware replies with decisions.

If the connection drops, greyproxy reconnects with exponential backoff (100ms to 10s cap). During reconnect, the `on_disconnect` policy applies.

### Hello exchange

**Greyproxy sends:**
```json
{"type": "hello", "version": 1}
```

**Middleware responds (within 5 seconds):**
```json
{
  "type": "hello",
  "hooks": [
    {
      "type": "http-request",
      "filters": {
        "host": ["*.openai.com"],
        "method": ["POST"],
        "content_type": ["application/json"]
      }
    },
    {
      "type": "http-response",
      "filters": {
        "host": ["*.openai.com"],
        "content_type": ["application/json"]
      }
    }
  ],
  "max_body_bytes": 1048576
}
```

### Hook types

| Hook | When it fires |
|---|---|
| `http-request` | Before the request is forwarded upstream |
| `http-response` | After upstream responds, before the response reaches the client |

### Filters

Filters are evaluated inside greyproxy before anything is sent over WebSocket. Non-matching traffic has zero overhead (no JSON encoding, no WS write).

| Filter | Matching | Example |
|---|---|---|
| `host` | Glob (`*` wildcards) | `*.openai.com` |
| `path` | Regex | `/v1/.*` |
| `method` | Exact, case-insensitive | `POST`, `PUT` |
| `content_type` | Glob | `application/json`, `text/*` |
| `container` | Glob | `my-app-*` |
| `tls` | Boolean | `true` (HTTPS only) |

Semantics:
- Within a field: **OR** (any match passes)
- Across fields: **AND** (all specified fields must match)
- Absent field: matches everything

### Request message

**Greyproxy sends:**
```json
{
  "type": "http-request",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "api.openai.com:443",
  "method": "POST",
  "uri": "/v1/chat/completions",
  "proto": "HTTP/1.1",
  "headers": {"Content-Type": ["application/json"]},
  "body": "<base64-encoded>",
  "container": "my-app",
  "tls": true
}
```

**Middleware responds:**
```json
{"type": "decision", "id": "...", "action": "allow"}
```
```json
{"type": "decision", "id": "...", "action": "deny",
 "status_code": 403, "body": "<base64>"}
```
```json
{"type": "decision", "id": "...", "action": "rewrite",
 "headers": {"X-Injected": ["1"]}, "body": "<base64-new-body>"}
```

### Response message

The response message includes the full original request so the middleware has context (e.g., "what prompt generated this response?").

**Greyproxy sends:**
```json
{
  "type": "http-response",
  "id": "...",
  "host": "api.openai.com:443",
  "method": "POST",
  "uri": "/v1/chat/completions",
  "status_code": 200,
  "request_headers": {"Content-Type": ["application/json"]},
  "request_body": "<base64>",
  "response_headers": {"Content-Type": ["application/json"]},
  "response_body": "<base64>",
  "container": "my-app",
  "duration_ms": 312
}
```

**Middleware responds:**
```json
{"type": "decision", "id": "...", "action": "passthrough"}
```
```json
{"type": "decision", "id": "...", "action": "block",
 "status_code": 502, "body": "<base64>"}
```
```json
{"type": "decision", "id": "...", "action": "rewrite",
 "status_code": 200, "headers": {"X-Filtered": ["1"]},
 "body": "<base64-new-body>"}
```

### Body handling

Bodies are base64-encoded in JSON. The `max_body_bytes` field in the hello response tells greyproxy the maximum body size the middleware wants to receive. Bodies larger than the limit are sent as `null`. Set to `0` or omit to receive everything.

### Timeout and disconnect

If the middleware does not respond within `timeout_ms` (default 2000), greyproxy applies the `on_disconnect` policy:

| Policy | Request hook | Response hook |
|---|---|---|
| `allow` (default) | Request is forwarded unchanged | Response is passed through unchanged |
| `deny` | Request is denied with 403 | Response is blocked with 502 |

The same policy applies when the WebSocket connection is down during reconnect.

## Writing a middleware

A middleware is any WebSocket server that speaks the protocol above. The passthrough example is the best starting point:

```bash
cp -r examples/middleware-passthrough-py my-middleware
cd my-middleware
# edit middleware.py -- change handle_request() and handle_response()
uv run middleware.py
```

The key requirements:

1. Listen for WebSocket connections (any path)
2. Read the proxy's `hello` message, respond with your own `hello` declaring hooks and filters
3. For each incoming `http-request` or `http-response` message, return a `decision` with the same `id`
4. Respond quickly; the proxy waits synchronously (the `timeout_ms` clock is ticking)

Each example provides helper functions (`allow`, `deny`, `rewrite_request`, `passthrough`, `block`, `rewrite_response`) so you only need to write the decision logic. The WebSocket boilerplate at the bottom of the file handles the protocol for you.

Any language with a WebSocket library works. The protocol is plain JSON over a persistent connection.
