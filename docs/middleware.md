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

The flag is repeatable and middlewares cascade in declaration order. Each middleware sees the previous one's (possibly rewritten) output as its input; `deny`/`block` short-circuits the chain.

```bash
greyproxy serve \
  --middleware ws://localhost:9000/secret-scanner \
  --middleware ws://localhost:9001/cost-tracker
```

The flag accepts `http://` and `https://` as aliases (automatically converted to `ws://` and `wss://`).

### Config file (greyproxy.yml)

```yaml
greyproxy:
  middlewares:
    - url: "ws://localhost:9000/secret-scanner"
      timeout_ms: 10000                  # per-request timeout (default: 10000)
      on_disconnect: deny                # allow | deny (default: deny)
      auth_header: "X-Secret: mysecret"  # optional, sent as WS header
    - url: "ws://localhost:9001/cost-tracker"
      on_disconnect: allow               # observational middleware: don't block on failure
      timeout_ms: 500                    # local, fast: surface hangs quickly
```

CLI entries come first in the cascade, then YAML entries. `on_disconnect` is per-middleware: a disconnected middleware configured `allow` skips to the next step; one configured `deny` kills the request immediately.

The default is `deny` (secure-by-default). A middleware that is unreachable, times out, or crashes causes the request to be rejected (403) or the response to be blocked (502); the operator has to opt in to pass-through behaviour by setting `on_disconnect: allow` explicitly. This matters for policy middleware (secret scanners, PII redactors, security gates): if the gate isn't running, the request shouldn't leak through silently. Observation-only middleware (audit logs, cost trackers) should set `on_disconnect: allow` explicitly since their absence is not a policy violation.

## Protocol

### Connection lifecycle

Greyproxy initiates a WebSocket connection to the configured URL. On connect:

1. Greyproxy sends a `hello` message with its protocol version.
2. The middleware responds with a `hello` declaring which hooks it wants and optional filters.
3. The connection stays open. Greyproxy sends request/response messages; the middleware replies with decisions.

If the connection drops, greyproxy reconnects with exponential backoff (100ms doubling up to a 2s cap) plus ±20% jitter. A connection that stayed up for at least 5 seconds before dropping is treated as "healthy", so the next disconnect restarts backoff at 100ms rather than inheriting the tail of the previous attempt. In practice, a middleware restart recovers within a few hundred milliseconds. During reconnect the `on_disconnect` policy applies.

### Hello exchange

**Greyproxy sends:**
```json
{"type": "hello", "version": 1}
```

**Middleware responds (within 5 seconds):**
```json
{
  "type": "hello",
  "name": "openai-pii-redactor",
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

`name` is optional but recommended. When the middleware takes a mutating action or emits tags, the Activity view shows the event badge labeled with this name (falling back to the middleware URL when `name` is absent). Keep it short — it's rendered inline in the activity rows.

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
| `llm` | Boolean | `true` (LLM traffic only), `false` (non-LLM only) |

Semantics:
- Within a field: **OR** (any match passes)
- Across fields: **AND** (all specified fields must match)
- Absent field: matches everything

#### The `llm` filter

Greyproxy ships with a built-in mapping from host/method/path to LLM decoders (Anthropic, OpenAI, Google AI, OpenRouter, plus any user-defined rules). The `llm` filter lets a middleware piggyback on that mapping instead of duplicating it:

```json
{
  "type": "hello",
  "hooks": [
    { "type": "http-request",  "filters": { "llm": true } },
    { "type": "http-response", "filters": { "llm": true } }
  ]
}
```

With this hello the middleware receives every request greyproxy currently considers LLM traffic, including user-defined providers added later at runtime. Adding a new provider rule in the UI takes effect on the very next request with no middleware restart. Disabling a rule immediately stops matching requests from being forwarded, so `llm: true` always means "whatever greyproxy currently dissects as LLM", never a stale snapshot.

`llm: false` is the inverse: useful for "audit everything *except* LLM calls". Omit the field entirely to disable LLM-based gating.

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

### Timeouts

There are three distinct timeouts in the protocol:

| Timeout | What it covers | Default | Configurable |
|---|---|---|---|
| Hello response | Middleware must emit its hello (hooks + filters) within this window after greyproxy sends the proxy hello | 5 s | No (fixed) |
| Per-message | Middleware must reply to a `http-request` or `http-response` with a `decision` within this window | 10 s | `timeout_ms` per middleware |
| Reconnect backoff | Delay before retrying after a dropped connection | 100 ms → 2 s with ±20% jitter | No (fixed) |

The 10 s default is deliberately generous: real middlewares often call out to an LLM or a slow scanner to compute their decision. Operators whose middleware is purely local (regex scan, static allowlist) should lower `timeout_ms` in config to surface hangs faster. A middleware that blows the deadline is treated exactly like a disconnect and the `on_disconnect` policy fires.

### Disconnect handling

If the middleware does not respond within `timeout_ms`, greyproxy applies the `on_disconnect` policy:

| Policy | Request hook | Response hook |
|---|---|---|
| `deny` (default) | Request is denied with 403 | Response is blocked with 502 |
| `allow` | Request is forwarded unchanged | Response is passed through unchanged |

The same policy applies when the WebSocket connection is down during reconnect, during `timeout_ms`, on write failure, on marshal error, and when the incoming ctx is cancelled. In every case greyproxy logs a `fallback action=<x>` warning naming the reason so operators can distinguish "middleware allowed" from "middleware was down".

### Header denylist on `rewrite`

A middleware's `rewrite` decision may set or replace arbitrary response or request headers, with one exception: greyproxy refuses to apply `rewrite` decisions that attempt to set hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authorization`, `Transfer-Encoding`, `Upgrade`, `Te`, `Trailer`, `Proxy-Authenticate`) or credential/identity headers (`Authorization`, `Cookie`, `Set-Cookie`, `Host`). Those keys are stripped from the decision and logged; the rest of the rewrite is applied normally.

This is a defence against a compromised or buggy middleware silently escalating authentication (overriding `Authorization`) or rerouting requests (overriding `Host`). If you genuinely need to mutate credentials from a middleware, open an issue describing the use case; this is deliberately not a v1 feature.

### Unknown actions

If a middleware returns an `action` string that greyproxy does not recognise (typo, protocol drift), greyproxy treats it as `allow` for request hooks and `passthrough` for response hooks and logs a warning naming the middleware and the unknown action. Silent fallback to `allow` without a log would let one bad middleware bypass policy undetected; this way the operator sees it in logs.

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
