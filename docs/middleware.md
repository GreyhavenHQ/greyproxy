# Middleware

Greyproxy supports external middleware services that can inspect, block, or rewrite HTTP requests and responses in real time. A middleware is a small program that receives structured JSON descriptions of requests and responses and replies with a decision: allow, deny, rewrite, passthrough, block. Greyproxy handles all the networking, TLS termination, and MITM certificate generation.

Two transports are supported, and you pick one per middleware:

- **Stdio** — greyproxy spawns your middleware as a child process and talks to it over stdin/stdout. No port, no separate terminal, greyproxy owns the lifecycle. **Recommended for local deployments.**
- **WebSocket** — greyproxy dials your middleware over a persistent WebSocket. Use this when the middleware runs as a shared service, on a different host, or in a language where stdio framing is awkward.

The wire protocol (hello exchange, message shapes, decision actions) is identical across both. The only difference is how messages are framed: WS frames for the network transport, newline-delimited JSON for stdio.

## Overview

```
 Client              Greyproxy                  Middleware           Upstream
+------+            +---------+                +----------+         +--------+
| App  | -- req --> | Proxy   | --- JSON ----> | Your     |         | API    |
|      |            |         | <-- decision - | Service  |         |        |
|      |            |         | ------------------ req -------->    |        |
|      | <-- resp - |         | <-- JSON ----- |          | <-resp- |        |
+------+            +---------+                +----------+         +--------+
                                   ^
                                   stdio (NDJSON) or WebSocket frames
```

The middleware never handles raw TCP or TLS. It gets ready-to-consume JSON and returns decisions.

## Quick start

### Stdio (simplest)

One command. Greyproxy spawns the middleware; no port to manage.

```bash
greyproxy serve --middleware-cmd 'uv run examples/middleware-passthrough-py/middleware.py'
```

### WebSocket

Start the middleware in one terminal, point greyproxy at it in another.

```bash
# Terminal 1
uv run examples/middleware-passthrough-py/middleware.py

# Terminal 2
greyproxy serve --middleware ws://localhost:9000/middleware
```

Either way: on startup greyproxy performs a capability handshake with the middleware and starts routing matching traffic through it.

## Examples

Seven example middlewares ship under `examples/`. Each is a single file and runs with `uv run middleware.py`. All of them use a small shared helper (`examples/_lib/greyproxy_middleware.py`) that auto-detects the transport, so the same middleware code runs under either stdio or WebSocket.

| Example | What it does | Hooks |
|---|---|---|
| `middleware-passthrough-py` | Logs and allows everything. Copy this as a starting point. | request + response |
| `middleware-command-stripper-py` | Strips dangerous shell commands (`rm -rf /`, `curl\|bash`, fork bombs, etc.) from LLM responses and replaces them with a warning marker. | response only |
| `middleware-pii-redactor-py` | Bidirectional PII redaction: replaces names, emails, SSNs, and phone numbers with placeholders in requests, then restores originals in responses. The upstream LLM never sees real PII. | request + response |
| `middleware-secret-scanner-py` | Blocks outbound requests that contain leaked secrets (AWS keys, API tokens, private keys, passwords). | request only |
| `middleware-cost-tracker-py` | Parses OpenAI/Anthropic response bodies for token usage, estimates cost, and logs cumulative spend per container to a JSONL file. Read-only, never blocks. | response only |
| `middleware-audit-log-py` | Writes every request/response to a structured JSONL audit trail with timestamps, containers, durations, and body sizes. Read-only, never blocks. | request + response |
| `middleware-rtk-compress-py` | Rewrites LLM request bodies to compress noisy `tool_result` output (diffs, JSON, logs) through [rtk](https://github.com/rtk-ai/rtk), saving context-window tokens. | request only |

All examples are intentionally simplified and are **not meant for production use**. See each file's docstring for specific limitations.

## Configuration

### CLI flags

Both flags are repeatable; the two can be mixed freely:

```bash
# One stdio child
greyproxy serve --middleware-cmd 'uv run examples/middleware-secret-scanner-py/middleware.py'

# One remote WebSocket middleware
greyproxy serve --middleware ws://remote-scanner.internal:9000/middleware

# Multiple middlewares cascade; declaration order wins
greyproxy serve \
  --middleware ws://internal-security.corp:9000/secret-scanner \
  --middleware-cmd 'uv run ./cost-tracker/middleware.py' \
  --middleware-cmd 'uv run ./audit-log/middleware.py'
```

Cascade order: CLI `--middleware` entries first, then CLI `--middleware-cmd` entries, then YAML entries. Each middleware sees the previous one's (possibly rewritten) output as its input; a `deny` or `block` decision short-circuits the chain.

- `--middleware ws://…` accepts `http://` and `https://` as aliases (converted to `ws://` and `wss://`).
- `--middleware-cmd '…'` takes a command string parsed with shell-like rules (quotes, backslash escapes) but **not** invoked through a shell. There's no variable expansion, no piping, no redirection. If you need those, spell them out: `--middleware-cmd 'sh -c "FOO=bar exec ./mw"'`.

### Config file (greyproxy.yml)

Each YAML entry specifies either `url:` (WebSocket) or `command:` (stdio), never both:

```yaml
greyproxy:
  middlewares:
    # Stdio: greyproxy spawns this process and owns its lifecycle.
    - command: ["uv", "run", "./middleware-secret-scanner-py/middleware.py"]
      name: "secret-scanner"
      timeout_ms: 10000
      on_disconnect: deny                # secure default, spelled out for clarity

    # WebSocket: middleware runs independently, greyproxy dials it.
    - url: "ws://cost-tracker.internal:9001/middleware"
      on_disconnect: allow               # observational middleware: don't block on failure
      timeout_ms: 500                    # local, fast: surface hangs quickly
      auth_header: "X-Secret: mysecret"  # sent on the WS upgrade request
```

`command:` is always a list of argv elements; no shell is invoked. If you need shell features, the first elements of the list should be `["sh", "-c", "..."]`.

`name:` on a stdio entry is a short identifier that shows up as the log prefix on the child's stderr output *before* the middleware has a chance to declare its own name in the hello exchange. Omit it and greyproxy uses the basename of the command (so `mw[uv]` etc).

`on_disconnect` is per-middleware: a disconnected middleware configured `allow` skips to the next step; one configured `deny` kills the request immediately.

The default is `deny` (secure-by-default). A middleware that is unreachable, times out, or crashes causes the request to be rejected (403) or the response to be blocked (502). The operator has to opt in to pass-through behaviour by setting `on_disconnect: allow` explicitly. This matters for policy middleware (secret scanners, PII redactors, security gates): if the gate isn't running, the request shouldn't leak through silently. Observation-only middleware (audit logs, cost trackers) should set `on_disconnect: allow` explicitly since their absence is not a policy violation.

## Protocol

### Connection lifecycle

On startup, greyproxy either dials the WebSocket URL (`ws` transport) or spawns the child process (`stdio` transport). Then:

1. Greyproxy sends a `hello` message with its protocol version.
2. The middleware responds with a `hello` declaring its supported version range, optional name, and the hooks it wants with filters.
3. The connection stays open. Greyproxy sends request/response messages; the middleware replies with decisions.

If the connection drops (the WS peer closes, or the stdio child exits), greyproxy reconnects with exponential backoff (100ms doubling up to a 2s cap) plus ±20% jitter. A connection that stayed up for at least 5 seconds before dropping is treated as "healthy", so the next disconnect restarts backoff at 100ms rather than inheriting the tail of the previous attempt. For stdio middlewares this means `greyproxy → uv → python3` is respawned as a fresh child; for WS middlewares it means a new dial. During the reconnect window the `on_disconnect` policy applies.

Stdio-specific: greyproxy puts the child in its own process group, so when greyproxy exits or needs to respawn the middleware, the whole subtree is killed (including grandchildren spawned by wrapper scripts like `uv run`). Ports and files the middleware had open are released immediately.

### Hello exchange

**Greyproxy sends:**
```json
{"type": "hello", "version": 1}
```

The `version` field is the protocol version the proxy currently speaks. Middlewares can ignore it and just declare their own supported range in the response.

**Middleware responds (within 5 seconds):**
```json
{
  "type": "hello",
  "name": "openai-pii-redactor",
  "min_version": 1,
  "max_version": 1,
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

`name` is optional but recommended. When the middleware takes a mutating action or emits tags, the Activity view shows the event badge labeled with this name (falling back to the middleware endpoint when `name` is absent). Keep it short — it's rendered inline in the activity rows.

#### Version negotiation

`min_version` and `max_version` declare the inclusive range of protocol versions the middleware supports. After the proxy receives the hello response it picks the highest integer in the overlap of `[min_version, max_version]` and `[1, ProxyMaxVersion]`. On success, the agreed version is logged and the connection proceeds. On no overlap, the connection is refused with an error naming both ranges so the operator can see exactly which side is lagging.

Omitting both fields is equivalent to declaring `min_version: 1, max_version: 1` — existing v1 middlewares keep working without changes as the proxy protocol evolves. New middlewares should set the range explicitly so that a future proxy bump can pick a higher version when both sides are ready.

The current proxy protocol version is **1**.

### Hook types

| Hook | When it fires |
|---|---|
| `http-request` | Before the request is forwarded upstream |
| `http-response` | After upstream responds, before the response reaches the client |

### Filters

Filters are evaluated inside greyproxy before anything is sent over the transport. Non-matching traffic has zero overhead (no JSON encoding, no message write).

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

The same policy applies when the transport is down during reconnect, during `timeout_ms`, on write failure, on marshal error, and when the incoming ctx is cancelled. In every case greyproxy logs a `fallback action=<x>` warning naming the reason so operators can distinguish "middleware allowed" from "middleware was down".

### Header denylist on `rewrite`

A middleware's `rewrite` decision may set or replace arbitrary response or request headers, with one exception: greyproxy refuses to apply `rewrite` decisions that attempt to set hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authorization`, `Transfer-Encoding`, `Upgrade`, `Te`, `Trailer`, `Proxy-Authenticate`) or credential/identity headers (`Authorization`, `Cookie`, `Set-Cookie`, `Host`). Those keys are stripped from the decision and logged; the rest of the rewrite is applied normally.

This is a defence against a compromised or buggy middleware silently escalating authentication (overriding `Authorization`) or rerouting requests (overriding `Host`). If you genuinely need to mutate credentials from a middleware, open an issue describing the use case; this is deliberately not a v1 feature.

### Unknown actions

If a middleware returns an `action` string that greyproxy does not recognise (typo, protocol drift), greyproxy treats it as `allow` for request hooks and `passthrough` for response hooks and logs a warning naming the middleware and the unknown action. Silent fallback to `allow` without a log would let one bad middleware bypass policy undetected; this way the operator sees it in logs.

## Writing a middleware

The supplied Python helper (`examples/_lib/greyproxy_middleware.py`) hides the transport choice from the author. Write two functions and a `run()` call:

```python
from greyproxy_middleware import run, allow, passthrough, decode_body

def handle_request(msg):
    body = decode_body(msg.get("body"))
    # ... inspect / decide ...
    return allow(msg["id"])

def handle_response(msg):
    return passthrough(msg["id"])

run(name="my-mw",
    handle_request=handle_request,
    handle_response=handle_response,
    max_body_bytes=1_048_576)
```

Launch it either way you like:

```bash
# Stdio: greyproxy owns the lifecycle
greyproxy serve --middleware-cmd 'uv run my-middleware/middleware.py'

# WebSocket: same code, standalone server
uv run my-middleware/middleware.py
greyproxy serve --middleware ws://localhost:9000/middleware
```

`run()` picks the transport based on the `GREYPROXY_TRANSPORT` env var that greyproxy sets when it spawns a child. If the var is absent, it starts a WebSocket server on `$GREYPROXY_WS_PORT` (default 9000).

The passthrough example is the best starting point — copy it as a template:

```bash
cp -r examples/middleware-passthrough-py my-middleware
# edit handle_request() / handle_response()
greyproxy serve --middleware-cmd "uv run $(pwd)/my-middleware/middleware.py"
```

### Other languages

Any language can implement either transport; the wire protocol is plain JSON:

- **Stdio:** read newline-delimited JSON from stdin, write newline-delimited JSON to stdout, route everything you want to log to stderr. Greyproxy sets `GREYPROXY_TRANSPORT=stdio` in the env so a multi-mode library can detect stdio framing.
- **WebSocket:** run any WS server, read JSON frames, write JSON frames. Any path is fine.

The key requirements either way:

1. Read the proxy's `hello` message, respond with your own `hello` declaring supported version range, hooks, and filters.
2. For each incoming `http-request` or `http-response` message, return a `decision` with the same `id`.
3. Respond within `timeout_ms` (default 10 s); the proxy waits synchronously.
4. In stdio mode: **never write to stdout except for protocol frames**. Logs must go to stderr.
