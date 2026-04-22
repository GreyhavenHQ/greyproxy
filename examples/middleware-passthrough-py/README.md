# Passthrough Middleware

A minimal skeleton that logs every request and response, then allows everything through unchanged. Reference implementation for the transport-agnostic pattern: the same `handle_request` / `handle_response` code runs under either stdio or WebSocket, picked at launch time.

> **Not for production use.** This example has no error handling, authentication, TLS, or other safeguards.

## What it does

- Hooks both `http-request` and `http-response` (no filters, receives everything)
- Logs method, host, URI, body size, container name, status code, and duration
- Always returns `allow` for requests and `passthrough` for responses

## Run

### Stdio (recommended for local policy gates)

Greyproxy spawns the middleware and owns its lifecycle. No port, no separate terminal:

```bash
greyproxy serve --middleware-cmd 'uv run examples/middleware-passthrough-py/middleware.py'
```

### WebSocket (for shared or remote middlewares)

Start the middleware in one terminal:

```bash
uv run examples/middleware-passthrough-py/middleware.py
```

Point greyproxy at it in another:

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```

The middleware code is identical between modes. The helper in `examples/_lib/greyproxy_middleware.py` picks transport based on the `GREYPROXY_TRANSPORT` env var that greyproxy sets when it spawns a child.

## Use as a template

```bash
cp -r examples/middleware-passthrough-py my-middleware
cd my-middleware
# edit handle_request() and handle_response() in middleware.py
greyproxy serve --middleware-cmd "uv run $(pwd)/middleware.py"
```

Helper functions (`allow`, `deny`, `rewrite_request`, `passthrough`, `block`, `rewrite_response`, `decode_body`) are importable from the shared helper so you only write decision logic.
