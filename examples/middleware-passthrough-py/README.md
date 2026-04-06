# Passthrough Middleware

A minimal skeleton that logs every request and response, then allows everything through unchanged. Use this as a starting point for your own middleware.

> **Not for production use.** This example has no error handling, authentication, TLS, or other safeguards.

## What it does

- Hooks both `http-request` and `http-response` (no filters, receives everything)
- Logs method, host, URI, body size, container name, status code, and duration
- Always returns `allow` for requests and `passthrough` for responses

## Run

```bash
uv run middleware.py
```

Then in another terminal:

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```

## Use as a template

```bash
cp -r examples/middleware-passthrough-py my-middleware
cd my-middleware
# edit handle_request() and handle_response() in middleware.py
uv run middleware.py
```

Helper functions (`allow`, `deny`, `rewrite_request`, `passthrough`, `block`, `rewrite_response`) are included so you only need to write the decision logic.
