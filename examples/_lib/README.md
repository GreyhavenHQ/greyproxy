# Python helper library

`greyproxy_middleware.py` is the shared helper used by the Python example middlewares. It hides the transport from the middleware author: the same `handle_request` / `handle_response` code runs under either stdio (greyproxy spawns the middleware as a child process) or WebSocket (greyproxy dials a standalone server).

## Writing a middleware

Three-line skeleton:

```python
from greyproxy_middleware import run, allow, passthrough

def handle_request(msg): return allow(msg["id"])
def handle_response(msg): return passthrough(msg["id"])

run(name="my-mw", handle_request=handle_request, handle_response=handle_response)
```

`run(...)` picks the transport based on the `GREYPROXY_TRANSPORT` env var. Greyproxy sets it to `stdio` when it spawns a child via `--middleware-cmd`; otherwise the library starts a WebSocket server on `$GREYPROXY_WS_PORT` (default 9000).

## Decision builders

| Builder | Action | When to use |
|---|---|---|
| `allow(id, tags=...)` | request passes through | default response from a request hook |
| `deny(id, status=403, body=..., tags=...)` | request is rejected | request hook: block this request |
| `rewrite_request(id, headers=..., body=..., tags=...)` | modified request is forwarded | request hook: transform the request |
| `passthrough(id, tags=...)` | response passes through | default response from a response hook |
| `block(id, status=502, body=..., tags=...)` | response is replaced | response hook: block the response |
| `rewrite_response(id, status=..., headers=..., body=..., tags=...)` | modified response is sent to client | response hook: transform the response |

`body` is `bytes`; the helpers base64-encode as required by the wire protocol. `tags` is a free-form dict shown in the Activity UI; it's always optional.

## stdio gotcha: stdout is the protocol

In stdio mode, anything written to stdout corrupts the protocol stream. The helper's `_configure_logging()` routes all log output to stderr automatically. If you write your own logging or use `print()`, make sure it goes to `sys.stderr`:

```python
import sys
print("debug info", file=sys.stderr)  # safe
print("debug info")                    # BREAKS THE PROTOCOL in stdio mode
```

WS mode doesn't have this problem; the library picks up either way.

## Error handling

A handler that raises is caught by the helper and falls back to `allow` (request) or `passthrough` (response) with the original id so the cascade doesn't stall. The exception is logged at ERROR level with a traceback. In production you probably want to surface the error yourself and return a deliberate `deny` / `block` instead.
