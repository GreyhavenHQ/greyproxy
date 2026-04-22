"""
greyproxy_middleware -- transport-agnostic helper for writing middlewares.

A middleware author writes two functions:

    def handle_request(msg) -> dict: ...
    def handle_response(msg) -> dict: ...

and calls run(...) at module scope. The helper picks the transport based on
how it was launched:

  - stdio   (greyproxy spawned us; GREYPROXY_TRANSPORT=stdio in env)
  - ws      (otherwise; GREYPROXY_WS_PORT or default 9000)

So the same handler code works whether the operator ran `uv run mw.py` and
pointed greyproxy at `ws://localhost:9000/middleware`, or ran
`greyproxy serve --middleware-cmd 'uv run mw.py'`. The author doesn't
care; the library picks.

Logging: in stdio mode, stdout is the protocol. All logs MUST go to
stderr. The library's _configure_logging() does that automatically, but
middleware code that uses print() or configures its own logger needs to
route to sys.stderr explicitly in stdio mode.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import sys
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Decision builders
# ---------------------------------------------------------------------------
# These are pure dict constructors. The wire format wants base64-encoded
# bodies; the helpers do that once so callers pass bytes and don't have
# to think about it.


def allow(rid: str, *, tags: Optional[dict] = None) -> dict:
    d: dict = {"type": "decision", "id": rid, "action": "allow"}
    if tags:
        d["tags"] = tags
    return d


def passthrough(rid: str, *, tags: Optional[dict] = None) -> dict:
    d: dict = {"type": "decision", "id": rid, "action": "passthrough"}
    if tags:
        d["tags"] = tags
    return d


def deny(rid: str, *, status: int = 403, body: bytes = b"Blocked",
         tags: Optional[dict] = None) -> dict:
    d: dict = {
        "type": "decision", "id": rid, "action": "deny",
        "status_code": status, "body": base64.b64encode(body).decode(),
    }
    if tags:
        d["tags"] = tags
    return d


def block(rid: str, *, status: int = 502, body: bytes = b"Blocked",
          tags: Optional[dict] = None) -> dict:
    d: dict = {
        "type": "decision", "id": rid, "action": "block",
        "status_code": status, "body": base64.b64encode(body).decode(),
    }
    if tags:
        d["tags"] = tags
    return d


def rewrite_request(rid: str, *, headers: Optional[dict] = None,
                    body: Optional[bytes] = None,
                    tags: Optional[dict] = None) -> dict:
    d: dict = {"type": "decision", "id": rid, "action": "rewrite"}
    if headers is not None:
        d["headers"] = headers
    if body is not None:
        d["body"] = base64.b64encode(body).decode()
    if tags:
        d["tags"] = tags
    return d


def rewrite_response(rid: str, *, status: Optional[int] = None,
                     headers: Optional[dict] = None,
                     body: Optional[bytes] = None,
                     tags: Optional[dict] = None) -> dict:
    d: dict = {"type": "decision", "id": rid, "action": "rewrite"}
    if status is not None:
        d["status_code"] = status
    if headers is not None:
        d["headers"] = headers
    if body is not None:
        d["body"] = base64.b64encode(body).decode()
    if tags:
        d["tags"] = tags
    return d


def decode_body(b64: Optional[str]) -> bytes:
    """Convenience: decode the base64 body from an incoming message.

    Returns b'' for both missing and null-in-JSON (the latter happens
    when greyproxy hit max_body_bytes).
    """
    return base64.b64decode(b64) if b64 else b""


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


Handler = Callable[[dict], dict]


def run(
    *,
    name: str = "",
    handle_request: Optional[Handler] = None,
    handle_response: Optional[Handler] = None,
    filters_request: Optional[dict] = None,
    filters_response: Optional[dict] = None,
    max_body_bytes: int = 1_048_576,
    min_version: int = 1,
    max_version: int = 1,
) -> None:
    """Start the middleware. Blocks until the transport closes.

    Pass only the handlers you need; omitted ones mean "don't declare
    that hook in hello".

    filters_request / filters_response mirror the protocol's HookFilter
    shape (host/path/method/content_type/container/tls/llm).
    """
    if handle_request is None and handle_response is None:
        raise ValueError("run: at least one of handle_request/handle_response is required")

    hello = {
        "type": "hello",
        "name": name,
        "min_version": min_version,
        "max_version": max_version,
        "hooks": [],
        "max_body_bytes": max_body_bytes,
    }
    if handle_request is not None:
        spec: dict = {"type": "http-request"}
        if filters_request:
            spec["filters"] = filters_request
        hello["hooks"].append(spec)
    if handle_response is not None:
        spec = {"type": "http-response"}
        if filters_response:
            spec["filters"] = filters_response
        hello["hooks"].append(spec)

    handlers: dict[str, Handler] = {}
    if handle_request is not None:
        handlers["http-request"] = handle_request
    if handle_response is not None:
        handlers["http-response"] = handle_response

    transport = os.environ.get("GREYPROXY_TRANSPORT", "ws")
    _configure_logging(transport, name)

    if transport == "stdio":
        _run_stdio(hello, handlers)
    else:
        port = int(os.environ.get("GREYPROXY_WS_PORT", "9000"))
        host = os.environ.get("GREYPROXY_WS_HOST", "0.0.0.0")
        asyncio.run(_run_ws(host, port, hello, handlers))


def _configure_logging(transport: str, name: str) -> None:
    """Route logs to stderr. In stdio mode this is critical: stdout is
    the wire protocol and any stray print() to it will corrupt frames."""
    handler = logging.StreamHandler(sys.stderr)
    prefix = f"[{name or 'middleware'}]"
    handler.setFormatter(logging.Formatter(
        f"%(asctime)s {prefix} %(levelname)s %(message)s"
    ))
    root = logging.getLogger()
    # Replace any previously-installed handlers so a middleware that
    # happened to configure its own before calling run() can't corrupt
    # stdout in stdio mode.
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(logging.INFO)


# --- stdio transport --------------------------------------------------------


def _run_stdio(hello: dict, handlers: dict[str, Handler]) -> None:
    """Simple synchronous NDJSON loop on stdin/stdout.

    Nothing async here on purpose: a middleware that needs concurrency
    can still ship a WS implementation separately; stdio is the "simple
    local child" mode and a plain blocking loop is easier to reason
    about and debug.
    """
    log = logging.getLogger("greyproxy.stdio")
    # Read proxy hello
    line = sys.stdin.readline()
    if not line:
        log.error("stdin closed before proxy hello")
        return
    try:
        proxy_hello = json.loads(line)
    except json.JSONDecodeError as e:
        log.error("proxy hello: invalid json: %s", e)
        return
    if proxy_hello.get("type") != "hello":
        log.error("expected hello, got: %s", proxy_hello.get("type"))
        return
    log.info("proxy hello: version=%s", proxy_hello.get("version"))

    # Send middleware hello
    sys.stdout.write(json.dumps(hello) + "\n")
    sys.stdout.flush()
    log.info("sent hello: %d hooks", len(hello["hooks"]))

    # Request/response loop
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log.warning("malformed frame, skipping: %s", e)
            continue
        handler = handlers.get(msg.get("type", ""))
        if handler is None:
            log.warning("unknown message type: %s", msg.get("type"))
            continue
        try:
            decision = handler(msg)
        except Exception:
            log.exception("handler raised for type=%s id=%s", msg.get("type"), msg.get("id"))
            # Fall back to allow/passthrough rather than crashing the
            # middleware: greyproxy will log the missing decision, but
            # at least the stream stays alive.
            decision = (passthrough(msg["id"]) if msg.get("type") == "http-response"
                        else allow(msg["id"]))
        sys.stdout.write(json.dumps(decision) + "\n")
        sys.stdout.flush()
    log.info("stdin closed, exiting")


# --- ws transport -----------------------------------------------------------


async def _run_ws(host: str, port: int, hello: dict, handlers: dict[str, Handler]) -> None:
    """WebSocket server with one handler per connection."""
    try:
        import websockets  # type: ignore
    except ImportError:
        print("greyproxy_middleware: websockets package is required for WS mode. "
              "Add it to your script dependencies, or run via --middleware-cmd "
              "to use stdio transport.", file=sys.stderr)
        raise

    log = logging.getLogger("greyproxy.ws")

    async def serve(websocket: Any) -> None:
        log.info("proxy connected from %s", websocket.remote_address)
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=5)
        except asyncio.TimeoutError:
            log.warning("proxy hello timeout")
            return
        proxy_hello = json.loads(raw)
        if proxy_hello.get("type") != "hello":
            log.error("expected hello, got: %s", proxy_hello.get("type"))
            return
        log.info("proxy hello: version=%s", proxy_hello.get("version"))
        await websocket.send(json.dumps(hello))
        log.info("sent hello: %d hooks", len(hello["hooks"]))

        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError as e:
                log.warning("malformed frame, skipping: %s", e)
                continue
            handler = handlers.get(msg.get("type", ""))
            if handler is None:
                log.warning("unknown message type: %s", msg.get("type"))
                continue
            try:
                decision = handler(msg)
            except Exception:
                log.exception("handler raised for type=%s id=%s", msg.get("type"), msg.get("id"))
                decision = (passthrough(msg["id"]) if msg.get("type") == "http-response"
                            else allow(msg["id"]))
            await websocket.send(json.dumps(decision))

    async with websockets.serve(serve, host, port):
        log.info("listening on ws://%s:%d/middleware", host, port)
        await asyncio.Future()
