# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Passthrough middleware -- a minimal skeleton that allows everything through.

Copy this file as a starting point for your own middleware. The two functions
you care about are handle_request() and handle_response(). Everything below
the "WebSocket server" separator handles the protocol for you.

WARNING: This is an example only and is NOT meant for production use.
It is intentionally simplified and lacks error handling, authentication,
TLS, and other safeguards required in a real deployment.

Usage:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""

import asyncio
import base64
import json
import logging

import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("middleware")

HOST = "0.0.0.0"
PORT = 9000

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HELLO_RESPONSE = {
    "type": "hello",
    "hooks": [
        {"type": "http-request"},
        {"type": "http-response"},
    ],
    "max_body_bytes": 1_048_576,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def decode_body(b64: str | None) -> bytes:
    return base64.b64decode(b64) if b64 else b""


def allow(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "allow"}


def deny(rid: str, status: int = 403, body: str = "Blocked") -> dict:
    return {"type": "decision", "id": rid, "action": "deny",
            "status_code": status, "body": base64.b64encode(body.encode()).decode()}


def rewrite_request(rid: str, *, headers: dict | None = None, body: bytes | None = None) -> dict:
    d: dict = {"type": "decision", "id": rid, "action": "rewrite"}
    if headers is not None:
        d["headers"] = headers
    if body is not None:
        d["body"] = base64.b64encode(body).decode()
    return d


def passthrough(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "passthrough"}


def block(rid: str, status: int = 502, body: str = "Blocked") -> dict:
    return {"type": "decision", "id": rid, "action": "block",
            "status_code": status, "body": base64.b64encode(body.encode()).decode()}


def rewrite_response(rid: str, *, status: int | None = None,
                     headers: dict | None = None, body: bytes | None = None) -> dict:
    d: dict = {"type": "decision", "id": rid, "action": "rewrite"}
    if status is not None:
        d["status_code"] = status
    if headers is not None:
        d["headers"] = headers
    if body is not None:
        d["body"] = base64.b64encode(body).decode()
    return d


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def handle_request(msg: dict) -> dict:
    body = decode_body(msg.get("body"))
    log.info("request  %s %s%s (%d bytes) container=%s",
             msg["method"], msg["host"], msg["uri"], len(body),
             msg.get("container", ""))
    return allow(msg["id"])


def handle_response(msg: dict) -> dict:
    resp_body = decode_body(msg.get("response_body"))
    log.info("response %s %s%s -> %d (%d bytes, %dms)",
             msg["method"], msg["host"], msg["uri"],
             msg["status_code"], len(resp_body), msg.get("duration_ms", 0))
    return passthrough(msg["id"])


# ---------------------------------------------------------------------------
# WebSocket server -- you should not need to change anything below
# ---------------------------------------------------------------------------

HANDLERS = {"http-request": handle_request, "http-response": handle_response}


async def serve(websocket):
    log.info("proxy connected from %s", websocket.remote_address)
    raw = await asyncio.wait_for(websocket.recv(), timeout=5)
    hello = json.loads(raw)
    if hello.get("type") != "hello":
        log.error("expected hello, got: %s", hello.get("type"))
        return
    log.info("proxy hello: version=%s", hello.get("version"))
    await websocket.send(json.dumps(HELLO_RESPONSE))
    log.info("sent hello: %d hooks", len(HELLO_RESPONSE["hooks"]))

    async for raw in websocket:
        msg = json.loads(raw)
        handler = HANDLERS.get(msg.get("type", ""))
        if handler is None:
            log.warning("unknown message type: %s", msg.get("type"))
            continue
        await websocket.send(json.dumps(handler(msg)))


async def _main():
    async with websockets.serve(serve, HOST, PORT):
        log.info("listening on ws://%s:%d/middleware", HOST, PORT)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_main())
