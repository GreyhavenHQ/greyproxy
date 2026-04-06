# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Audit log -- writes every request and response to a structured JSONL file.

This middleware is read-only: it never blocks or rewrites anything. It hooks
both requests and responses and logs them with timestamps, container names,
durations, and body sizes. Bodies themselves are NOT logged (only sizes) to
keep the log manageable and avoid storing sensitive data.

Output file (audit.jsonl) gets one line per event:
    {"ts": "...", "direction": "request", "container": "my-app",
     "method": "POST", "host": "api.openai.com", "uri": "/v1/...",
     "body_bytes": 1234, "tls": true}
    {"ts": "...", "direction": "response", "container": "my-app",
     "method": "POST", "host": "api.openai.com", "uri": "/v1/...",
     "status_code": 200, "body_bytes": 5678, "duration_ms": 312}

WARNING: This is an example only and is NOT meant for production use.
It writes to a local file with no rotation, no compression, and no access
controls. A production audit system should use a proper log pipeline
(syslog, SIEM, or a cloud logging service) with tamper-proof storage.

Usage:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
    tail -f audit.jsonl
"""

import asyncio
import base64
import json
import logging
import time

import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("middleware")

HOST = "0.0.0.0"
PORT = 9000
AUDIT_FILE = "audit.jsonl"

# Counters for the status line
stats = {"requests": 0, "responses": 0}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HELLO_RESPONSE = {
    "type": "hello",
    "hooks": [
        {"type": "http-request"},
        {"type": "http-response"},
    ],
    "max_body_bytes": 0,  # we only log sizes, so accept null bodies too
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def body_size(b64: str | None) -> int:
    """Return decoded body size in bytes without fully decoding."""
    if not b64:
        return 0
    # base64 output is roughly 4/3 of the input
    return len(base64.b64decode(b64))


def allow(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "allow"}


def passthrough(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "passthrough"}


def write_record(record: dict):
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def handle_request(msg: dict) -> dict:
    stats["requests"] += 1
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "direction": "request",
        "container": msg.get("container", ""),
        "method": msg["method"],
        "host": msg["host"],
        "uri": msg["uri"],
        "proto": msg.get("proto", ""),
        "body_bytes": body_size(msg.get("body")),
        "tls": msg.get("tls", False),
    }
    write_record(record)

    if stats["requests"] % 100 == 0:
        log.info("audit stats: %d requests, %d responses logged",
                 stats["requests"], stats["responses"])

    return allow(msg["id"])


def handle_response(msg: dict) -> dict:
    stats["responses"] += 1
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "direction": "response",
        "container": msg.get("container", ""),
        "method": msg["method"],
        "host": msg["host"],
        "uri": msg["uri"],
        "status_code": msg["status_code"],
        "request_body_bytes": body_size(msg.get("request_body")),
        "response_body_bytes": body_size(msg.get("response_body")),
        "duration_ms": msg.get("duration_ms", 0),
    }
    write_record(record)

    return passthrough(msg["id"])


# ---------------------------------------------------------------------------
# WebSocket server
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
        log.info("writing audit log to %s", AUDIT_FILE)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_main())
