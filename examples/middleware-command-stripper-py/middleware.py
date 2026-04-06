# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Dangerous command stripper -- rewrites LLM responses to redact shell commands
that look destructive (rm -rf, chmod 777, curl|bash, etc.).

The middleware inspects response bodies from known LLM API hosts. When it finds
a dangerous-looking command inside a JSON "content" field, it replaces the
command with a warning marker so the end user or agent sees that something was
stripped rather than silently executing it.

WARNING: This is an example only and is NOT meant for production use.
The heuristics here are intentionally naive and will miss obfuscated commands,
produce false positives on benign documentation, and do not cover all dangerous
patterns. A real deployment needs a proper sandboxed execution model, not regex.

Usage:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""

import asyncio
import base64
import json
import logging
import re

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
        # Filter on LLM completion endpoints by path rather than domain,
        # so this works with any provider (including self-hosted models).
        {
            "type": "http-response",
            "filters": {
                "path": [
                    "/v1/chat/completions",
                    "/v1/completions",
                    "/v1/responses",
                    "/v1/messages",
                ],
                "content_type": ["application/json"],
            },
        },
    ],
    "max_body_bytes": 2_097_152,  # 2 MB
}

# ---------------------------------------------------------------------------
# Dangerous command patterns
# ---------------------------------------------------------------------------

# Each tuple is (compiled regex, human-readable label).
# Patterns target common destructive one-liners that LLMs sometimes suggest.
DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/", re.IGNORECASE),
     "recursive force-delete from root"),
    (re.compile(r"rm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+/", re.IGNORECASE),
     "recursive force-delete from root"),
    (re.compile(r"mkfs\.", re.IGNORECASE),
     "filesystem format"),
    (re.compile(r"dd\s+if=/dev/zero\s+of=/dev/", re.IGNORECASE),
     "disk overwrite"),
    (re.compile(r"chmod\s+-R\s+777\s+/", re.IGNORECASE),
     "recursive world-writable permissions from root"),
    (re.compile(r"curl\s+[^\|]*\|\s*(sudo\s+)?bash", re.IGNORECASE),
     "pipe curl to bash"),
    (re.compile(r"wget\s+[^\|]*\|\s*(sudo\s+)?bash", re.IGNORECASE),
     "pipe wget to bash"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;:", re.IGNORECASE),
     "fork bomb"),
    (re.compile(r">\s*/dev/sda", re.IGNORECASE),
     "write to raw disk device"),
    (re.compile(r"shutdown\s+(-h\s+)?now", re.IGNORECASE),
     "immediate shutdown"),
    (re.compile(r"init\s+0", re.IGNORECASE),
     "halt system"),
]

REDACTION_MARKER = "[STRIPPED: command removed by middleware -- flagged as: {}]"


def strip_dangerous(text: str) -> tuple[str, list[str]]:
    """Replace dangerous command patterns in text. Returns (cleaned, list of flags)."""
    flags = []
    for pattern, label in DANGEROUS_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(REDACTION_MARKER.format(label), text)
            flags.append(label)
    return text, flags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def decode_body(b64: str | None) -> bytes:
    return base64.b64decode(b64) if b64 else b""


def passthrough(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "passthrough"}


def rewrite_response(rid: str, *, body: bytes) -> dict:
    return {"type": "decision", "id": rid, "action": "rewrite",
            "body": base64.b64encode(body).decode()}


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def handle_response(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("response_body"))
    if not raw:
        return passthrough(rid)

    text = raw.decode("utf-8", errors="replace")
    cleaned, flags = strip_dangerous(text)

    if not flags:
        log.info("response %s %s%s -> %d (clean)",
                 msg["method"], msg["host"], msg["uri"], msg["status_code"])
        return passthrough(rid)

    log.warning("response %s %s%s -> %d STRIPPED: %s",
                msg["method"], msg["host"], msg["uri"],
                msg["status_code"], ", ".join(flags))
    return rewrite_response(rid, body=cleaned.encode("utf-8"))


# ---------------------------------------------------------------------------
# WebSocket server
# ---------------------------------------------------------------------------

HANDLERS = {"http-response": handle_response}


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
