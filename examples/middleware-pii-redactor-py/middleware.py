# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
PII redactor -- replaces personally identifiable information in requests with
anonymous placeholders, then restores the original values in responses.

The replacement is bidirectional and per-connection:
  Request:  "Please summarize John Doe's file"
         -> "Please summarize PERSON_A's file"
  Response: "PERSON_A's file contains 3 items"
         -> "John Doe's file contains 3 items"

This means the upstream LLM never sees real PII, but the end user gets back
a response with the original names and emails in place.

WARNING: This is an example only and is NOT meant for production use.
The regex patterns here are simplistic and will miss many PII forms (non-Western
names, phone numbers in various formats, addresses, national IDs, etc.).
A production PII redactor should use a dedicated NER model (spaCy, Presidio,
or a cloud DLP API). This example also stores the mapping in memory, so it is
lost on restart and does not handle concurrent sessions with colliding placeholders.

Usage:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""

import asyncio
import base64
import json
import logging
import re
from collections import defaultdict

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
        {
            "type": "http-request",
            "filters": {
                "host": ["*.openai.com", "*.anthropic.com", "*.googleapis.com"],
                "method": ["POST"],
                "content_type": ["application/json"],
            },
        },
        {
            "type": "http-response",
            "filters": {
                "host": ["*.openai.com", "*.anthropic.com", "*.googleapis.com"],
                "content_type": ["application/json"],
            },
        },
    ],
    "max_body_bytes": 2_097_152,
}

# ---------------------------------------------------------------------------
# PII detection patterns (intentionally simple)
# ---------------------------------------------------------------------------

# Email addresses
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

# Names that look like "Firstname Lastname" (capitalized words, 2-3 parts).
# This is very rough and will match many non-name phrases.
NAME_RE = re.compile(r"\b([A-Z][a-z]{1,15})\s+([A-Z][a-z]{1,15})(?:\s+([A-Z][a-z]{1,15}))?\b")

# US Social Security Numbers (XXX-XX-XXXX)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# US phone numbers (various formats)
PHONE_RE = re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")

PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (EMAIL_RE, "EMAIL"),
    (SSN_RE, "SSN"),
    (PHONE_RE, "PHONE"),
    (NAME_RE, "PERSON"),
]

# ---------------------------------------------------------------------------
# Bidirectional mapping
# ---------------------------------------------------------------------------

# real_value -> placeholder
forward_map: dict[str, str] = {}
# placeholder -> real_value
reverse_map: dict[str, str] = {}
# counters per category for generating unique placeholders
counters: dict[str, int] = defaultdict(int)


def get_placeholder(real_value: str, category: str) -> str:
    """Return or create a placeholder for a real PII value."""
    if real_value in forward_map:
        return forward_map[real_value]
    counters[category] += 1
    placeholder = f"{category}_{chr(64 + counters[category])}"  # PERSON_A, EMAIL_B, ...
    if counters[category] > 26:
        placeholder = f"{category}_{counters[category]}"
    forward_map[real_value] = placeholder
    reverse_map[placeholder] = real_value
    log.info("mapped %r -> %s", real_value, placeholder)
    return placeholder


def redact(text: str) -> tuple[str, int]:
    """Replace PII in text with placeholders. Returns (redacted_text, count)."""
    count = 0
    for pattern, category in PII_PATTERNS:
        for match in pattern.finditer(text):
            real_value = match.group(0)
            placeholder = get_placeholder(real_value, category)
            count += 1
        # Do the replacement after collecting all matches to avoid offset issues
        text = pattern.sub(lambda m: get_placeholder(m.group(0), category), text)
    return text, count


def restore(text: str) -> tuple[str, int]:
    """Replace placeholders in text with original PII values. Returns (restored_text, count)."""
    count = 0
    # Sort by longest placeholder first to avoid partial replacements
    for placeholder, real_value in sorted(reverse_map.items(), key=lambda kv: -len(kv[0])):
        if placeholder in text:
            text = text.replace(placeholder, real_value)
            count += 1
    return text, count


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def decode_body(b64: str | None) -> bytes:
    return base64.b64decode(b64) if b64 else b""


def allow(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "allow"}


def rewrite_request(rid: str, *, body: bytes) -> dict:
    return {"type": "decision", "id": rid, "action": "rewrite",
            "body": base64.b64encode(body).decode()}


def passthrough(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "passthrough"}


def rewrite_response(rid: str, *, body: bytes) -> dict:
    return {"type": "decision", "id": rid, "action": "rewrite",
            "body": base64.b64encode(body).decode()}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def handle_request(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("body"))
    if not raw:
        return allow(rid)

    text = raw.decode("utf-8", errors="replace")
    redacted, count = redact(text)

    if count == 0:
        log.info("request  %s %s%s (no PII found)", msg["method"], msg["host"], msg["uri"])
        return allow(rid)

    log.warning("request  %s %s%s REDACTED %d PII value(s)",
                msg["method"], msg["host"], msg["uri"], count)
    return rewrite_request(rid, body=redacted.encode("utf-8"))


def handle_response(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("response_body"))
    if not raw:
        return passthrough(rid)

    text = raw.decode("utf-8", errors="replace")
    restored, count = restore(text)

    if count == 0:
        log.info("response %s %s%s -> %d (no placeholders to restore)",
                 msg["method"], msg["host"], msg["uri"], msg["status_code"])
        return passthrough(rid)

    log.info("response %s %s%s -> %d RESTORED %d PII value(s)",
             msg["method"], msg["host"], msg["uri"], msg["status_code"], count)
    return rewrite_response(rid, body=restored.encode("utf-8"))


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
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_main())
