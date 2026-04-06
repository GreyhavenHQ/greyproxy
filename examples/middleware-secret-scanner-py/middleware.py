# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Secret scanner -- blocks outbound requests that contain accidentally leaked
secrets such as API keys, AWS credentials, private keys, or passwords.

Only inspects request bodies (outbound). Responses are not hooked.

WARNING: This is an example only and is NOT meant for production use.
The patterns here cover a handful of common secret formats but will miss
encoded, split, or obfuscated credentials. A production scanner should use
a purpose-built tool (truffleHog, detect-secrets, Gitleaks) and run against
all content types, not just JSON.

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
        # Only outbound requests -- we are scanning for leaked secrets.
        {"type": "http-request"},
    ],
    "max_body_bytes": 2_097_152,
}

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

# Each tuple: (compiled regex, label, description for the block message)
SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    # AWS access key IDs (always start with AKIA)
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    # AWS secret keys (40 base64-ish chars after a known prefix context)
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}"), "AWS Secret Key"),
    # Generic API keys (common env-var-style patterns)
    (re.compile(r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{20,}"),
     "Generic API Key/Token"),
    # OpenAI API keys
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style API Key"),
    # GitHub personal access tokens
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub PAT"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "GitHub Fine-grained PAT"),
    # PEM private keys
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "PEM Private Key"),
    # Slack tokens
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack Token"),
    # Stripe keys
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe Secret Key"),
    # Generic "password" in JSON/form data
    (re.compile(r'(?i)"password"\s*:\s*"[^"]{8,}"'), "Password in JSON"),
    # Bearer tokens in body (sometimes apps paste full curl commands)
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer Token"),
]

# Hosts/paths to skip scanning (avoid flagging legitimate auth endpoints)
SKIP_HOSTS = {
    "login.microsoftonline.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def scan_for_secrets(text: str) -> list[str]:
    """Return list of matched secret labels found in text."""
    found = []
    for pattern, label in SECRET_PATTERNS:
        if pattern.search(text):
            found.append(label)
    return found


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


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def handle_request(msg: dict) -> dict:
    rid = msg["id"]
    host = msg.get("host", "")

    # Strip port for host matching
    hostname = host.split(":")[0] if ":" in host else host
    if hostname in SKIP_HOSTS:
        return allow(rid)

    raw = decode_body(msg.get("body"))
    if not raw:
        return allow(rid)

    text = raw.decode("utf-8", errors="replace")
    secrets = scan_for_secrets(text)

    if not secrets:
        log.info("request  %s %s%s (clean)", msg["method"], host, msg["uri"])
        return allow(rid)

    labels = ", ".join(secrets)
    log.warning("BLOCKED  %s %s%s -- leaked secret(s): %s (container=%s)",
                msg["method"], host, msg["uri"], labels, msg.get("container", ""))
    return deny(rid, 403, f"Request blocked: detected leaked credentials ({labels}). "
                          "Remove secrets from the request body before retrying.")


# ---------------------------------------------------------------------------
# WebSocket server
# ---------------------------------------------------------------------------

HANDLERS = {"http-request": handle_request}


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
