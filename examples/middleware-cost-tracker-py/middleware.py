# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
LLM cost tracker -- parses OpenAI and Anthropic response bodies to extract
token usage, then logs cumulative cost per container to a JSONL file.

This middleware is read-only: it never blocks or rewrites anything. It only
hooks responses and extracts the "usage" field that LLM APIs return.

The output file (costs.jsonl) gets one JSON line per LLM response:
    {"ts": "...", "container": "my-app", "host": "api.openai.com",
     "model": "gpt-4", "prompt_tokens": 120, "completion_tokens": 58,
     "cost_usd": 0.0071, "cumulative_usd": 0.42}

WARNING: This is an example only and is NOT meant for production use.
The pricing table is hardcoded, likely outdated, and only covers a few models.
A production cost tracker should pull pricing from a live source and handle
streaming responses (SSE chunks), which this example does not.

Usage:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
    tail -f costs.jsonl
"""

import asyncio
import base64
import json
import logging
import time
from collections import defaultdict
from pathlib import Path

import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("middleware")

HOST = "0.0.0.0"
PORT = 9000
COSTS_FILE = Path("costs.jsonl")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HELLO_RESPONSE = {
    "type": "hello",
    "hooks": [
        {
            "type": "http-response",
            "filters": {
                "host": ["*.openai.com", "*.anthropic.com"],
                "content_type": ["application/json"],
            },
        },
    ],
    "max_body_bytes": 2_097_152,
}

# ---------------------------------------------------------------------------
# Pricing table (USD per token, as of early 2025 -- will go stale quickly)
# ---------------------------------------------------------------------------

# Format: model_prefix -> (cost_per_prompt_token, cost_per_completion_token)
PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o":           (2.50 / 1e6,  10.00 / 1e6),
    "gpt-4o-mini":      (0.15 / 1e6,   0.60 / 1e6),
    "gpt-4-turbo":      (10.0 / 1e6,  30.00 / 1e6),
    "gpt-4":            (30.0 / 1e6,  60.00 / 1e6),
    "gpt-3.5-turbo":    (0.50 / 1e6,   1.50 / 1e6),
    "claude-opus-4":    (15.0 / 1e6,  75.00 / 1e6),
    "claude-sonnet-4":  (3.00 / 1e6,  15.00 / 1e6),
    "claude-3-5-sonnet":(3.00 / 1e6,  15.00 / 1e6),
    "claude-3-5-haiku": (0.80 / 1e6,   4.00 / 1e6),
    "claude-3-haiku":   (0.25 / 1e6,   1.25 / 1e6),
}

# Fallback if the model is unknown
DEFAULT_PRICING = (5.0 / 1e6, 15.0 / 1e6)

# Cumulative cost per container
cumulative: dict[str, float] = defaultdict(float)


def lookup_pricing(model: str) -> tuple[float, float]:
    """Find pricing by longest prefix match."""
    best = DEFAULT_PRICING
    best_len = 0
    for prefix, pricing in PRICING.items():
        if model.startswith(prefix) and len(prefix) > best_len:
            best = pricing
            best_len = len(prefix)
    return best


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    prompt_price, completion_price = lookup_pricing(model)
    return prompt_tokens * prompt_price + completion_tokens * completion_price


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def decode_body(b64: str | None) -> bytes:
    return base64.b64decode(b64) if b64 else b""


def passthrough(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "passthrough"}


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def handle_response(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("response_body"))
    if not raw:
        return passthrough(rid)

    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return passthrough(rid)

    # Extract usage -- OpenAI and Anthropic both use a "usage" object
    usage = body.get("usage")
    if not usage:
        return passthrough(rid)

    # OpenAI: prompt_tokens / completion_tokens
    # Anthropic: input_tokens / output_tokens
    prompt_tokens = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
    completion_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0
    model = body.get("model", "unknown")
    container = msg.get("container", "unknown")
    host = msg.get("host", "")

    cost = estimate_cost(model, prompt_tokens, completion_tokens)
    cumulative[container] += cost

    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "container": container,
        "host": host,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cost_usd": round(cost, 6),
        "cumulative_usd": round(cumulative[container], 6),
    }

    # Append to JSONL file
    with open(COSTS_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    log.info("cost %s model=%s tokens=%d+%d cost=$%.4f cumulative=$%.4f",
             container, model, prompt_tokens, completion_tokens,
             cost, cumulative[container])

    return passthrough(rid)


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
        log.info("writing cost data to %s", COSTS_FILE.resolve())
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_main())
