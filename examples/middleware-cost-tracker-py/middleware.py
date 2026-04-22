# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
LLM cost tracker -- parses OpenAI and Anthropic response bodies to
extract token usage, then logs cumulative cost per container.

Read-only: never blocks or rewrites. Only hooks responses and extracts
the "usage" field LLM APIs return.

Output (costs.jsonl): one JSON line per LLM response:
    {"ts": "...", "container": "my-app", "host": "api.openai.com",
     "model": "gpt-4", "prompt_tokens": 120, "completion_tokens": 58,
     "cost_usd": 0.0071, "cumulative_usd": 0.42}

WARNING: Example only. Pricing table is hardcoded and will go stale
quickly. Doesn't handle streaming responses (SSE chunks). A production
cost tracker should pull pricing from a live source.

Usage (preferred):
    greyproxy serve --middleware-cmd 'uv run examples/middleware-cost-tracker-py/middleware.py'

Or as a WS server:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""
import json
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_lib"))
from greyproxy_middleware import decode_body, passthrough, run  # noqa: E402

log = logging.getLogger(__name__)

COSTS_FILE = Path("costs.jsonl")

# Pricing table (USD per token, early 2025 — will go stale quickly).
# Format: model_prefix -> (cost_per_prompt_token, cost_per_completion_token)
PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o":            (2.50 / 1e6, 10.00 / 1e6),
    "gpt-4o-mini":       (0.15 / 1e6,  0.60 / 1e6),
    "gpt-4-turbo":       (10.0 / 1e6, 30.00 / 1e6),
    "gpt-4":             (30.0 / 1e6, 60.00 / 1e6),
    "gpt-3.5-turbo":     (0.50 / 1e6,  1.50 / 1e6),
    "claude-opus-4":     (15.0 / 1e6, 75.00 / 1e6),
    "claude-sonnet-4":   (3.00 / 1e6, 15.00 / 1e6),
    "claude-3-5-sonnet": (3.00 / 1e6, 15.00 / 1e6),
    "claude-3-5-haiku":  (0.80 / 1e6,  4.00 / 1e6),
    "claude-3-haiku":    (0.25 / 1e6,  1.25 / 1e6),
}

DEFAULT_PRICING = (5.0 / 1e6, 15.0 / 1e6)

cumulative: dict[str, float] = defaultdict(float)


def lookup_pricing(model: str) -> tuple[float, float]:
    """Find pricing by longest-prefix match."""
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


def handle_response(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("response_body"))
    if not raw:
        return passthrough(rid)

    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return passthrough(rid)

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
    with open(COSTS_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    log.info("cost %s model=%s tokens=%d+%d cost=$%.4f cumulative=$%.4f",
             container, model, prompt_tokens, completion_tokens,
             cost, cumulative[container])

    return passthrough(
        rid,
        tags={
            "cost.model": model,
            "cost.prompt_tokens": prompt_tokens,
            "cost.completion_tokens": completion_tokens,
            "cost.usd": round(cost, 6),
        },
    )


if __name__ == "__main__":
    log.info("writing cost data to %s", COSTS_FILE.resolve())
    run(
        name="cost-tracker",
        handle_response=handle_response,
        filters_response={
            "host": ["*.openai.com", "*.anthropic.com"],
            "content_type": ["application/json"],
        },
        max_body_bytes=2_097_152,
    )
