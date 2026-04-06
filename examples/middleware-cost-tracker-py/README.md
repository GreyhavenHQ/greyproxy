# LLM Cost Tracker

Parses OpenAI and Anthropic response bodies to extract token usage, estimates the cost, and logs cumulative spend per container to a JSONL file. Read-only: never blocks or rewrites anything.

> **Not for production use.** The pricing table is hardcoded, likely outdated, and only covers a few models. Streaming responses (SSE chunks) are not handled. A production cost tracker should pull pricing from a live source and integrate with a billing system.

## What it does

- Hooks `http-response` only, filtered to `*.openai.com` and `*.anthropic.com` with JSON content type
- Extracts the `usage` object from response bodies (supports both OpenAI's `prompt_tokens`/`completion_tokens` and Anthropic's `input_tokens`/`output_tokens`)
- Estimates cost using a built-in pricing table with longest-prefix model matching
- Appends one JSON line per LLM response to `costs.jsonl`
- Tracks cumulative cost per container in memory

## Output

`costs.jsonl` (one line per LLM response):
```json
{"ts":"2025-03-15T14:32:01Z","container":"my-app","host":"api.openai.com:443","model":"gpt-4o","prompt_tokens":120,"completion_tokens":58,"cost_usd":0.00088,"cumulative_usd":0.42}
```

## Run

```bash
uv run middleware.py
```

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
tail -f costs.jsonl
```
