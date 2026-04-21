# rtk Compression Middleware -- end-to-end test

Exercises the rtk compression middleware against a fake LLM server and a fake client. Two files:

- `server.py` -- a stdlib HTTP server pretending to be Anthropic's `/v1/messages`. Logs what it receives and writes the last request body to `/tmp/rtk_test_last_req.json`.
- `client.py` -- drives a two-turn conversation through greyproxy, comparing "bytes sent by client" against "bytes actually received by server". If the middleware is wired and matched the filter, the server should see a smaller `tool_result` than the client sent.

## What the scenario does

Turn 1: client sends a plain user message through greyproxy to the fake server. The fake server returns an assistant message with a `tool_use` block asking to run `cat package.json`.

Turn 2: the client fabricates a noisy fake package.json as the tool output, wraps it in a `tool_result` block, and sends it back through greyproxy. This is the request the middleware should rewrite: the `tool_result` content goes through `rtk json -`, which collapses the JSON and drops most of it, and greyproxy forwards the compressed version upstream. The fake server sees the compressed bytes, logs their size, and returns a final "done" message.

The client then reads the server's trace file and prints a before/after size comparison.

## Prerequisites

Four things need to be true at once for this test to exercise the rewrite path:

1. `rtk` is on `PATH` (`cargo install --git https://github.com/rtk-ai/rtk`).
2. The rtk middleware is running: `uv run ../middleware.py` (from the parent directory).
3. greyproxy is running with the middleware wired up:
   ```bash
   greyproxy serve --middleware ws://127.0.0.1:9000/middleware
   ```
4. greyproxy's endpoint registry treats the fake server as an LLM endpoint, so the middleware's `llm: true` filter matches. Because the fake server runs on `127.0.0.1:18123`, you must add a one-off endpoint rule. The easiest way is via the greyproxy API (assuming its UI/API is on the default port `43080`):
   ```bash
   curl -sS -X POST http://127.0.0.1:43080/api/endpoint-rules \
     -H 'Content-Type: application/json' \
     -d '{
       "host_pattern": "127.0.0.1:18123",
       "path_pattern": "/v1/messages",
       "method": "POST",
       "decoder_name": "anthropic",
       "priority": 100
     }'
   ```
   You can delete this rule after the test via `DELETE /api/endpoint-rules/<id>` or from the UI.

   Alternatively, edit `middleware.py`'s `HELLO_RESPONSE` temporarily and replace the `"filters": {"llm": true, ...}` with `"filters": {"host": ["127.0.0.1:18123"]}`. This bypasses the registry entirely for the test.

## Run

Terminal A -- fake LLM server:
```bash
uv run server.py
```

Terminal B -- middleware (if not already running):
```bash
uv run ../middleware.py
```

Terminal C -- client:
```bash
uv run client.py
```

The client prints a summary at the end:

```
============================================================
  rtk compression test result
============================================================
  tool_result sent by client:       1832 bytes
  tool_result seen by server:        641 bytes
  delta:                            1191 bytes (65.0% smaller)

  PASS: middleware rewrote the tool_result between client and server
```

Exit code `0` on PASS, `2` if no rewrite happened (with diagnostics), `3` if the server somehow saw more bytes.

## Environment overrides

- `PROXY_URL` (default `http://127.0.0.1:43051`) -- greyproxy's HTTP proxy listen address.
- `SERVER_URL` (default `http://127.0.0.1:18123/v1/messages`) -- fake LLM server endpoint.

If your greyproxy is on different ports, export these before running the client.

## Interpreting NO REWRITE

If the final output reads `NO REWRITE` the middleware did not rewrite the request. The most likely causes:

- **`rtk` missing.** The middleware logs `rtk=MISSING` at startup and acts as a passthrough.
- **Middleware not connected to greyproxy.** The middleware prints `proxy connected from ...` when greyproxy establishes the WebSocket. If you never saw that line, check `--middleware ws://...` on the greyproxy command line.
- **`llm: true` did not match.** Without the endpoint rule in step 4 above, greyproxy's registry returns empty for `127.0.0.1:18123`, so `isLLM=false` and the middleware is never called. Add the rule, or swap the hello filter temporarily.
- **rtk mode heuristic rejected the payload.** `pick_mode()` only fires for diff/json/log shapes today. The fake package.json fixture is chosen to match `rtk json -`, so this should not happen unless the fixture has been edited.
