# rtk Tool-Output Compressor

Compresses the output of `tool_result` blocks inside outgoing LLM request bodies by piping them through [`rtk`](https://github.com/rtk-ai/rtk) (Rust Token Killer) before the model sees them. rtk acts as a pure text transformer here: it never executes any command, it only reads captured output from stdin.

The net effect is that when an agent sends a noisy `git diff` or `jq` output back to the model as a tool result, the model receives a compacted version and the agent's context window stretches further. Nothing about the local command execution changes.

> **Not for production use.** The command-shape heuristics are intentionally naive. Measure token savings on your own workload before relying on this.

## What it does

- Hooks `http-request` with `{"llm": true}`, so greyproxy's endpoint registry decides which traffic counts as LLM. Adding a new provider rule upstream means this middleware starts seeing that provider with no restart.
- Parses Anthropic (`/v1/messages`) and OpenAI (`/v1/chat/completions`) message shapes.
- For each `tool_result` (Anthropic) or `role=tool` message (OpenAI), walks back to the paired `tool_use` / `tool_call` to recover the command that produced the output.
- Picks an rtk stdin mode based on the shape of the command and/or the first 256 bytes of the output:
  - `git diff`, unified diff markers → `rtk diff -`
  - Output starts with `{` or `[`, or command contains `jq` → `rtk json -`
  - `tail`/`journalctl`/`/var/log/`/`*.log` → `rtk log -`
  - Anything else → passthrough (no rewrite)
- Returns a `rewrite` decision with the mutated JSON body, and attaches tags (`rtk.rewrites`, `rtk.bytes_before`, `rtk.bytes_after`) so the activity view shows what was compressed.

## Why hook the request and not the response

Tool outputs flow *from* the agent *to* the model inside request bodies (`messages[].content[].tool_result`). The response path carries the model's reply, which does not contain tool execution output. Hooking the request means we transform what the model receives.

## Prerequisites

Install rtk:

```bash
cargo install --git https://github.com/rtk-ai/rtk
# or: brew install rtk-ai/tap/rtk
```

The middleware auto-detects `rtk` on `PATH` at startup. If it is missing, the middleware logs a warning and acts as a passthrough.

## Run

```bash
uv run middleware.py
```

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```

Or cascade after another middleware (e.g. a secret scanner that runs first):

```bash
greyproxy serve \
  --middleware ws://localhost:9100/secret-scanner \
  --middleware ws://localhost:9000/middleware
```

## Verifying it's working

- The middleware logs one line per rewritten `tool_result` with the before/after byte count and percent saved.
- In the greyproxy Activity view, look for a blue `rewrite` badge on LLM requests with `rtk.*` tags in the detail panel.
- If you see `rtk=MISSING` in the startup log, rtk is not on `PATH`.

## Tuning

- `RTK_TIMEOUT_S` (default 5): a hung rtk invocation falls through to the original text rather than blocking the live LLM request.
- The `pick_mode` function is where to add new detection rules. If you add a new rtk subcommand (e.g. a generic `rtk read -`), wire it in there.
