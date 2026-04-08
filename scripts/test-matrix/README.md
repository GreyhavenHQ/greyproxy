# Test Matrix Runner

Runs AI coding agents through 3 standard scenarios while greyproxy captures their HTTP traffic.
Purpose: collect real request/response samples to build wire decoders and client adapters.

## Prerequisites

- greyproxy running and intercepting HTTPS traffic
- At least one agent installed and authenticated

## Usage

```bash
# Dry-run first to see what will be executed
PREFIX="greywall --" ./run.sh --dry-run all

# Run a single agent
PREFIX="greywall --" ./run.sh claudecode

# Run one scenario across all agents
PREFIX="greywall --" ./run.sh --scenario A all

# Override model
PREFIX="greywall --" ./run.sh --model gpt-4o codex
```

`PREFIX="greywall --"` routes each agent's traffic through the proxy.

## Agents

| Name | Binary | Status |
|---|---|---|
| `claudecode` | `claude` | verified |
| `opencode` | `opencode` | verified |
| `codex` | `codex` | verified |
| `aider` | `aider` | verified |
| `gemini` | `gemini` | verified |
| `goose` | `goose` | verify `goose run --help` |
| `amp` | `amp` | verify `amp --help` |
| `cursor` | `cursor` | verify `cursor agent --help` |
| `continue` | `cn` | verify `cn --help` |

## Scenarios

| | Prompt | Dir contents | What it tests |
|---|---|---|---|
| **A** | "Say hello world" | empty | session ID, wire format, basic SSE |
| **B** | "Read README.md, write SUMMARY.md" | `README.md` | tool call format, tool result embedding |
| **C** | "Two subagents: list TODOs, count LOC" | `src/*.py` | subagent spawning, cross-session linking |

## After running

Each run leaves a temp dir at `/tmp/greyproxy-matrix-<agent>-<scenario>-*`.

Export captured transactions from the greyproxy DB:

```bash
sqlite3 ~/.local/share/greyproxy/greyproxy.db \
  "SELECT id, url, substr(request_body,1,300) FROM http_transactions ORDER BY id DESC LIMIT 30"
```

Save interesting ones to `internal/greyproxy/dissector/testdata/<agent>_<id>.json` for use in dissector tests.
