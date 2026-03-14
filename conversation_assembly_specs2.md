# Conversation Assembly v2 Specification

`cmd/assembleconv/assemble2.py` reconstructs agent conversations by reading directly from `greyproxy.db` and maintaining state in `conversation.db`. It works incrementally and includes an API server with a web viewer.

## Data Pipeline

```
HTTP Traffic -> MITM Proxy (2MB body limit) -> greyproxy.db
                                                    |
                                              assemble2.py
                                                    |
                                              conversation.db
                                                    |
                                              API Server + Viewer
```

This replaces the previous pipeline (`greyproxy.db -> exportlogs -> JSON files -> assemble.py -> JSON output`), eliminating the export step and its associated issues (base64 bodies silently ignored, compression metadata unused, export bugs propagating silently).

## Usage

```bash
python assemble2.py                              # one-shot assembly
python assemble2.py --serve                      # assemble + serve API
python assemble2.py --serve --watch              # assemble + serve + periodic re-assembly
python assemble2.py --serve --watch --interval 5 # check every 5 seconds
python assemble2.py --full                       # full re-assembly (ignore watermark)
```

Options:
- `--greyproxy-db PATH` -- source database (default: `greyproxy.db`)
- `--conversation-db PATH` -- output database (default: `conversation.db`)
- `--serve` -- start API server after assembly
- `--port PORT` -- API server port (default: `8199`)
- `--watch` -- background thread polls for new transactions
- `--interval SECS` -- poll interval (default: `10`)

## Incremental Processing

Assembly tracks a watermark (`last_processed_id`) in the `processing_state` table. Each run:

1. Query `http_transactions` where `id > last_processed_id`
2. Filter for Anthropic API calls (`https://api.anthropic.com/v1/messages`)
3. Extract `session_UUID` from each new transaction's request body
4. Collect the set of affected session IDs
5. Re-query ALL transactions for those sessions (full history needed for correct assembly)
6. Re-assemble affected conversations and upsert into `conversation.db`
7. Update the watermark

Sessions not affected by new transactions are left untouched. A `--full` flag forces re-assembly of everything.

## conversation.db Schema

```sql
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,              -- "session_{UUID}" or "session_{UUID}/subagent_xxx"
    model TEXT,
    container_name TEXT,
    started_at TEXT,
    ended_at TEXT,
    turn_count INTEGER DEFAULT 0,
    system_prompt TEXT,
    system_prompt_summary TEXT,
    parent_conversation_id TEXT,       -- NULL for main, "session_{UUID}" for subagents
    last_turn_has_response INTEGER DEFAULT 0,
    metadata_json TEXT,
    linked_subagents_json TEXT,
    request_ids_json TEXT,
    incomplete INTEGER DEFAULT 0,
    incomplete_reason TEXT,
    updated_at TEXT
);

CREATE TABLE turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    turn_number INTEGER NOT NULL,
    user_prompt TEXT,
    steps_json TEXT,                   -- JSON array of step objects
    api_calls_in_turn INTEGER DEFAULT 0,
    request_ids_json TEXT,
    timestamp TEXT,
    timestamp_end TEXT,
    duration_ms INTEGER,
    model TEXT,
    UNIQUE(conversation_id, turn_number)
);

CREATE TABLE processing_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

Steps are stored as a JSON array in `steps_json` because their structure is deeply nested (tool calls with results, thinking previews) and there is no need to query individual steps.

## BLOB Handling

`assemble2.py` reads BLOBs directly from `greyproxy.db`, handling decompression and encoding inline:

1. Check for gzip magic bytes (`\x1f\x8b`), decompress if present
2. Attempt UTF-8 decode; skip binary bodies (they cannot contain conversation data)
3. Parse SSE events from `response_body` when `response_content_type` contains `text/event-stream`

This eliminates the previous issue where the export tool would base64-encode binary bodies and the assembler would silently ignore them.

## Core Algorithm

The assembly algorithm is identical to `assemble.py` (see `conversation_assembly_analysis.md` for full specification). In summary:

### Step 1: Load and Filter
- Query `http_transactions` from `greyproxy.db` (read-only)
- Keep requests targeting `https://api.anthropic.com/v1/messages`
- Decompress and decode BLOBs inline

### Step 2: Group by Session
- Extract `session_UUID` from `metadata.user_id` in request body
- Fallback: regex extraction from raw body, then temporal clustering (5-minute gap)

### Step 3: Split into Threads
- Classify by system prompt length: main (>10K), subagent (>1K), mcp (>100, <=2 tools), utility (<=100)
- Discard utility and mcp threads
- Split subagent threads by message count drops (new invocation detection)

### Step 4: Identify Real User Prompts
- Filter out scaffolding (`<available-deferred-tools>`, `"Tool loaded."`, etc.)
- Clean XML tags from real prompts

### Step 5: Build Rounds
- Each round = one real user prompt + all assistant steps until the next prompt
- Merge tool results back to their originating tool calls by `tool_use_id`

### Step 6: Map Requests to Turns
- Parseable requests: count real prompts to determine turn number
- Truncated requests: interpolate from nearest known boundaries

### Step 7: Recover Last Assistant Response
- Parse SSE from the last request's `response_body`
- Deduplicate against existing steps

### Step 8: Link Subagent Conversations
- Match subagent IDs to parent by shared session UUID prefix
- Temporal matching: subagent start time within parent turn's time range

## API Server

The `--serve` flag starts an HTTP server on the configured port.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Serves `viewer2.html` |
| GET | `/api/conversations` | List main conversations (no subagents), ordered by `ended_at` DESC |
| GET | `/api/conversations/{id}` | Full conversation with turns and steps |
| GET | `/api/subagents/{parent_id}` | List subagent conversations for a parent |

Subagent conversation IDs contain `/` (e.g., `session_UUID/subagent_3878_1`), which must be URL-encoded in requests.

### Conversation List Response

```json
[
  {
    "conversation_id": "session_{UUID}",
    "model": "claude-opus-4-6",
    "container_name": "claude",
    "started_at": "2026-03-13T18:12:51Z",
    "ended_at": "2026-03-13T18:17:46Z",
    "turn_count": 3,
    "first_prompt": "Hello, can you help me...",
    "last_turn_has_response": true,
    "metadata": { ... }
  }
]
```

### Full Conversation Response

Same structure as documented in `conversation_assembly_analysis.md` under "Output Format", with turns containing `steps_json` arrays.

## Web Viewer (`viewer2.html`)

API-driven single-page viewer served at `/`. Key differences from `viewer.html`:

- Fetches conversation list from `/api/conversations` instead of probing static JSON files
- Lazy-loads full conversation on click via `/api/conversations/{id}`
- Sidebar shows only main conversations; selecting one fetches and displays its subagents indented below via `/api/subagents/{id}`
- Polls every 15 seconds for new conversations (live indicator dot)
- Caches fetched conversations client-side

## Subagent-to-Parent Linking

Unchanged from the original analysis. See `conversation_assembly_analysis.md` section "Subagent-to-Parent Linking: Limitations" for details on the heuristic approach and its weaknesses.

## Provider-Agnostic Generalization

Unchanged from the original analysis. See `conversation_assembly_analysis.md` section "Provider-Agnostic Generalization" for the adapter interface needed to support OpenAI, Gemini, etc.
