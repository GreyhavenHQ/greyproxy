# Plan: Assemble HTTP Transactions as Agent Conversations

## Business Goal
Reconstruct agent conversations with Claude from intercepted HTTP traffic, so users can review what their AI agents discussed with the model.

## Data Source
- `exported_logs/http_transactions/*.json` - MITM-captured HTTP request/response pairs
- Filter: `url == "https://api.anthropic.com/v1/messages?beta=true"`
- 60 total requests in the dataset

## Key Observations

### Anthropic Messages API Structure
Each request to `/v1/messages` contains the **full conversation history** in the `messages` array:
- Request N has messages: [user_1, assistant_1, user_2, assistant_2, ..., user_N]
- Request N+1 has messages: [user_1, assistant_1, ..., user_N, assistant_N, user_N+1]
- So each subsequent request grows by 2 messages (previous assistant response + new user message)

### Grouping Signal: Session ID
The `metadata.user_id` field in the request body contains a session UUID:
```
user_HASH_account_UUID_session_UUID
```
Requests with the same session UUID belong to the same conversation.

### Data Quality Issues

1. **Request body truncation**: Bodies are capped at 64KB (`DefaultBodySize` in `internal/gostx/internal/util/sniffing/sniffer.go`). 46/60 requests are truncated (body_size == 65536). For these, JSON parsing fails.

2. **Response body corruption**: The export tool (`cmd/exportlogs/main.go:87`) converts `[]byte` BLOBs to `string()`, which corrupts binary gzip data. Response bodies are unreadable from the JSON export.

### Identified Sessions
| Session | Request IDs | Parseable | Notes |
|---------|------------|-----------|-------|
| 365484e0 | 1-14 | IDs 1-14 (all parseable) | Arch Linux CA cert discussion, 14 turns |
| 98816dcb | 26-28 | IDs 26-28 (all parseable) | 3 turns |
| 32e969d8 | 39,44,49,50 | All parseable | Includes a haiku request (ID 39) |
| Unknown | 15-25,29-38,40-43,45-48,51-70 | None (all truncated) | Need heuristic grouping |

## Implementation Plan

### Phase 1: Fix Data Pipeline (prerequisites)

**Step 1a: Fix export tool for binary data**
- In `cmd/exportlogs/main.go`, base64-encode BLOB columns (specifically `response_body`)
- This makes response bodies recoverable for future exports

**Step 1b: Increase body capture limit** (optional, for future captures)
- Increase `DefaultBodySize` in `sniffer.go` or make it configurable
- Would prevent truncation for large conversation contexts

### Phase 2: Build Conversation Assembler (the POC)

**Step 2a: Python script `cmd/assembleconv/assemble.py`**

1. **Load all transactions**: Read all `http_transactions/*.json`, filter for Anthropic messages endpoint
2. **Parse request bodies**: Extract `model`, `messages`, `system`, `metadata` from non-truncated requests
3. **Group by session**: Use `session_UUID` from `metadata.user_id`
4. **Handle truncated requests**: For requests where JSON parsing fails:
   - Try regex extraction of session_id from the raw (truncated) string
   - Fall back to temporal/sequential heuristic grouping
5. **Extract conversation turns**: From the last fully-parseable request per session, extract the messages array. Each pair of (user, assistant) messages is one turn.
6. **Extract incremental messages**: For each request in a session, diff against previous to find the new user message and new assistant response
7. **Output**: Write `exported_logs/inferred_conversations/conversation_XXXX.json`

### Phase 3: Output Format

```json
{
  "conversation_id": "session_365484e0-d64f-4299-a861-1e416f6113d4",
  "model": "claude-opus-4-6",
  "container_name": "claude",
  "request_ids": [1, 2, 3, ...],
  "started_at": "2026-03-13T18:12:51Z",
  "ended_at": "2026-03-13T18:17:46Z",
  "turn_count": 14,
  "system_prompt_summary": "Claude Code CLI agent...",
  "turns": [
    {
      "turn_number": 1,
      "request_id": 1,
      "timestamp": "2026-03-13T18:12:51Z",
      "user_message": { "role": "user", "content": "..." },
      "assistant_message": { "role": "assistant", "content": "..." },
      "model": "claude-opus-4-6",
      "duration_ms": 5114
    }
  ],
  "metadata": {
    "total_requests": 14,
    "truncated_requests": 0,
    "parseable_requests": 14
  }
}
```

## Heuristics for Truncated Request Grouping

For requests where the body is truncated and session_id can't be extracted:
1. **Regex session extraction**: Try to find `session_UUID` pattern in the truncated JSON string
2. **Temporal clustering**: Group requests by time gaps (>2 min gap = new conversation)
3. **Body size progression**: Within a cluster, growing body sizes suggest same conversation
4. **Container name**: Same container_name likely means same agent instance

## Iteration Loop
1. Build the Python script
2. Run it on the dataset
3. Inspect output conversations
4. Fix issues, repeat

## POC Results

### What works
- **Session grouping by metadata.user_id**: Successfully extracts session UUID from parseable requests
- **Heuristic grouping**: Truncated requests assigned to sessions by temporal proximity (5-min gap threshold)
- **Turn detection**: Properly distinguishes real user prompts from tool_result messages and scaffolding
- **Conversation assembly**: Extracts user prompts, assistant text responses, tool calls, and thinking previews from the messages array
- **Scaffolding cleanup**: Strips `<system-reminder>`, `<available-deferred-tools>`, `<local-command-caveat>`, "Tool loaded." etc.

### Output (from dataset)
| Conversation | Session | Turns | Requests | Parseable | Topic |
|-------------|---------|-------|----------|-----------|-------|
| 0001 | 365484e0 | 3 | 23 | 14 | Arch Linux CA cert install + auto-detect |
| 0002 | 98816dcb | 1 | 3 | 3 | Create exportlogs tool |
| 0003 | 32e969d8 | 2 | 34 | 4 | HTTP traffic saving / compression |

### Known Limitations

1. **64KB body truncation**: 46/60 requests are truncated. The `metadata.user_id` (containing session_id) is at the END of the JSON body, so it's lost for large requests. Fix: increase `DefaultBodySize` in `sniffer.go` (up to 1MB max).

2. **Response body corruption**: Binary gzip response data is mangled by `string([]byte)` in the export tool. Cannot decode assistant responses from the SSE stream. Fix: base64-encode BLOB columns in `cmd/exportlogs/main.go`.

3. **Last turn incomplete**: The final turn's assistant response only exists in the (corrupted) response body. The next request would contain it in its messages, but if there's no next request or it's truncated, it's lost.

4. **Heuristic grouping may merge wrong sessions**: Truncated requests without session_id are grouped by time proximity, which may incorrectly merge requests from concurrent sessions.

5. **Subagent requests**: Claude Code launches subagents with the same session_id but different conversation context. Currently these are grouped with the main conversation.

### Recommended Next Steps
1. **Increase body capture limit** to 1MB to avoid truncation for most conversations
2. **Base64-encode response_body** in the export tool so gzip SSE streams are recoverable
3. **Decompress and parse SSE** response bodies to extract the final assistant turn
4. **Detect subagent requests** (shorter system prompts, different tools) and separate them
