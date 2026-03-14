# Conversation Assembly Analysis

Analysis of `cmd/assembleconv/assemble.py` -- the algorithm that reconstructs agent conversations from intercepted HTTP traffic.

## Core Algorithm Specification

### Step 1: Load and Filter

- Load all `*.json` transaction files from `exported_logs/http_transactions/`
- Keep only requests targeting `https://api.anthropic.com/v1/messages` (with or without `?beta=true`)
- Sort by `(timestamp, id)`

### Step 2: Group by Session

Each Anthropic API request includes `metadata.user_id` in the request body, following the pattern:

```
user_HASH_account_UUID_session_UUID
```

Requests sharing the same `session_UUID` belong to the same conversation.

**Fallback for truncated requests** (where JSON parsing fails):
1. Try regex extraction of `session_UUID` from the raw truncated string
2. Sort unassigned requests by timestamp
3. Cluster by temporal proximity (5-minute gap threshold = new group)
4. For each cluster, find the known session with the best time overlap and merge into it
5. If no overlap found, create a synthetic session ID: `heuristic_{first_id}_{last_id}`

### Step 3: Split into Threads

Within a single session, the main agent and subagents share the same session ID but have different system prompts. Classification uses system prompt length and tool count:

| Thread Type | System Prompt Length | Tool Count | Notes |
|-------------|---------------------|------------|-------|
| `main`      | > 10,000 chars       | any        | Primary agent conversation |
| `subagent`  | > 1,000 chars        | any        | Spawned sub-conversations |
| `mcp`       | > 100 chars          | <= 2       | MCP tool calls |
| `utility`   | <= 100 chars         | any        | Quota checks, classification |

- `utility` and `mcp` threads are discarded (not real conversations)
- Subagent threads are further split into separate invocations when the message count drops (non-monotonic growth indicates a new invocation)

### Step 4: Identify Real User Prompts

A user message is considered a "real prompt" (not scaffolding) when it passes these filters:

**Excluded as scaffolding:**
- String content starting with `<available-deferred-tools>`
- Exact matches: `"Tool loaded."`, `"[Request interrupted by user]"`, `"clear"`
- Empty or whitespace-only content
- Messages containing only `tool_result` blocks (no real text)

**Excluded text blocks within list-type content:**
- Blocks starting with `<system-reminder>`
- Blocks starting with `<local-command-caveat>`
- Blocks matching any scaffolding text

**Cleaned from real prompts:**
- `<local-command-caveat>...</local-command-caveat>` tags
- `<command-name>...</command-name>` tags
- `<command-message>...</command-message>` tags
- `<command-args>...</command-args>` tags
- `<local-command-stdout>...</local-command-stdout>` tags

### Step 5: Build Rounds

A "round" = one real user prompt + all assistant steps until the next real prompt.

For the last parseable request in a session (which has the most complete message history, since each API call includes the full conversation), scan the `messages[]` array:

1. Find all indices of real user prompts
2. For each prompt at index `i`, the round spans from `i` to the next prompt (or end of array)
3. Within each round, collect steps:
   - **Assistant steps**: extract text, tool calls (with `tool_use_id`, name, input preview), and thinking preview (first 500 chars)
   - **Tool result merging**: match `tool_result` blocks in subsequent user messages back to their originating `tool_use_id` in the assistant step

### Step 6: Map Requests to Turns

Each HTTP transaction is mapped to a turn number:
- For parseable requests: count the number of real prompts in `messages[]` to determine the turn
- For truncated requests: interpolate using the nearest known turn boundaries (before and after)

### Step 7: Recover Last Assistant Response

The final assistant response only exists in the SSE stream data, since there is no subsequent request that would contain it in its `messages[]` array.

**SSE parsing** (from `response_body_events` or raw `response_body`):
- `content_block_delta` with `text_delta` -> text parts
- `content_block_delta` with `thinking_delta` -> thinking parts
- `content_block_start` with `type: tool_use` -> tool calls

Deduplication: skip if the response text (first 200 chars) already appears in an existing step.

### Step 8: Link Subagent Conversations

Match subagent conversations to parent `Agent` tool calls:
- Subagent conversation IDs contain `/` (e.g., `session_UUID/subagent_XXXX_N`)
- Base session ID links them to the parent
- Temporal matching: find the subagent that started within the parent turn's time range

## Output Format

```json
{
  "conversation_id": "session_{UUID}",
  "model": "claude-opus-4-6",
  "container_name": "claude",
  "request_ids": [1, 2, 3],
  "started_at": "2026-03-13T18:12:51Z",
  "ended_at": "2026-03-13T18:17:46Z",
  "turn_count": 3,
  "system_prompt_summary": "First 500 chars...",
  "system_prompt": "Full system prompt text",
  "turns": [
    {
      "turn_number": 1,
      "user_prompt": "User's cleaned text",
      "steps": [
        {
          "type": "assistant",
          "thinking_preview": "First 500 chars of thinking...",
          "text": "Assistant's text response",
          "tool_calls": [
            {
              "tool": "Read",
              "input_preview": "{\"file_path\":\"/some/file\"}",
              "tool_use_id": "toolu_xxx",
              "result_preview": "First 500 chars of result...",
              "is_error": false,
              "linked_conversation_id": "session_UUID/subagent_xxx"
            }
          ]
        }
      ],
      "api_calls_in_turn": 5,
      "request_ids": [1, 2, 3],
      "timestamp": "2026-03-13T18:12:51Z",
      "timestamp_end": "2026-03-13T18:13:02Z",
      "duration_ms": 11000,
      "model": "claude-opus-4-6"
    }
  ],
  "linked_subagents": [
    {
      "conversation_id": "session_UUID/subagent_xxx",
      "turn_count": 2,
      "started_at": "...",
      "ended_at": "...",
      "first_prompt": "..."
    }
  ],
  "last_turn_has_response": true,
  "metadata": {
    "total_requests": 23,
    "truncated_requests": 9,
    "parseable_requests": 14,
    "messages_in_best_request": 42,
    "best_request_id": 14
  }
}
```

## Discrepancies: assembleconv vs Database/Export Pipeline

### Current Data Pipeline

```
HTTP Traffic -> Sniffer (2MB body limit) -> SQLite DB -> Export Tool -> JSON files -> assembleconv
```

### Issues Found

| Issue | Details |
|-------|---------|
| **Base64 bodies ignored** | The export tool base64-encodes non-UTF8 response data and sets `response_body_encoding: "base64"`. The assembler never checks `_encoding` flags, so these bodies are silently unusable. |
| **Compression metadata unused** | Export sets `_was_compressed: true` on decompressed bodies. The assembler does not use this metadata. |
| **No direct DB access** | The assembler depends on the export tool's correctness for decompression, SSE parsing, and encoding. Any export bug propagates silently. |
| **Plan doc outdated** | The plan references 64KB body truncation, but the actual limit was increased to 2MB. The code handles this correctly (checks JSON parse failure), so this is a documentation-only issue. |

## Subagent-to-Parent Linking: Limitations

The current implementation has **no concrete evidence** linking a subagent request to the specific parent `Agent` tool call that spawned it. All linking is heuristic.

### What the Anthropic API exposes

- **`session_UUID`** (from `metadata.user_id`): Shared by the main agent and all its subagents within the same Claude Code session. This reliably prevents merging requests from different Claude Code processes, since each process gets a unique session UUID.
- **System prompt content**: Differs between main agent (~15K chars) and subagents (~1-5K chars), which is the basis for thread classification.
- **HTTP headers**: Nearly identical between main and subagent requests. The `Anthropic-Beta` flags differ only for utility requests (haiku quota checks omit `claude-code-20250219`).
- **`container_name`**: Always `"claude"` regardless of main vs subagent. No process-level distinction.

### What the Anthropic API does NOT expose

- No `parent_request_id` or `agent_invocation_id` field
- No header distinguishing subagent requests from main requests
- No correlation ID linking a subagent back to the `Agent` tool call that spawned it

### How thread classification works (and its weaknesses)

Classification is based on system prompt character length:

| Classification | System Prompt Length | Weakness |
|---------------|---------------------|----------|
| `main`        | > 10,000 chars       | Reliable for Claude Code; main prompt is ~15K |
| `subagent`    | > 1,000 chars        | Different subagent types could collide if they have the same prompt length |
| `mcp`         | > 100 chars, <= 2 tools | Fragile; depends on tool count threshold |
| `utility`     | <= 100 chars         | Reliable; quota checks have no system prompt |

Subagent threads are bucketed by `f"subagent_{sys_len}"` (exact byte count), then split into separate invocations when message count drops. This works when subagents run sequentially, but concurrent subagents of the same type would interleave and confuse the splitter.

### Linking subagents to parent turns

`link_subagent_conversations()` matches subagents to parent `Agent` tool calls by temporal overlap (subagent start time falls within the parent turn's time range). This is a best-effort heuristic; it cannot distinguish multiple `Agent` calls in the same turn that spawn subagents of the same type.

### Potential improvements

1. **Hash system prompt content** instead of using raw length -- a content hash would distinguish subagent types that happen to have the same prompt length.
2. **Use message content overlap** -- if two requests share the same first N messages, they belong to the same conversation thread. This is a stronger signal than prompt length.
3. **Track TCP/TLS session identity at the proxy level** -- requests from the same connection almost certainly come from the same process, providing process-level isolation even without application-layer identifiers.

## Provider-Agnostic Generalization

To support conversation assembly from different LLM providers, the algorithm needs these provider-specific adapters:

### Concepts That Vary by Provider

| Concept | Anthropic | OpenAI | Google (Gemini) |
|---------|-----------|--------|-----------------|
| **API endpoint** | `/v1/messages` | `/v1/chat/completions` | `/v1/models/*/generateContent` |
| **Session ID extraction** | `metadata.user_id` -> session UUID | No standard field; app-specific | No standard field; app-specific |
| **Message history** | Full history in every request (stateless) | Full history in every request (stateless) | Can be stateful (cached context) or stateless |
| **Tool call format** | `type: "tool_use"` with `id`, `name`, `input` | `tool_calls[]` with `id`, `function.name`, `function.arguments` | `functionCall` with `name`, `args` |
| **Tool result format** | `type: "tool_result"` with `tool_use_id` | `role: "tool"` with `tool_call_id` | `functionResponse` with `name` |
| **SSE response format** | `content_block_delta` with `text_delta` | `choices[0].delta.content` | Different streaming protocol |
| **Thinking/reasoning** | `type: "thinking"` blocks | Not exposed (o1/o3 reasoning hidden) | `type: "thinking"` blocks (Gemini 2.5) |
| **System prompt** | `system[]` array of text blocks | `messages[0]` with `role: "system"` | `systemInstruction` field |

### Required Provider Adapter Interface

A generic assembler would need each provider to implement:

```
1. url_matches(url) -> bool
   Whether this HTTP transaction targets this provider's API

2. extract_session_id(request_body) -> str | None
   Provider/app-specific session grouping signal

3. extract_messages(request_body) -> list[Message]
   Normalize messages into a common format: {role, content, tool_calls, tool_results}

4. extract_model(request_body) -> str
   Model identifier

5. extract_system_prompt(request_body) -> str | None
   System prompt text for thread classification

6. parse_sse_response(events) -> AssistantResponse
   Reconstruct the assistant's response from streaming events

7. is_real_user_prompt(message) -> bool
   Distinguish real user input from tool results and scaffolding
   (Note: scaffolding detection is app-specific, not provider-specific)
```

### What Stays the Same Across Providers

These parts of the algorithm are provider-agnostic:
- Temporal clustering for session grouping fallback
- Thread splitting by system prompt fingerprint
- Round/turn structure (prompt -> steps -> next prompt)
- Tool result merging (match results to calls by ID)
- Subagent linking by time overlap
- Output format (the conversation JSON structure)
