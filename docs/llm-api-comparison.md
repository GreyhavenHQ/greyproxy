# LLM API Comparison: Anthropic vs OpenAI

Observed through greyproxy MITM traffic from Claude Code and OpenCode (March 2026).
This documents the wire format as seen by the proxy, not the full API specification.

> **Scope**: Anthropic Messages API (`/v1/messages`) and OpenAI Responses API (`/v1/responses`).
> OpenAI Chat Completions (`/v1/chat/completions`) is not covered yet.

## Endpoints

| | Anthropic | OpenAI |
|---|---|---|
| **URL** | `POST https://api.anthropic.com/v1/messages` | `POST https://api.openai.com/v1/responses` |
| **Query params** | `?beta=true` (optional) | None observed |
| **Auth header** | `x-api-key: sk-ant-...` | `Authorization: Bearer sk-...` |
| **Streaming** | `stream: true` in body | `stream: true` in body |
| **Response type** | `text/event-stream` (SSE) | `text/event-stream` (SSE) |

## Request Body Structure

| Field | Anthropic | OpenAI |
|---|---|---|
| **Model** | `model: "claude-opus-4-6"` | `model: "gpt-5.1"` |
| **System prompt** | Separate `system` array of `{type, text}` blocks | `{role: "developer", content: "..."}` item inside `input[]` |
| **Messages** | `messages[]` with uniform `{role, content}` | `input[]` with heterogeneous items (see below) |
| **Tools** | `tools[]` with `{name, description, input_schema}` | `tools[]` with `{type: "function", name, description, parameters, strict}` |
| **Max tokens** | `max_tokens: 16384` | `max_output_tokens: 32000` |
| **Thinking/reasoning** | `thinking: {type: "enabled", budget_tokens: N}` | `reasoning: {effort: "medium", summary: "auto"}` |
| **Streaming config** | `stream: true` | `stream: true` |
| **Caching** | Implicit via `cache_control` on content blocks | `prompt_cache_key: "ses_XXX"` |
| **Tool choice** | `tool_choice: {type: "auto"}` | `tool_choice: "auto"` |

## Message/Input Format

This is the biggest structural difference between the two APIs.

### Anthropic: `messages[]`

All items have `{role, content}`. Content is either a string or array of typed blocks.

```json
{
  "messages": [
    {"role": "user", "content": "Hello"},
    {"role": "assistant", "content": [
      {"type": "thinking", "thinking": "..."},
      {"type": "text", "text": "Hi there!"},
      {"type": "tool_use", "id": "toolu_XXX", "name": "Bash", "input": {"command": "ls"}}
    ]},
    {"role": "user", "content": [
      {"type": "tool_result", "tool_use_id": "toolu_XXX", "content": "file1.txt\nfile2.txt"}
    ]}
  ]
}
```

### OpenAI: `input[]`

Items are heterogeneous. Some have `role`, some have `type`, some have both.

```json
{
  "input": [
    {"role": "developer", "content": "You are a coding agent..."},
    {"role": "user", "content": [{"type": "input_text", "text": "Hello"}]},
    {"type": "reasoning", "encrypted_content": "..."},
    {"type": "function_call", "call_id": "call_XXX", "name": "bash", "arguments": "{\"command\":\"ls\"}"},
    {"type": "function_call_output", "call_id": "call_XXX", "output": "file1.txt\nfile2.txt"},
    {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Here are the files."}]}
  ]
}
```

### Message Type Mapping

| Concept | Anthropic | OpenAI |
|---|---|---|
| **System prompt** | `system: [{type: "text", text: "..."}]` (top-level) | `{role: "developer", content: "..."}` (in `input[]`) |
| **User message** | `{role: "user", content: "text"}` or `{role: "user", content: [{type: "text", text: "..."}]}` | `{role: "user", content: [{type: "input_text", text: "..."}]}` |
| **Assistant text** | `{role: "assistant", content: [{type: "text", text: "..."}]}` | `{type: "message", role: "assistant", content: [{type: "output_text", text: "..."}]}` |
| **Thinking** | `{type: "thinking", thinking: "..."}` content block | `{type: "reasoning", encrypted_content: "..."}` top-level item |
| **Tool call** | `{type: "tool_use", id: "toolu_XXX", name: "Read", input: {...}}` content block inside assistant message | `{type: "function_call", call_id: "call_XXX", name: "read", arguments: "{...}"}` top-level item |
| **Tool result** | `{type: "tool_result", tool_use_id: "toolu_XXX", content: "..."}` content block inside user message | `{type: "function_call_output", call_id: "call_XXX", output: "..."}` top-level item |

Key differences:
- Anthropic nests tool calls inside assistant messages and tool results inside user messages
- OpenAI places them as top-level items in the `input[]` array
- Anthropic tool arguments are a JSON object; OpenAI stringifies them
- OpenAI reasoning is opaque (encrypted); Anthropic thinking is plaintext (when enabled)

## SSE Response Events

### Anthropic

| Event | Description |
|---|---|
| `message_start` | Response metadata (model, usage) |
| `content_block_start` | New block: `{type: "text"}`, `{type: "tool_use", name: "..."}`, `{type: "thinking"}` |
| `content_block_delta` | Incremental content: `text_delta`, `input_json_delta`, `thinking_delta` |
| `content_block_stop` | Block finished |
| `message_delta` | Final usage stats, stop reason |
| `message_stop` | End of response |

### OpenAI

| Event | Description |
|---|---|
| `response.created` | Response metadata (id, model) |
| `response.in_progress` | Processing started |
| `response.output_item.added` | New output item: `{type: "reasoning"}`, `{type: "function_call", name: "..."}`, `{type: "message"}` |
| `response.output_text.delta` | Streamed text content |
| `response.function_call_arguments.delta` | Streamed tool call arguments |
| `response.function_call_arguments.done` | Complete tool call arguments |
| `response.reasoning_summary_text.delta` | Streamed reasoning summary |
| `response.output_item.done` | Output item finished |
| `response.completed` | Final event with full response object and usage |

### SSE Event Mapping

| Concept | Anthropic | OpenAI |
|---|---|---|
| **Text streaming** | `content_block_delta` with `text_delta` | `response.output_text.delta` |
| **Tool call start** | `content_block_start` with `type: "tool_use"` | `response.output_item.added` with `type: "function_call"` |
| **Tool call args** | `content_block_delta` with `input_json_delta` | `response.function_call_arguments.delta` |
| **Tool call complete** | `content_block_stop` | `response.function_call_arguments.done` |
| **Thinking** | `content_block_delta` with `thinking_delta` | `response.reasoning_summary_text.delta` |
| **End of response** | `message_stop` | `response.completed` |

## Session and Identity

| | Anthropic | OpenAI |
|---|---|---|
| **Session ID location** | `metadata.user_id` field in body | `prompt_cache_key` field in body |
| **Session ID format** | `user_HASH_account_UUID_session_UUID` (36-char hex UUID) | `ses_XXXX` (alphanumeric, ~30 chars) |
| **Also in headers** | No | `Session_id` header (same value as `prompt_cache_key`) |
| **Client identifier** | `anthropic-version` header, User-Agent | `Originator` header (e.g. `opencode`), User-Agent |

## Tool Names

Tool names differ in casing between providers. Anthropic uses PascalCase, OpenAI uses lowercase.

| Function | Anthropic (Claude Code) | OpenAI (OpenCode) |
|---|---|---|
| Read file | `Read` | `read` |
| Edit file | `Edit` | `apply_patch` |
| Write file | `Write` | (via `apply_patch`) |
| Run command | `Bash` | `bash` |
| Search content | `Grep` | `grep` |
| Find files | `Glob` | `glob` |
| Spawn subagent | `Agent` | `task` |
| Ask user | `AskUserQuestion` | `question` |
| Web fetch | `WebFetch` | `webfetch` |
| Web search | `WebSearch` | (not observed) |
| Todo list | `TodoWrite` | `todowrite` |
| Skills/commands | `Skill` | `skill` |
| Tool discovery | `ToolSearch` | (not observed) |
| Notebook | `NotebookEdit` | (not observed) |

## Subagent / Task Spawning

| | Anthropic | OpenAI |
|---|---|---|
| **Tool name** | `Agent` | `task` |
| **How it works** | Agent tool call with `prompt` and `description` fields | Task tool call with `prompt` and `description` fields |
| **Session sharing** | Subagent shares the same session UUID as parent | Subagent gets its own `prompt_cache_key` |
| **Parent-child link** | Same session ID; distinguished by system prompt length (main >10K, subagent ~4-5K) | `function_call_output` contains `task_id: ses_XXX` referencing the subagent's session |
| **Classification** | System prompt length threshold | Presence of management tools (`task`, `question`, `todowrite`) indicates main |

## Thread Classification Heuristics

Used by greyproxy to distinguish main conversations from subagents and utilities.

### Anthropic

Based on system prompt length (`system[]` blocks total character count):

| System Prompt Length | Tools | Classification |
|---|---|---|
| > 10,000 chars | Any | `main` (Claude Code primary conversation) |
| > 1,000 chars | Any | `subagent` |
| > 100 chars | <= 2 | `mcp` (MCP utility, discarded) |
| <= 100 chars | Any | `utility` (discarded) |

### OpenAI

Based on tool list contents (system prompt length is identical for main and subagents):

| Condition | Classification |
|---|---|
| Tools include `task`, `question`, or `todowrite` | `main` (OpenCode primary conversation) |
| Has tools but no management tools | `subagent` |
| No tools | `utility` (e.g. title generator using gpt-5-nano) |

## Usage / Token Reporting

| Field | Anthropic | OpenAI |
|---|---|---|
| **Location** | `message_delta` event and `message_start` | `response.completed` event -> `response.usage` |
| **Input tokens** | `usage.input_tokens` | `usage.input_tokens` |
| **Output tokens** | `usage.output_tokens` | `usage.output_tokens` |
| **Cache tokens** | `usage.cache_read_input_tokens`, `usage.cache_creation_input_tokens` | `usage.input_tokens_details.cached_tokens` |
| **Thinking tokens** | Not separately reported | `usage.output_tokens_details.reasoning_tokens` |
