# Conversation Tracking

GreyProxy intercepts LLM API traffic and reconstructs it into structured conversations. This document explains how the system works, which providers and clients are supported, and how to extend it for custom endpoints.

## How it works

Conversation tracking has three layers:

```
HTTP transaction -> EndpointRegistry -> Dissector -> ClientAdapter -> Conversation
```

1. **EndpointRegistry** looks at the request URL, host, and HTTP method to decide which dissector should parse it. This is pattern-based matching using glob rules (e.g. `api.openai.com` + `/v1/chat/completions` + `POST` -> `openai-chat`).

2. **Dissectors** parse provider-specific API formats (request body, response body, SSE streams, WebSocket frames) into a common internal representation: messages, system prompts, tools, and assistant responses.

3. **ClientAdapters** detect which coding tool generated the traffic (Claude Code, Codex, Aider, etc.) and apply client-specific logic: session grouping, thread classification (main vs. subagent vs. utility), and subagent linking.

The assembler then groups transactions into sessions, assigns them to conversations, and stores the result.

## Built-in dissectors

Each dissector handles a specific API format. The decoder name is what you use when creating endpoint rules.

### `anthropic` -- Anthropic Messages API

- **Endpoint**: `/v1/messages` on `api.anthropic.com`
- **Format**: JSON request with `model`, `system`, `messages[]` (roles: user, assistant), `tools[]`. Response is JSON or SSE stream with `content_block_delta` events.
- **Used by**: Claude Code, any tool using the Anthropic SDK directly.

### `openai` -- OpenAI Responses API

- **Endpoint**: `/v1/responses` on `api.openai.com` (HTTP POST)
- **Format**: JSON request with `model`, `instructions`, `input[]` (items with types: message, function_call, function_call_output). Response is JSON or SSE stream.
- **Used by**: Codex CLI (HTTP mode), tools using the OpenAI Responses API.

### `openai-chat` -- OpenAI Chat Completions API

- **Endpoint**: `/v1/chat/completions` on `api.openai.com`, `openrouter.ai`, or any custom host via endpoint rules
- **Format**: JSON request with `model`, `messages[]` (roles: system, user, assistant, tool), `tools[]`. Response is JSON or SSE `data:` lines with `choices[0].delta`.
- **Used by**: Aider, OpenCode, LiteLLM, Ollama, vLLM, and any OpenAI-compatible proxy or self-hosted model. This is the most common format for custom endpoints.

### `openai-ws` -- OpenAI Responses API (WebSocket)

- **Endpoint**: `/v1/responses` on `api.openai.com` (WebSocket frames)
- **Format**: Client sends `WS_REQ` frames with `{"type":"response.create", ...}`. Server sends `WS_RESP` frames with events like `response.completed` containing the full assistant response.
- **Used by**: Codex CLI (WebSocket mode). Each turn sends only the new messages (incremental), so the assembler aggregates across all frames to reconstruct the full conversation.

### `google-ai` -- Google Gemini API

- **Endpoint**: `/v1beta/models/*` on `generativelanguage.googleapis.com`
- **Format**: JSON request with `contents[]` (roles: user, model), `systemInstruction`, `tools[]`. Response is JSON with `candidates[0].content`.
- **Used by**: Gemini CLI, any tool using the Google AI SDK.

## Client detection

GreyProxy identifies which coding tool generated the traffic using a priority chain:

1. **Container name** (highest priority): When running under greywall, the process name is known (e.g. "aider", "claude", "opencode"). A lookup table maps container names to client adapters.
2. **HTTP headers**: Some clients set identifying headers (e.g. `User-Agent: opencode/...`, `X-Title: Aider`).
3. **Client hints from dissectors**: The WebSocket dissector detects Codex from `client_metadata.x-codex-turn-metadata`.
4. **Adapter fingerprinting**: Each adapter's `DetectConfidence()` inspects the extracted data (tool names, system prompt content) to claim a match. For example, Aider is detected by the phrase "expert software developer" + "diligent and tireless" in its system prompt.
5. **Provider fallback** (lowest priority): If nothing else matches, the provider name from the dissector is used as a generic client name.

## Session grouping

Transactions are grouped into conversations (sessions) using strategies that vary by client:

- **PromptCacheKeyStrategy**: Uses OpenAI's `prompt_cache_key` field as a session identifier. Used by Codex and OpenCode.
- **MessageGrowthStrategy**: Detects growing message arrays across requests as belonging to the same session. Used by OpenCode.
- **TimingStrategy**: Groups transactions within a time gap (e.g. 5 minutes). Used by Aider and Gemini CLI.
- **CompositeStrategy**: Tries multiple strategies in order. Used by OpenCode (prompt_cache_key first, then message growth).

## Thread classification

Each transaction is classified as one of:

- **main**: The primary conversation thread (user prompts, agent responses).
- **subagent**: A sub-conversation spawned by the main agent (e.g. Claude Code's `Agent` tool).
- **utility**: Non-conversation requests (title generation, embeddings, health checks). These are excluded from conversations.
- **title-gen**: Title generation requests (excluded from conversations).

The classification logic is client-specific. For example, Claude Code classifies by system prompt length and tool count; Aider marks everything as "main" since it has no subagents.

## Adding custom endpoints

### Via the UI

Go to **Settings > Conversations > Add Endpoint Rule**. You need:

- **Host pattern**: The hostname of your endpoint (e.g. `litellm.local:4000`). Supports `*` as a wildcard (e.g. `*.internal.company.com`).
- **Path pattern**: The URL path (e.g. `/v1/chat/completions`). Supports `*` as a wildcard (e.g. `/v1/*/completions`).
- **Decoder**: Which dissector to use. For most custom/self-hosted endpoints, choose `openai-chat`.
- **Method**: Usually `POST`.

After adding a rule, click **Rebuild** to reprocess existing traffic.

### Via the API

```bash
# Add a rule
curl -X POST http://localhost:43080/api/endpoint-rules \
  -H 'Content-Type: application/json' \
  -d '{
    "host_pattern": "litellm.local:4000",
    "path_pattern": "/v1/chat/completions",
    "method": "POST",
    "decoder_name": "openai-chat",
    "priority": 10,
    "enabled": true
  }'

# List all rules
curl http://localhost:43080/api/endpoint-rules

# Delete a user-defined rule
curl -X DELETE http://localhost:43080/api/endpoint-rules/42

# Trigger a rebuild after adding rules
curl -X POST http://localhost:43080/api/maintenance/rebuild-conversations
```

### Auto-detection

If you forget to add a rule, the assembler will try to auto-detect OpenAI-compatible endpoints. When it encounters a POST to an unknown host where the request body has `model` and `messages` fields, it automatically creates an `openai-chat` endpoint rule and processes the transaction. The auto-created rule appears in the UI as a custom rule.

## Implementing a custom dissector

To add support for a new API format (not OpenAI-compatible), you need to implement the `Dissector` interface in Go:

```go
package dissector

type Dissector interface {
    Name() string
    Description() string
    CanHandle(url, method, host string) bool
    Extract(input ExtractionInput) (*ExtractionResult, error)
}
```

### Step 1: Create the dissector

Create a new file in `internal/greyproxy/dissector/`, e.g. `my_provider.go`:

```go
package dissector

type MyProviderDissector struct{}

func (d *MyProviderDissector) Name() string        { return "my-provider" }
func (d *MyProviderDissector) Description() string { return "My Provider API (/v1/generate)" }

func (d *MyProviderDissector) CanHandle(url, method, host string) bool {
    // Fallback detection (used when no endpoint rule matches)
    return method == "POST" && strings.Contains(host, "my-provider.com")
}

func (d *MyProviderDissector) Extract(input ExtractionInput) (*ExtractionResult, error) {
    result := &ExtractionResult{Provider: "my-provider"}

    // Parse input.RequestBody (JSON) into result fields:
    // - result.Model (string)
    // - result.SystemBlocks ([]SystemBlock with Type + Text)
    // - result.Messages ([]Message with Role + Content)
    // - result.Tools ([]Tool with Name + Description)
    // - result.MessageCount (int)
    // - result.SessionID (string, for session grouping)

    // Parse input.ResponseBody into:
    // - result.SSEResponse (assistant text + tool calls)

    return result, nil
}

func init() {
    Register(&MyProviderDissector{})
}
```

### Step 2: Add a built-in endpoint rule (optional)

If you want the dissector to be used automatically for known hosts, add it to `builtinRules` in `internal/greyproxy/endpoint_registry.go`:

```go
var builtinRules = []EndpointRule{
    // ... existing rules ...
    {HostPattern: "api.my-provider.com", PathPattern: "/v1/generate", Method: "POST", DecoderName: "my-provider"},
}
```

### Step 3: Add a client adapter (optional)

If the provider has a specific coding tool with unique behavior (subagents, custom session grouping), create a client adapter in `internal/greyproxy/client_*.go` implementing the `ClientAdapter` interface:

```go
type ClientAdapter interface {
    Name() string
    DetectConfidence(headers http.Header, result *ExtractionResult) float64
    Scaffolding() *ScaffoldingConfig
    ClassifyThread(result *ExtractionResult) string
    SessionStrategy() SessionStrategy
    SubagentStrategy() SubagentStrategyI
    PairTransactions(entries []transactionEntry) [][]int64
}
```

Most custom endpoints work fine with the `GenericAdapter`; you only need a custom adapter if the client has distinctive behavior.

## Configuration reference

### Settings API

```
GET  /api/settings                              -- includes conversations.enabled
PUT  /api/settings {conversations:{enabled:bool}} -- toggle conversation tracking
GET  /api/endpoint-rules                        -- list all endpoint rules
POST /api/endpoint-rules                        -- create user-defined rule
PUT  /api/endpoint-rules/:id                    -- update user-defined rule
DELETE /api/endpoint-rules/:id                  -- delete user-defined rule
GET  /api/dissectors                            -- list available decoders
POST /api/maintenance/rebuild-conversations     -- trigger full rebuild
GET  /api/maintenance/status                    -- assembler version info
```

### Glob pattern syntax

Host and path patterns use simple glob matching:
- `*` matches any sequence of characters
- No other special characters (not regex)
- Examples: `*.example.com`, `/v1/*/completions`, `api.openai.com`
