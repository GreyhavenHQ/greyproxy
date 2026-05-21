// Package llmproxy implements the integrated LLM proxy: a gateway that
// accepts requests in multiple LLM API dialects (OpenAI Chat Completions,
// Anthropic Messages, etc.), translates them through a canonical
// intermediate representation, routes them through provider plumbing, and
// returns the response in the dialect the client used.
//
// Phase 1 ships providers + aliases over the OpenAI Chat Completions
// dialect at the root. Streaming, the Anthropic dialect, redirects,
// guardrails, and auto routing arrive in later phases.
package llmproxy

import "net/http"

// Inbound shape identifiers. Set by decoders, read by encoders and the
// router/audit layer to make per-shape decisions.
const (
	ShapeOpenAIChat      = "openai-chat"
	ShapeOpenAIResponses = "openai-responses"
	ShapeOpenAIRealtime  = "openai-realtime"
	ShapeAnthropic       = "anthropic"
	ShapeGoogleAI        = "google-ai"
)

// ChatRequest is the canonical IR for a chat-style LLM call. Decoders
// populate it from a wire body; the router resolves Model against the
// alias table; the provider serialises it to the upstream's wire format.
type ChatRequest struct {
	Model          string
	Messages       []Message
	Tools          []Tool
	ToolChoice     *ToolChoice
	Temperature    *float64
	MaxTokens      *int
	Stream         bool
	ResponseFormat *ResponseFormat
	Reasoning      *Reasoning
	Metadata       map[string]string

	// Provenance — set by the decoder, read by the encoder and the router.
	InboundShape   string
	InboundRawPath string
	RawHeaders     http.Header
}

// Message is one entry in the conversation. Content is always a slice of
// blocks; decoders that receive a bare string normalise to a single
// text block so the encoder side never has to branch on shape.
type Message struct {
	Role    string // system | user | assistant | tool
	Name    string // optional, e.g. for tool messages
	Content []ContentBlock
}

// ContentBlock is a tagged union over the block types the IR supports.
// Only the fields matching Type are meaningful; the rest are zero.
type ContentBlock struct {
	Type       string // text | image | tool_call | tool_result | thinking
	Text       string
	Image      *ImageRef
	ToolCall   *ToolCall
	ToolResult *ToolResult
	Thinking   string
}

// ImageRef points at an image used as content. Exactly one of URL or
// Base64 is set.
type ImageRef struct {
	URL      string
	Base64   string
	MimeType string
}

// ToolCall is an assistant-emitted tool invocation. Arguments is the
// JSON-encoded argument object (the OpenAI shape — Anthropic uses an
// object, which the inbound decoder string-encodes on the way in).
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// ToolResult is the output of a tool call, posted back by the client.
type ToolResult struct {
	ToolUseID string
	Content   string
	IsError   bool
}

// Tool declares a callable tool. Parameters is the JSON-Schema object the
// model uses to decide how to call.
type Tool struct {
	Name        string
	Description string
	Parameters  map[string]any
}

// ToolChoice represents the OpenAI tool_choice field. Type is one of
// "auto", "none", "required", or "function" (with Name set).
type ToolChoice struct {
	Type string
	Name string
}

// ResponseFormat carries the OpenAI response_format directive.
type ResponseFormat struct {
	Type       string         // "text" | "json_object" | "json_schema"
	JSONSchema map[string]any // when Type=="json_schema"
}

// Reasoning unifies thinking/effort controls across dialects.
type Reasoning struct {
	Effort       string // "low" | "medium" | "high"
	BudgetTokens int
	Summary      string // "auto" | "concise" | "detailed"
}

// ChatResponse is the canonical IR for a non-streaming response.
type ChatResponse struct {
	ID       string
	Model    string // resolved backend model id
	Choices  []Choice
	Usage    Usage
	Provider string // backend that answered
}

// Choice is one of (usually one) completion choices.
type Choice struct {
	Index        int
	FinishReason string
	Message      Message
}

// Usage carries token counts. Cached/reasoning fields are optional.
type Usage struct {
	InputTokens      int
	OutputTokens     int
	CachedTokens     int
	ReasoningTokens  int
}

// StreamEvent is one item in a streaming response.
type StreamEvent struct {
	Type  string // delta | tool_call_delta | thinking_delta | done | error
	Delta *Delta
	Usage *Usage
	Error *ErrorInfo
}

// Delta is an incremental piece of an assistant message.
type Delta struct {
	Role          string
	Content       string
	ToolCallID    string
	ToolCallName  string
	ToolCallArgs  string
	Thinking      string
	FinishReason  string
}

// ErrorInfo is a structured error attached to a stream event.
type ErrorInfo struct {
	Type    string
	Message string
	Code    string
}
