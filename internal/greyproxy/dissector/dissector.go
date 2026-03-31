package dissector

import "time"

// Dissector extracts structured LLM conversation data from HTTP transactions.
// Inspired by Wireshark's protocol dissector concept: each implementation
// knows how to parse a specific provider's API format.
type Dissector interface {
	// Name returns the provider name (e.g. "anthropic").
	Name() string

	// CanHandle returns true if this dissector can parse the given HTTP transaction.
	CanHandle(url, method, host string) bool

	// Extract parses request/response bodies and returns structured data.
	Extract(input ExtractionInput) (*ExtractionResult, error)
}

// ExtractionInput contains the raw HTTP transaction data to parse.
type ExtractionInput struct {
	TransactionID   int64
	URL             string
	Method          string
	Host            string
	RequestBody     []byte
	ResponseBody    []byte
	RequestCT       string // Content-Type of request
	ResponseCT      string // Content-Type of response
	Timestamp       time.Time
	ContainerName   string
	DurationMs      int64
}

// ExtractionResult contains structured data extracted from an HTTP transaction.
type ExtractionResult struct {
	SessionID    string
	Model        string
	Messages     []Message
	SystemBlocks []SystemBlock
	Tools        []Tool
	SSEResponse  *SSEResponseData
	MessageCount int
}

// Message represents a single message in a conversation.
type Message struct {
	Role    string         `json:"role"`
	Content []ContentBlock `json:"content"`
	// RawContent holds the original content field when it's a plain string.
	RawContent string `json:"-"`
}

// ContentBlock represents a block within a message's content array.
type ContentBlock struct {
	Type         string `json:"type"`
	Text         string `json:"text,omitempty"`
	Name         string `json:"name,omitempty"`         // tool_use: tool name
	ID           string `json:"id,omitempty"`            // tool_use: tool_use_id
	Input        string `json:"input,omitempty"`         // tool_use: JSON input (stringified)
	ToolSummary  string `json:"tool_summary,omitempty"`  // tool_use: short human-readable summary
	ToolUseID    string `json:"tool_use_id,omitempty"`   // tool_result
	Content      string `json:"content,omitempty"`       // tool_result content preview
	IsError      bool   `json:"is_error,omitempty"`      // tool_result
	Thinking     string `json:"thinking,omitempty"`      // thinking block
}

// SystemBlock represents a system prompt block.
type SystemBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Tool represents a tool definition from the request.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// SSEResponseData holds parsed assistant response from SSE stream.
type SSEResponseData struct {
	Text      string     `json:"text,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	Thinking  string     `json:"thinking,omitempty"`
}

// ToolCall represents a tool invocation from an assistant response.
type ToolCall struct {
	Tool                 string `json:"tool"`
	InputPreview         string `json:"input_preview,omitempty"`
	ToolSummary          string `json:"tool_summary,omitempty"`
	ToolUseID            string `json:"tool_use_id,omitempty"`
	ResultPreview        string `json:"result_preview,omitempty"`
	IsError              bool   `json:"is_error,omitempty"`
	LinkedConversationID string `json:"linked_conversation_id,omitempty"`
}

// --- Registry ---

var registry []Dissector

// Register adds a dissector to the global registry.
func Register(d Dissector) {
	registry = append(registry, d)
}

// FindDissector returns the first dissector that can handle the given request.
func FindDissector(url, method, host string) Dissector {
	for _, d := range registry {
		if d.CanHandle(url, method, host) {
			return d
		}
	}
	return nil
}

func init() {
	Register(&AnthropicDissector{})
}
