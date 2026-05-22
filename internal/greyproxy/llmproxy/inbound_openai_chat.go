// inbound_*.go hold the wire-format adapters for each dialect. holds the wire-format adapters for each dialect the
// gateway accepts. Each file pairs a Decode (wire -> IR) and Encode
// (IR -> wire) function. Decoders normalise to the canonical IR; encoders
// emit the exact shape the inbound client expects so the proxy is
// indistinguishable from a real upstream.
//
// openai_chat.go covers POST /v1/chat/completions plus the matching
// Phase 1 helpers /v1/models and error envelopes.
package llmproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

)

// DecodeOpenAIChat reads the request body as OpenAI Chat Completions
// JSON and returns the canonical IR. RawHeaders, InboundShape and
// InboundRawPath are populated so downstream guardrails and the audit
// log see the original context.
func DecodeOpenAIChat(req *http.Request) (*ChatRequest, error) {
	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	_ = req.Body.Close()

	var w openaiChatWire
	if err := json.Unmarshal(buf, &w); err != nil {
		return nil, fmt.Errorf("decode chat completions body: %w", err)
	}
	ir := &ChatRequest{
		Model:          w.Model,
		Stream:         w.Stream,
		InboundShape:   ShapeOpenAIChat,
		InboundRawPath: req.URL.Path,
		RawHeaders:     req.Header.Clone(),
	}
	if w.Temperature != nil {
		v := *w.Temperature
		ir.Temperature = &v
	}
	if w.MaxTokens != nil {
		v := *w.MaxTokens
		ir.MaxTokens = &v
	} else if w.MaxCompletionTokens != nil {
		v := *w.MaxCompletionTokens
		ir.MaxTokens = &v
	}
	if w.ResponseFormat != nil {
		ir.ResponseFormat = &ResponseFormat{
			Type:       w.ResponseFormat.Type,
			JSONSchema: w.ResponseFormat.JSONSchema,
		}
	}
	for _, m := range w.Messages {
		ir.Messages = append(ir.Messages, decodeOpenAIMessage(m))
	}
	for _, t := range w.Tools {
		ir.Tools = append(ir.Tools, Tool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Parameters:  t.Function.Parameters,
		})
	}
	if w.ToolChoice != nil {
		ir.ToolChoice = decodeOpenAIToolChoice(w.ToolChoice)
	}
	return ir, nil
}

func decodeOpenAIMessage(m openaiWireMessage) Message {
	out := Message{Role: m.Role, Name: m.Name}

	// Content is either a string, an array of parts, or null (common for
	// assistant messages that carry only tool_calls). A nil content must
	// still fall through to the tool_calls handling below, so we only
	// skip the content switch — never return early.
	switch c := m.Content.(type) {
	case string:
		if c != "" {
			out.Content = append(out.Content, ContentBlock{Type: "text", Text: c})
		}
	case []any:
		for _, raw := range c {
			block, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := block["type"].(string)
			switch typ {
			case "text":
				if s, ok := block["text"].(string); ok {
					out.Content = append(out.Content, ContentBlock{Type: "text", Text: s})
				}
			case "image_url":
				if iu, ok := block["image_url"].(map[string]any); ok {
					url, _ := iu["url"].(string)
					out.Content = append(out.Content, ContentBlock{
						Type:  "image",
						Image: &ImageRef{URL: url},
					})
				}
			}
		}
	}

	// Assistant-side tool_calls come as a sibling field, not inside content.
	for _, tc := range m.ToolCalls {
		out.Content = append(out.Content, ContentBlock{
			Type: "tool_call",
			ToolCall: &ToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			},
		})
	}

	// role=tool with tool_call_id is the result of a previous tool call.
	if m.Role == "tool" && m.ToolCallID != "" {
		text := ""
		if s, ok := m.Content.(string); ok {
			text = s
		}
		out.Content = []ContentBlock{{
			Type: "tool_result",
			ToolResult: &ToolResult{
				ToolUseID: m.ToolCallID,
				Content:   text,
			},
		}}
	}
	return out
}

func decodeOpenAIToolChoice(raw any) *ToolChoice {
	switch v := raw.(type) {
	case string:
		return &ToolChoice{Type: v}
	case map[string]any:
		typ, _ := v["type"].(string)
		tc := &ToolChoice{Type: typ}
		if fn, ok := v["function"].(map[string]any); ok {
			tc.Name, _ = fn["name"].(string)
		}
		return tc
	}
	return nil
}

// EncodeOpenAIChat writes a ChatResponse to the http.ResponseWriter as
// the OpenAI Chat Completions JSON shape. Caller is responsible for
// writing the HTTP status; this only sets Content-Type and body.
func EncodeOpenAIChat(w http.ResponseWriter, resp *ChatResponse) error {
	w.Header().Set("Content-Type", "application/json")

	wire := openaiChatResponseWire{
		ID:      resp.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   resp.Model,
	}
	for _, c := range resp.Choices {
		msg := openaiWireMessageOut{Role: c.Message.Role}
		if len(c.Message.Content) == 1 && c.Message.Content[0].Type == "text" {
			msg.Content = c.Message.Content[0].Text
		} else {
			parts := []map[string]any{}
			for _, b := range c.Message.Content {
				switch b.Type {
				case "text":
					parts = append(parts, map[string]any{"type": "text", "text": b.Text})
				case "tool_call":
					if b.ToolCall != nil {
						msg.ToolCalls = append(msg.ToolCalls, openaiWireToolCallOut{
							ID:   b.ToolCall.ID,
							Type: "function",
							Function: openaiWireToolFnOut{
								Name:      b.ToolCall.Name,
								Arguments: b.ToolCall.Arguments,
							},
						})
					}
				}
			}
			if len(parts) > 0 {
				msg.Content = parts
			}
		}
		wire.Choices = append(wire.Choices, openaiChoiceOut{
			Index:        c.Index,
			FinishReason: c.FinishReason,
			Message:      msg,
		})
	}
	wire.Usage = openaiUsageOut{
		PromptTokens:     resp.Usage.InputTokens,
		CompletionTokens: resp.Usage.OutputTokens,
		TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
	}
	return json.NewEncoder(w).Encode(wire)
}

// EncodeOpenAIChatError emits the OpenAI error envelope shape.
func EncodeOpenAIChatError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    errorTypeForStatus(status),
			"code":    code,
		},
	})
}

func errorTypeForStatus(status int) string {
	switch {
	case status >= 500:
		return "server_error"
	case status == 401 || status == 403:
		return "permission_error"
	case status == 404:
		return "not_found_error"
	default:
		return "invalid_request_error"
	}
}

// EncodeOpenAIModelsList emits a /v1/models response. The proxy lists
// configured aliases; each id maps to (provider, model_id) on dispatch.
func EncodeOpenAIModelsList(w http.ResponseWriter, ids []string) error {
	w.Header().Set("Content-Type", "application/json")
	now := time.Now().Unix()
	type modelOut struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}
	out := struct {
		Object string     `json:"object"`
		Data   []modelOut `json:"data"`
	}{Object: "list"}
	for _, id := range ids {
		out.Data = append(out.Data, modelOut{
			ID: id, Object: "model", Created: now, OwnedBy: "greyproxy",
		})
	}
	return json.NewEncoder(w).Encode(out)
}

// EncodeOpenAIModel emits a single model object for /v1/models/:id.
func EncodeOpenAIModel(w http.ResponseWriter, id string) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]any{
		"id":       id,
		"object":   "model",
		"created":  time.Now().Unix(),
		"owned_by": "greyproxy",
	})
}

// wire types ----------------------------------------------------------------

type openaiChatWire struct {
	Model               string              `json:"model"`
	Messages            []openaiWireMessage `json:"messages"`
	Temperature         *float64            `json:"temperature,omitempty"`
	MaxTokens           *int                `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int                `json:"max_completion_tokens,omitempty"`
	Stream              bool                `json:"stream,omitempty"`
	ResponseFormat      *openaiResponseFmt  `json:"response_format,omitempty"`
	Tools               []openaiWireTool    `json:"tools,omitempty"`
	ToolChoice          any                 `json:"tool_choice,omitempty"`
}

type openaiResponseFmt struct {
	Type       string         `json:"type"`
	JSONSchema map[string]any `json:"json_schema,omitempty"`
}

type openaiWireMessage struct {
	Role       string             `json:"role"`
	Name       string             `json:"name,omitempty"`
	Content    any                `json:"content,omitempty"`
	ToolCalls  []openaiWireToolCl `json:"tool_calls,omitempty"`
	ToolCallID string             `json:"tool_call_id,omitempty"`
}

type openaiWireToolCl struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openaiWireToolCall `json:"function"`
}

type openaiWireToolCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openaiWireTool struct {
	Type     string                 `json:"type"`
	Function openaiWireToolFunction `json:"function"`
}

type openaiWireToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// outbound (encode) ---------------------------------------------------------

type openaiChatResponseWire struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []openaiChoiceOut `json:"choices"`
	Usage   openaiUsageOut    `json:"usage"`
}

type openaiChoiceOut struct {
	Index        int                  `json:"index"`
	FinishReason string               `json:"finish_reason"`
	Message      openaiWireMessageOut `json:"message"`
}

type openaiWireMessageOut struct {
	Role      string                  `json:"role"`
	Content   any                     `json:"content,omitempty"`
	ToolCalls []openaiWireToolCallOut `json:"tool_calls,omitempty"`
}

type openaiWireToolCallOut struct {
	ID       string              `json:"id"`
	Type     string              `json:"type"`
	Function openaiWireToolFnOut `json:"function"`
}

type openaiWireToolFnOut struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openaiUsageOut struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}
