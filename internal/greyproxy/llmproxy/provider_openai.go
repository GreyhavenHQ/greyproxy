package llmproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

)

func init() {
	RegisterBackend("openai", newOpenAI)
	RegisterBackend("openai-compat", newOpenAI)
	RegisterBackend("openrouter", newOpenRouter)
}

// openaiProvider implements the OpenAI Chat Completions wire format. It
// is also used for any OpenAI-compatible upstream (Ollama, LM Studio,
// vLLM, LiteLLM-as-upstream, OpenRouter, …) — they all speak the same
// schema and only differ in base URL and (optionally) auth header style.
type openaiProvider struct {
	name    string // "openai" | "openai-compat" | "openrouter"
	baseURL string
	apiKey  string
	headers map[string]string // extra headers merged at request time
}

func newOpenAI(baseURL, apiKey string, metadata map[string]string) (Backend, error) {
	p := &openaiProvider{
		name:    "openai",
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
	}
	if metadata != nil {
		hdr := map[string]string{}
		for k, v := range metadata {
			if strings.HasPrefix(k, "header.") {
				hdr[strings.TrimPrefix(k, "header.")] = v
			}
		}
		if len(hdr) > 0 {
			p.headers = hdr
		}
	}
	return p, nil
}

func newOpenRouter(baseURL, apiKey string, metadata map[string]string) (Backend, error) {
	if baseURL == "" {
		baseURL = "https://openrouter.ai/api/v1"
	}
	p, _ := newOpenAI(baseURL, apiKey, metadata)
	op := p.(*openaiProvider)
	op.name = "openrouter"
	return op, nil
}

func (p *openaiProvider) Name() string { return p.name }

func (p *openaiProvider) Validate() error {
	if p.baseURL == "" {
		return fmt.Errorf("openai: base_url required")
	}
	return nil
}

// BuildRequest serialises the IR to the OpenAI Chat Completions wire
// format. For Phase 1 we cover the fields most clients send: model,
// messages (text/tool blocks), temperature, max_tokens, stream,
// response_format, tools, tool_choice. Provider-specific extensions
// (`reasoning_effort`, `prompt_cache_key`, etc.) land later.
func (p *openaiProvider) BuildRequest(ctx context.Context, ir *ChatRequest, modelID string) (*http.Request, error) {
	if modelID == "" {
		return nil, fmt.Errorf("openai: empty model id")
	}

	body := map[string]any{
		"model":    modelID,
		"messages": encodeMessages(ir.Messages),
	}
	if ir.Stream {
		body["stream"] = true
	}
	if ir.Temperature != nil {
		body["temperature"] = *ir.Temperature
	}
	if ir.MaxTokens != nil {
		body["max_tokens"] = *ir.MaxTokens
	}
	if rf := ir.ResponseFormat; rf != nil {
		if rf.Type == "json_schema" && rf.JSONSchema != nil {
			body["response_format"] = map[string]any{
				"type":        "json_schema",
				"json_schema": rf.JSONSchema,
			}
		} else if rf.Type != "" {
			body["response_format"] = map[string]any{"type": rf.Type}
		}
	}
	if len(ir.Tools) > 0 {
		body["tools"] = encodeTools(ir.Tools)
	}
	if tc := ir.ToolChoice; tc != nil {
		body["tool_choice"] = encodeToolChoice(tc)
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}

	url := p.baseURL + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// ParseResponse decodes the JSON response into IR.
func (p *openaiProvider) ParseResponse(body []byte) (*ChatResponse, error) {
	var raw openaiChatResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	out := &ChatResponse{
		ID:       raw.ID,
		Model:    raw.Model,
		Provider: p.name,
	}
	for _, c := range raw.Choices {
		msg := Message{Role: c.Message.Role}
		if c.Message.Content != "" {
			msg.Content = []ContentBlock{{Type: "text", Text: c.Message.Content}}
		}
		for _, tc := range c.Message.ToolCalls {
			msg.Content = append(msg.Content, ContentBlock{
				Type: "tool_call",
				ToolCall: &ToolCall{
					ID:        tc.ID,
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
		out.Choices = append(out.Choices, Choice{
			Index:        c.Index,
			FinishReason: c.FinishReason,
			Message:      msg,
		})
	}
	out.Usage = Usage{
		InputTokens:  raw.Usage.PromptTokens,
		OutputTokens: raw.Usage.CompletionTokens,
	}
	if raw.Usage.PromptTokensDetails != nil {
		out.Usage.CachedTokens = raw.Usage.PromptTokensDetails.CachedTokens
	}
	if raw.Usage.CompletionTokensDetails != nil {
		out.Usage.ReasoningTokens = raw.Usage.CompletionTokensDetails.ReasoningTokens
	}
	return out, nil
}

// ParseStream walks an OpenAI SSE stream and emits StreamEvents.
// Phase 2+ will exercise this; included here to satisfy the interface
// without adding a separate stub.
func (p *openaiProvider) ParseStream(r io.Reader, out chan<- *StreamEvent) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		if payload == "[DONE]" {
			out <- &StreamEvent{Type: "done"}
			return nil
		}
		var chunk openaiStreamChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		for _, c := range chunk.Choices {
			ev := &StreamEvent{Type: "delta", Delta: &Delta{
				Role:         c.Delta.Role,
				Content:      c.Delta.Content,
				FinishReason: c.FinishReason,
			}}
			out <- ev
		}
	}
	return sc.Err()
}

// helpers -------------------------------------------------------------------

func encodeMessages(msgs []Message) []map[string]any {
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		// Collapse a single-text-block message back to a string so the
		// payload matches what clients normally send. Tool calls and
		// images use the structured form.
		entry := map[string]any{"role": m.Role}
		if m.Name != "" {
			entry["name"] = m.Name
		}
		if len(m.Content) == 1 && m.Content[0].Type == "text" {
			entry["content"] = m.Content[0].Text
		} else if len(m.Content) > 0 {
			parts := make([]map[string]any, 0, len(m.Content))
			var toolCalls []map[string]any
			for _, b := range m.Content {
				switch b.Type {
				case "text":
					parts = append(parts, map[string]any{"type": "text", "text": b.Text})
				case "image":
					if b.Image != nil {
						url := b.Image.URL
						if url == "" && b.Image.Base64 != "" {
							url = "data:" + b.Image.MimeType + ";base64," + b.Image.Base64
						}
						parts = append(parts, map[string]any{
							"type":      "image_url",
							"image_url": map[string]any{"url": url},
						})
					}
				case "tool_call":
					if b.ToolCall != nil {
						toolCalls = append(toolCalls, map[string]any{
							"id":   b.ToolCall.ID,
							"type": "function",
							"function": map[string]any{
								"name":      b.ToolCall.Name,
								"arguments": b.ToolCall.Arguments,
							},
						})
					}
				case "tool_result":
					// OpenAI represents tool results as a separate message
					// with role=tool, so they shouldn't appear here. Skip
					// defensively.
				}
			}
			if len(parts) > 0 {
				entry["content"] = parts
			}
			if len(toolCalls) > 0 {
				entry["tool_calls"] = toolCalls
			}
		}
		out = append(out, entry)
	}
	return out
}

func encodeTools(tools []Tool) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		fn := map[string]any{
			"name":        t.Name,
			"description": t.Description,
		}
		if t.Parameters != nil {
			fn["parameters"] = t.Parameters
		}
		out = append(out, map[string]any{
			"type":     "function",
			"function": fn,
		})
	}
	return out
}

func encodeToolChoice(tc *ToolChoice) any {
	switch tc.Type {
	case "auto", "none", "required":
		return tc.Type
	case "function":
		return map[string]any{
			"type":     "function",
			"function": map[string]any{"name": tc.Name},
		}
	}
	return tc.Type
}

// OpenAI wire types we decode from. Only the fields we actually consume
// are listed.
type openaiChatResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int    `json:"index"`
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Role      string `json:"role"`
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens        int `json:"prompt_tokens"`
		CompletionTokens    int `json:"completion_tokens"`
		TotalTokens         int `json:"total_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
		CompletionTokensDetails *struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
}

type openaiStreamChunk struct {
	ID      string `json:"id"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}
