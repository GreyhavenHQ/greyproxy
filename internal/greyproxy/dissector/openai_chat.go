package dissector

// OpenAI Chat Completions API dissector (/v1/chat/completions).
//
// Handles traffic from:
//   - Aider via OpenRouter (non-streaming, stream: false)
//   - OpenCode via OpenRouter (streaming with tools)
//   - OpenCode via LiteLLM (streaming with tools)
//   - Any client using /v1/chat/completions on any host
//
// Request body structure:
//   - model: string
//   - messages[]: array of {role, content} with roles: system, user, assistant, tool
//   - tools[]: array of {type: "function", function: {name, description, parameters}}
//   - stream: bool
//   - prompt_cache_key: string (optional, OpenRouter pass-through)
//
// Response (non-streaming): JSON with choices[0].message
// Response (streaming): SSE data: lines with choices[0].delta, terminated by data: [DONE]

import (
	"encoding/json"
	"strings"
)

// OpenAIChatDissector parses OpenAI Chat Completions API transactions.
type OpenAIChatDissector struct{}

func (d *OpenAIChatDissector) Name() string { return "openai-chat" }
func (d *OpenAIChatDissector) Description() string {
	return "OpenAI Chat Completions API, also used by LiteLLM, Ollama, and other compatible endpoints"
}

// CanHandle matches known chat completions hosts. Custom/self-hosted endpoints
// (LiteLLM, Ollama, etc.) are handled via the EndpointRegistry, not here.
func (d *OpenAIChatDissector) CanHandle(url, method, host string) bool {
	if method != "POST" {
		return false
	}
	// Only match known hosts as fallback. User-added hosts are routed
	// through the EndpointRegistry -> FindDissectorByName("openai-chat").
	switch host {
	case "api.openai.com", "openrouter.ai":
		// ok
	default:
		return false
	}
	base := url
	if i := strings.IndexByte(url, '?'); i >= 0 {
		base = url[:i]
	}
	return strings.HasSuffix(base, "/chat/completions")
}

func (d *OpenAIChatDissector) Extract(input ExtractionInput) (*ExtractionResult, error) {
	// Determine provider from host: OpenRouter traffic is "openrouter",
	// api.openai.com is "openai", everything else defaults to "openai".
	provider := "openai"
	switch input.Host {
	case "openrouter.ai":
		provider = "openrouter"
	}
	result := &ExtractionResult{Provider: provider}

	var body struct {
		Model          string            `json:"model"`
		Messages       []json.RawMessage `json:"messages"`
		Tools          []json.RawMessage `json:"tools"`
		PromptCacheKey string            `json:"prompt_cache_key"`
		Stream         *bool             `json:"stream"`
	}

	if len(input.RequestBody) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(input.RequestBody, &body); err != nil {
		return result, nil
	}

	// Session ID from prompt_cache_key (OpenRouter pass-through)
	result.SessionID = body.PromptCacheKey

	// Model
	result.Model = body.Model
	if result.Model == "" {
		result.Model = "unknown"
	}

	// Tools
	for _, raw := range body.Tools {
		var tool struct {
			Type     string `json:"type"`
			Function struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"function"`
		}
		if json.Unmarshal(raw, &tool) == nil && tool.Function.Name != "" {
			result.Tools = append(result.Tools, Tool{
				Name:        tool.Function.Name,
				Description: tool.Function.Description,
			})
		}
	}

	// Messages
	for _, raw := range body.Messages {
		var probe struct {
			Role       string            `json:"role"`
			Content    any               `json:"content"`
			ToolCalls  []json.RawMessage `json:"tool_calls"`
			ToolCallID string            `json:"tool_call_id"`
		}
		if json.Unmarshal(raw, &probe) != nil {
			continue
		}

		switch probe.Role {
		case "system":
			text := extractChatContent(raw)
			if text != "" {
				result.SystemBlocks = append(result.SystemBlocks, SystemBlock{
					Type: "text",
					Text: text,
				})
			}

		case "user":
			text := extractChatContent(raw)
			m := Message{Role: "user"}
			if text != "" {
				m.Content = []ContentBlock{{Type: "text", Text: text}}
			}
			result.Messages = append(result.Messages, m)
			result.MessageCount++

		case "assistant":
			m := Message{Role: "assistant"}

			// Text content
			text := extractChatContent(raw)
			if text != "" {
				m.Content = append(m.Content, ContentBlock{Type: "text", Text: text})
			}

			// Tool calls
			for _, tcRaw := range probe.ToolCalls {
				var tc struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				}
				if json.Unmarshal(tcRaw, &tc) != nil {
					continue
				}
				cb := ContentBlock{
					Type: "tool_use",
					Name: tc.Function.Name,
					ID:   tc.ID,
				}
				// Parse arguments for summary
				var argsMap map[string]any
				if json.Unmarshal([]byte(tc.Function.Arguments), &argsMap) == nil {
					cb.ToolSummary = ExtractToolSummary(tc.Function.Name, argsMap)
				}
				args := tc.Function.Arguments
				if len(args) > 300 {
					args = args[:300]
				}
				cb.Input = args
				m.Content = append(m.Content, cb)
			}

			if len(m.Content) > 0 {
				result.Messages = append(result.Messages, m)
				result.MessageCount++
			}

		case "tool":
			// Tool result
			text := extractChatContent(raw)
			if len(text) > 500 {
				text = text[:500]
			}
			cb := ContentBlock{
				Type:      "tool_result",
				ToolUseID: probe.ToolCallID,
				Content:   text,
			}
			result.Messages = append(result.Messages, Message{
				Role:    "user",
				Content: []ContentBlock{cb},
			})
			result.MessageCount++
		}
	}

	// Parse response
	isStreaming := body.Stream != nil && *body.Stream
	if len(input.ResponseBody) > 0 {
		if isStreaming && strings.Contains(input.ResponseCT, "text/event-stream") {
			result.SSEResponse = extractChatStreamingResponse(input.ResponseBody)
		} else if !isStreaming {
			result.SSEResponse = extractChatNonStreamingResponse(input.ResponseBody)
		}
	}

	return result, nil
}

// extractChatContent gets text content from a chat message.
// Content can be a string or an array of typed blocks.
func extractChatContent(raw json.RawMessage) string {
	var asStr struct {
		Content string `json:"content"`
	}
	if json.Unmarshal(raw, &asStr) == nil && asStr.Content != "" {
		return asStr.Content
	}

	var asList struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &asList) == nil {
		var parts []string
		for _, b := range asList.Content {
			if (b.Type == "text" || b.Type == "") && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// extractChatStreamingResponse parses streaming SSE response from chat completions.
func extractChatStreamingResponse(body []byte) *SSEResponseData {
	chunks := ParseSSEDataOnly(string(body))
	if len(chunks) == 0 {
		return nil
	}

	var textParts []string
	var toolCalls []ToolCall

	for _, chunk := range chunks {
		var data struct {
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(chunk), &data) != nil || len(data.Choices) == 0 {
			continue
		}
		delta := data.Choices[0].Delta

		if delta.Content != "" {
			textParts = append(textParts, delta.Content)
		}

		for _, tc := range delta.ToolCalls {
			// Extend or create tool call
			for len(toolCalls) <= tc.Index {
				toolCalls = append(toolCalls, ToolCall{})
			}
			if tc.Function.Name != "" {
				toolCalls[tc.Index].Tool = tc.Function.Name
			}
			if tc.ID != "" {
				toolCalls[tc.Index].ToolUseID = tc.ID
			}
			if tc.Function.Arguments != "" {
				toolCalls[tc.Index].InputPreview += tc.Function.Arguments
			}
		}
	}

	if len(textParts) == 0 && len(toolCalls) == 0 {
		return nil
	}

	// Generate summaries and truncate
	for i := range toolCalls {
		if len(toolCalls[i].InputPreview) > 200 {
			var argsMap map[string]any
			if json.Unmarshal([]byte(toolCalls[i].InputPreview), &argsMap) == nil {
				toolCalls[i].ToolSummary = ExtractToolSummary(toolCalls[i].Tool, argsMap)
			}
			toolCalls[i].InputPreview = toolCalls[i].InputPreview[:200]
		} else if toolCalls[i].InputPreview != "" {
			var argsMap map[string]any
			if json.Unmarshal([]byte(toolCalls[i].InputPreview), &argsMap) == nil {
				toolCalls[i].ToolSummary = ExtractToolSummary(toolCalls[i].Tool, argsMap)
			}
		}
	}

	result := &SSEResponseData{}
	if len(textParts) > 0 {
		result.Text = strings.Join(textParts, "")
	}
	if len(toolCalls) > 0 {
		result.ToolCalls = toolCalls
	}
	return result
}

// extractChatNonStreamingResponse parses a non-streaming chat completions response.
func extractChatNonStreamingResponse(body []byte) *SSEResponseData {
	var resp struct {
		Choices []struct {
			Message struct {
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
	}
	if json.Unmarshal(body, &resp) != nil || len(resp.Choices) == 0 {
		return nil
	}

	msg := resp.Choices[0].Message
	result := &SSEResponseData{}

	if msg.Content != "" {
		result.Text = msg.Content
	}

	for _, tc := range msg.ToolCalls {
		call := ToolCall{
			Tool:      tc.Function.Name,
			ToolUseID: tc.ID,
		}
		args := tc.Function.Arguments
		var argsMap map[string]any
		if json.Unmarshal([]byte(args), &argsMap) == nil {
			call.ToolSummary = ExtractToolSummary(tc.Function.Name, argsMap)
		}
		if len(args) > 200 {
			args = args[:200]
		}
		call.InputPreview = args
		result.ToolCalls = append(result.ToolCalls, call)
	}

	if result.Text == "" && len(result.ToolCalls) == 0 {
		return nil
	}
	return result
}

func init() {
	Register(&OpenAIChatDissector{})
}
