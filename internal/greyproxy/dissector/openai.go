package dissector

// OpenAI Responses API dissector (/v1/responses only).
//
// Analysis based on captured traffic from OpenCode (opencode/1.2.6) using
// gpt-5.1 and gpt-5-nano, March 2026.
//
// Endpoint: POST https://api.openai.com/v1/responses
//
// Request body structure:
//   - model: string (e.g. "gpt-5.1", "gpt-5-nano")
//   - input: array of heterogeneous items (NOT uniform {role, content} like Anthropic)
//     - {role: "developer", content: string}         -- system prompt
//     - {role: "user", content: [{type: "input_text", text: ...}]}  -- user message
//     - {type: "reasoning", encrypted_content: ...}  -- opaque reasoning block
//     - {type: "function_call", call_id, name, arguments}   -- tool invocation
//     - {type: "function_call_output", call_id, output}     -- tool result
//   - tools: array of {type: "function", name, description, parameters, strict}
//   - prompt_cache_key: string like "ses_XXX" (serves as session ID)
//   - reasoning: {effort, summary}
//   - stream: bool (always true in observed traffic)
//
// Response: SSE stream (text/event-stream) with events:
//   - response.created, response.in_progress   -- lifecycle
//   - response.output_item.added               -- new output item (reasoning, message, function_call)
//   - response.output_text.delta / .done       -- streamed text output
//   - response.function_call_arguments.delta / .done  -- streamed tool call args
//   - response.reasoning_summary_text.delta / .done   -- reasoning summary
//   - response.completed                       -- final event with usage stats
//
// Session ID: extracted from prompt_cache_key ("ses_XXX" prefix).
// Utility requests (title generation) use gpt-5-nano, no tools, no cache key.
//
// This does NOT cover /v1/chat/completions; that will be a separate dissector
// once traffic is collected.

import (
	"encoding/json"
	"strings"
)

// OpenAIDissector parses OpenAI Responses API (/v1/responses) transactions.
type OpenAIDissector struct{}

func (d *OpenAIDissector) Name() string        { return "openai" }
func (d *OpenAIDissector) Description() string { return "OpenAI Responses API (/v1/responses)" }

func (d *OpenAIDissector) CanHandle(url, method, host string) bool {
	if method != "POST" {
		return false
	}
	base := url
	if i := strings.IndexByte(url, '?'); i >= 0 {
		base = url[:i]
	}
	return base == "https://api.openai.com/v1/responses"
}

func (d *OpenAIDissector) Extract(input ExtractionInput) (*ExtractionResult, error) {
	result := &ExtractionResult{Provider: d.Name()}

	var body struct {
		Model string            `json:"model"`
		Input []json.RawMessage `json:"input"`
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
		PromptCacheKey string `json:"prompt_cache_key"`
	}

	if len(input.RequestBody) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(input.RequestBody, &body); err != nil {
		return result, nil
	}

	// Session ID from prompt_cache_key
	result.SessionID = body.PromptCacheKey

	// Model
	result.Model = body.Model
	if result.Model == "" {
		result.Model = "unknown"
	}

	// Tools
	for _, t := range body.Tools {
		result.Tools = append(result.Tools, Tool{Name: t.Name, Description: t.Description})
	}

	// Parse input items into Messages and SystemBlocks
	for _, raw := range body.Input {
		var probe struct {
			Role    string `json:"role"`
			Type    string `json:"type"`
			Content any    `json:"content"`
		}
		if json.Unmarshal(raw, &probe) != nil {
			continue
		}

		switch {
		case probe.Role == "developer":
			// System prompt
			text := extractOpenAIText(raw)
			if text != "" {
				result.SystemBlocks = append(result.SystemBlocks, SystemBlock{
					Type: "text",
					Text: text,
				})
			}

		case probe.Role == "user":
			// User message
			m := Message{Role: "user"}
			text := extractOpenAIInputTextBlocks(raw)
			if text != "" {
				m.Content = []ContentBlock{{Type: "text", Text: text}}
			}
			result.Messages = append(result.Messages, m)
			result.MessageCount++

		case probe.Type == "function_call":
			// Tool use (part of assistant turn)
			var fc struct {
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}
			_ = json.Unmarshal(raw, &fc)

			cb := ContentBlock{
				Type: "tool_use",
				Name: fc.Name,
				ID:   fc.CallID,
			}
			// Parse arguments for summary
			var argsMap map[string]any
			if json.Unmarshal([]byte(fc.Arguments), &argsMap) == nil {
				cb.ToolSummary = ExtractToolSummary(fc.Name, argsMap)
			}
			if len(fc.Arguments) > 300 {
				cb.Input = fc.Arguments[:300]
			} else {
				cb.Input = fc.Arguments
			}

			// Attach to an assistant message (create one if needed, or append to last)
			result.Messages = appendToAssistant(result.Messages, cb)
			result.MessageCount++

		case probe.Type == "function_call_output":
			// Tool result
			var fco struct {
				CallID string `json:"call_id"`
				Output string `json:"output"`
			}
			_ = json.Unmarshal(raw, &fco)

			content := fco.Output
			if len(content) > 500 {
				content = content[:500]
			}
			cb := ContentBlock{
				Type:      "tool_result",
				ToolUseID: fco.CallID,
				Content:   content,
			}
			result.Messages = append(result.Messages, Message{
				Role:    "user",
				Content: []ContentBlock{cb},
			})
			result.MessageCount++

		case probe.Type == "reasoning":
			// Opaque reasoning block; skip (encrypted)

		case probe.Type == "message":
			// Assistant message echoed back in input
			var msg struct {
				Role    string `json:"role"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			}
			_ = json.Unmarshal(raw, &msg)
			m := Message{Role: msg.Role}
			for _, c := range msg.Content {
				if c.Type == "output_text" && c.Text != "" {
					m.Content = append(m.Content, ContentBlock{Type: "text", Text: c.Text})
				}
			}
			if len(m.Content) > 0 {
				result.Messages = append(result.Messages, m)
				result.MessageCount++
			}
		}
	}

	// Parse SSE response
	if strings.Contains(input.ResponseCT, "text/event-stream") && len(input.ResponseBody) > 0 {
		events := ParseSSE(string(input.ResponseBody))
		result.SSEResponse = extractOpenAIResponseFromSSE(events)
	}

	return result, nil
}

// extractOpenAIText gets the text content from a developer or user message.
// Content can be a plain string or a list of blocks.
func extractOpenAIText(raw json.RawMessage) string {
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
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// extractOpenAIInputTextBlocks extracts text from user messages with input_text blocks.
func extractOpenAIInputTextBlocks(raw json.RawMessage) string {
	var msg struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &msg) == nil {
		var parts []string
		for _, b := range msg.Content {
			if (b.Type == "input_text" || b.Type == "text") && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}

	// Fallback: plain string content
	var plain struct {
		Content string `json:"content"`
	}
	if json.Unmarshal(raw, &plain) == nil {
		return plain.Content
	}
	return ""
}

// appendToAssistant appends a tool_use block to the last assistant message,
// or creates a new assistant message if the last one isn't an assistant.
func appendToAssistant(messages []Message, cb ContentBlock) []Message {
	if len(messages) > 0 && messages[len(messages)-1].Role == "assistant" {
		messages[len(messages)-1].Content = append(messages[len(messages)-1].Content, cb)
		return messages
	}
	return append(messages, Message{
		Role:    "assistant",
		Content: []ContentBlock{cb},
	})
}

// extractOpenAIResponseFromSSE builds an SSEResponseData from OpenAI SSE events.
func extractOpenAIResponseFromSSE(events []SSEEvent) *SSEResponseData {
	if len(events) == 0 {
		return nil
	}

	var textParts []string
	var toolCalls []ToolCall

	// Track function calls by output_index to build complete tool calls
	type pendingFC struct {
		name      string
		toolUseID string
	}
	pendingFCs := map[int]pendingFC{}

	for _, evt := range events {
		var data map[string]any
		if json.Unmarshal([]byte(evt.Data), &data) != nil {
			continue
		}

		switch evt.Event {
		case "response.output_text.delta":
			if delta, ok := data["delta"].(string); ok {
				textParts = append(textParts, delta)
			}

		case "response.output_item.added":
			item, ok := data["item"].(map[string]any)
			if !ok {
				continue
			}
			itemType, _ := item["type"].(string)
			outIdx := int(getFloat(data, "output_index"))

			if itemType == "function_call" {
				name, _ := item["name"].(string)
				callID, _ := item["call_id"].(string)
				if name == "" {
					name = "unknown"
				}
				pendingFCs[outIdx] = pendingFC{name: name, toolUseID: callID}
				toolCalls = append(toolCalls, ToolCall{
					Tool:      name,
					ToolUseID: callID,
				})
			}

		case "response.function_call_arguments.done":
			args, _ := data["arguments"].(string)
			itemID, _ := data["item_id"].(string)
			// Find and update the matching tool call
			for i := range toolCalls {
				if toolCalls[i].ToolUseID != "" {
					// Match by item_id prefix (fc_ IDs map to call_ IDs)
					// Or just update the last one with matching tool
					if matchToolCallID(toolCalls[i].ToolUseID, itemID) || i == len(toolCalls)-1 {
						if len(args) > 200 {
							toolCalls[i].InputPreview = args[:200]
						} else {
							toolCalls[i].InputPreview = args
						}
						// Generate summary from parsed args
						var argsMap map[string]any
						if json.Unmarshal([]byte(args), &argsMap) == nil {
							toolCalls[i].ToolSummary = ExtractToolSummary(toolCalls[i].Tool, argsMap)
						}
						break
					}
				}
			}
		}
	}

	if len(textParts) == 0 && len(toolCalls) == 0 {
		return nil
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

func getFloat(m map[string]any, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

// matchToolCallID checks if a call_id and an item fc_ id refer to the same call.
// OpenAI uses call_XXX in input and fc_XXX in SSE events for the same logical call.
// We match by checking if both exist (exact match is rare across formats).
func matchToolCallID(callID, itemID string) bool {
	// In response SSE, item_id is fc_XXX while call_id from the request is call_XXX
	// Within a single response, they correlate by output_index order.
	// Simple heuristic: just match the last tool call added.
	return callID != "" && itemID != ""
}
