package dissector

import (
	"encoding/json"
	"strings"
)

// SSEEvent represents a single Server-Sent Event.
type SSEEvent struct {
	Event string `json:"event"`
	Data  string `json:"data"`
}

// ParseSSE parses Server-Sent Events from a response body string.
// Handles both event-prefixed format (Anthropic, OpenAI Responses) and
// data-only format (OpenAI Chat Completions, Google AI).
func ParseSSE(body string) []SSEEvent {
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "event:") && !strings.HasPrefix(body, "data:") {
		return nil
	}

	var events []SSEEvent
	var current SSEEvent
	hasData := false

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			if hasData {
				events = append(events, current)
				current = SSEEvent{}
				hasData = false
			}
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			current.Event = line[7:]
			hasData = true
		} else if strings.HasPrefix(line, "data: ") {
			data := line[6:]
			if data == "[DONE]" {
				continue
			}
			current.Data = data
			hasData = true
		}
	}
	if hasData {
		events = append(events, current)
	}
	return events
}

// ParseSSEDataOnly parses SSE streams that use only "data:" lines without
// "event:" prefixes. Used by OpenAI Chat Completions and Google AI.
// Returns the raw data strings (excluding [DONE] sentinel).
func ParseSSEDataOnly(body string) []string {
	body = strings.TrimSpace(body)
	var results []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			break
		}
		if data != "" {
			results = append(results, data)
		}
	}
	return results
}

// ExtractResponseFromSSE builds an SSEResponseData from SSE events.
// Handles Anthropic-style content_block_start / content_block_delta events.
func ExtractResponseFromSSE(events []SSEEvent) *SSEResponseData {
	if len(events) == 0 {
		return nil
	}

	var textParts []string
	var toolCalls []ToolCall
	var thinkingParts []string

	for _, evt := range events {
		var data map[string]any
		if json.Unmarshal([]byte(evt.Data), &data) != nil {
			continue
		}

		switch evt.Event {
		case "content_block_delta":
			delta, ok := data["delta"].(map[string]any)
			if !ok {
				continue
			}
			dt, _ := delta["type"].(string)
			switch dt {
			case "text_delta":
				if text, ok := delta["text"].(string); ok {
					textParts = append(textParts, text)
				}
			case "thinking_delta":
				if thinking, ok := delta["thinking"].(string); ok {
					thinkingParts = append(thinkingParts, thinking)
				}
			}
		case "content_block_start":
			cb, ok := data["content_block"].(map[string]any)
			if !ok {
				continue
			}
			cbType, _ := cb["type"].(string)
			if cbType == "tool_use" {
				name, _ := cb["name"].(string)
				id, _ := cb["id"].(string)
				if name == "" {
					name = "unknown"
				}
				toolCalls = append(toolCalls, ToolCall{
					Tool:      name,
					ToolUseID: id,
				})
			}
		}
	}

	if len(textParts) == 0 && len(toolCalls) == 0 && len(thinkingParts) == 0 {
		return nil
	}

	result := &SSEResponseData{}
	if len(textParts) > 0 {
		result.Text = strings.Join(textParts, "")
	}
	if len(toolCalls) > 0 {
		result.ToolCalls = toolCalls
	}
	if len(thinkingParts) > 0 {
		thinking := strings.Join(thinkingParts, "")
		if len(thinking) > 500 {
			thinking = thinking[:500] + "..."
		}
		result.Thinking = thinking
	}
	return result
}
