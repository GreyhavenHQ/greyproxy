package dissector

// Anthropic API behavior (as of 2026-03-13):
//
// Endpoint: POST https://api.anthropic.com/v1/messages (with optional ?beta=true)
//
// Request: JSON body with fields:
//   - model: string (e.g. "claude-opus-4-6")
//   - messages: array of {role, content} objects
//   - system: array of {type: "text", text: "..."} blocks
//   - tools: array of tool definitions
//   - metadata: {user_id: "user_HASH_account_UUID_session_UUID"}
//   - max_tokens, thinking, output_config, stream: various options
//
// Response: SSE stream (Content-Type: text/event-stream)
//   - content_block_start: signals new content block (text, tool_use, thinking)
//   - content_block_delta: incremental content (text_delta, thinking_delta)
//   - message_stop: end of response
//
// Session ID extraction:
//   metadata.user_id contains "session_UUID" where UUID is a 36-char hex UUID.
//   Pattern: user_HASH_account_UUID_session_UUID
//
// Thread classification (by system prompt length):
//   - >10K chars: main conversation (Claude Code primary)
//   - >1K chars: subagent invocation
//   - >100 chars, <=2 tools: MCP-style utility (discarded)
//   - <=100 chars: utility (discarded)

import (
	"encoding/json"
	"regexp"
	"strings"
)

var sessionIDPattern = regexp.MustCompile(`session_([a-f0-9-]{36})`)

// AnthropicDissector parses Anthropic Messages API transactions.
type AnthropicDissector struct{}

func (d *AnthropicDissector) Name() string { return "anthropic" }

func (d *AnthropicDissector) CanHandle(url, method, host string) bool {
	if method != "POST" {
		return false
	}
	// Match https://api.anthropic.com/v1/messages with optional query params
	base := url
	if i := strings.IndexByte(url, '?'); i >= 0 {
		base = url[:i]
	}
	return base == "https://api.anthropic.com/v1/messages"
}

func (d *AnthropicDissector) Extract(input ExtractionInput) (*ExtractionResult, error) {
	result := &ExtractionResult{}

	// Parse request body
	var body struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
		System   []json.RawMessage `json:"system"`
		Tools    []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}

	if len(input.RequestBody) > 0 {
		if err := json.Unmarshal(input.RequestBody, &body); err != nil {
			// If we can't parse the body, try regex for session ID
			result.SessionID = extractSessionIDFromRaw(string(input.RequestBody))
			result.Model = extractModelFromRaw(string(input.RequestBody))
			return result, nil
		}
	} else {
		return result, nil
	}

	// Session ID
	if m := sessionIDPattern.FindStringSubmatch(body.Metadata.UserID); len(m) > 1 {
		result.SessionID = m[1]
	} else {
		result.SessionID = extractSessionIDFromRaw(string(input.RequestBody))
	}

	// Model
	result.Model = body.Model
	if result.Model == "" {
		result.Model = "unknown"
	}

	// Messages
	result.MessageCount = len(body.Messages)
	for _, msg := range body.Messages {
		m := Message{Role: msg.Role}
		switch content := msg.Content.(type) {
		case string:
			m.RawContent = content
			m.Content = []ContentBlock{{Type: "text", Text: content}}
		case []any:
			for _, block := range content {
				bmap, ok := block.(map[string]any)
				if !ok {
					continue
				}
				cb := parseContentBlock(bmap)
				m.Content = append(m.Content, cb)
			}
		}
		result.Messages = append(result.Messages, m)
	}

	// System blocks
	for _, raw := range body.System {
		var sb SystemBlock
		if json.Unmarshal(raw, &sb) == nil && sb.Text != "" {
			result.SystemBlocks = append(result.SystemBlocks, sb)
		}
	}

	// Tools
	for _, t := range body.Tools {
		result.Tools = append(result.Tools, Tool{Name: t.Name, Description: t.Description})
	}

	// Parse SSE response
	if strings.Contains(input.ResponseCT, "text/event-stream") && len(input.ResponseBody) > 0 {
		events := ParseSSE(string(input.ResponseBody))
		result.SSEResponse = ExtractResponseFromSSE(events)
	}

	return result, nil
}

func parseContentBlock(bmap map[string]any) ContentBlock {
	cb := ContentBlock{}
	cb.Type, _ = bmap["type"].(string)

	switch cb.Type {
	case "text":
		cb.Text, _ = bmap["text"].(string)
	case "tool_use":
		cb.Name, _ = bmap["name"].(string)
		cb.ID, _ = bmap["id"].(string)
		if input, ok := bmap["input"]; ok {
			if b, err := json.Marshal(input); err == nil {
				s := string(b)
				if len(s) > 300 {
					s = s[:300]
				}
				cb.Input = s
			}
		}
	case "tool_result":
		cb.ToolUseID, _ = bmap["tool_use_id"].(string)
		cb.IsError, _ = bmap["is_error"].(bool)
		switch rc := bmap["content"].(type) {
		case string:
			if len(rc) > 500 {
				rc = rc[:500]
			}
			cb.Content = rc
		case []any:
			var parts []string
			for _, item := range rc {
				if m, ok := item.(map[string]any); ok {
					if t, _ := m["type"].(string); t == "text" {
						if text, ok := m["text"].(string); ok {
							parts = append(parts, text)
						}
					}
				}
			}
			joined := strings.Join(parts, "\n")
			if len(joined) > 500 {
				joined = joined[:500]
			}
			cb.Content = joined
		}
	case "thinking":
		cb.Thinking, _ = bmap["thinking"].(string)
	}
	return cb
}

func extractSessionIDFromRaw(body string) string {
	if m := sessionIDPattern.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return ""
}

var modelPattern = regexp.MustCompile(`"model":"([^"]+)"`)

func extractModelFromRaw(body string) string {
	if m := modelPattern.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return "unknown"
}

// SystemPromptLength returns the total length of system prompt text blocks.
func SystemPromptLength(blocks []SystemBlock) int {
	total := 0
	for _, b := range blocks {
		total += len(b.Text)
	}
	return total
}

// ClassifyThread determines if a request represents a main conversation,
// subagent, MCP utility, or plain utility based on system prompt size and tool count.
func ClassifyThread(systemBlocks []SystemBlock, toolCount int) string {
	sysLen := SystemPromptLength(systemBlocks)
	if sysLen > 10000 {
		return "main"
	}
	if sysLen > 1000 {
		return "subagent"
	}
	if sysLen > 100 && toolCount <= 2 {
		return "mcp"
	}
	return "utility"
}
