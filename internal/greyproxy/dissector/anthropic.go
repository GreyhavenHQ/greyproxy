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
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var sessionIDPattern = regexp.MustCompile(`session_([a-f0-9-]{36})`)
var sessionIDJSONPattern = regexp.MustCompile(`"session_id"\s*:\s*"([a-f0-9-]{36})"`)
var sessionIDEscapedJSONPattern = regexp.MustCompile(`\\?"session_id\\?"\s*:\\?\s*\\?"([a-f0-9-]{36})\\?"`)


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
			UserID json.RawMessage `json:"user_id"`
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

	// Session ID - user_id can be a string or a JSON object with session_id field
	result.SessionID = extractSessionIDFromUserID(body.Metadata.UserID)
	if result.SessionID == "" {
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
			// Extract summary from full input before truncation
			if inputMap, ok := input.(map[string]any); ok {
				cb.ToolSummary = extractToolSummary(cb.Name, inputMap)
			}
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

// extractSessionIDFromUserID handles both the legacy string format
// ("user_HASH_account_UUID_session_UUID") and the new JSON object format
// ({"session_id": "UUID", ...}).
func extractSessionIDFromUserID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// Try as string first (legacy format or JSON-encoded object)
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		// Legacy format: "user_HASH_account_UUID_session_UUID"
		if m := sessionIDPattern.FindStringSubmatch(s); len(m) > 1 {
			return m[1]
		}
		// New format: user_id is a JSON string containing a JSON object
		// e.g. "{\"session_id\":\"UUID\",\"device_id\":\"...\"}"
		var inner struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal([]byte(s), &inner) == nil && inner.SessionID != "" {
			return inner.SessionID
		}
	}

	// Try as object with session_id field (direct JSON object, not string-encoded)
	var obj struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.SessionID != "" {
		return obj.SessionID
	}

	return ""
}

func extractSessionIDFromRaw(body string) string {
	if m := sessionIDPattern.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	// Try "session_id":"UUID" pattern (new metadata format in raw JSON)
	if m := sessionIDJSONPattern.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	// Try escaped variant: \"session_id\":\"UUID\" (string-encoded JSON in body)
	if m := sessionIDEscapedJSONPattern.FindStringSubmatch(body); len(m) > 1 {
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

// extractToolSummary produces a short human-readable summary from the full
// tool input map, before any truncation. This ensures the summary is always
// valid even when input_preview gets cut mid-JSON.
func extractToolSummary(toolName string, input map[string]any) string {
	str := func(key string) string {
		if v, ok := input[key].(string); ok {
			return v
		}
		return ""
	}
	switch toolName {
	case "Read", "Edit", "Write":
		if fp := str("file_path"); fp != "" {
			dir := filepath.Base(filepath.Dir(fp))
			base := filepath.Base(fp)
			if dir != "." && dir != "/" {
				return dir + "/" + base
			}
			return base
		}
	case "Bash":
		if desc := str("description"); desc != "" {
			return desc
		}
		if cmd := str("command"); cmd != "" {
			if len(cmd) > 80 {
				return cmd[:80] + "..."
			}
			return cmd
		}
	case "Grep":
		summary := ""
		if pat := str("pattern"); pat != "" {
			summary = "pattern: " + pat
			if p := str("path"); p != "" {
				summary += " in " + filepath.Base(p)
			}
			return summary
		}
	case "Glob":
		if pat := str("pattern"); pat != "" {
			return pat
		}
	case "Agent":
		if desc := str("description"); desc != "" {
			return desc
		}
	case "ToolSearch":
		if q := str("query"); q != "" {
			return q
		}
	case "WebFetch":
		if u := str("url"); u != "" {
			return u
		}
	case "WebSearch":
		if q := str("query"); q != "" {
			return q
		}
	}
	// Fallback: list top-level keys with short values
	var parts []string
	for k, v := range input {
		if s, ok := v.(string); ok && len(s) <= 40 {
			parts = append(parts, fmt.Sprintf("%s=%s", k, s))
		}
	}
	if len(parts) > 0 {
		s := strings.Join(parts, " ")
		if len(s) > 80 {
			return s[:80] + "..."
		}
		return s
	}
	return ""
}
