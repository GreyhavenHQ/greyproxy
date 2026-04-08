package dissector

// OpenAI Responses API over WebSocket dissector.
//
// Codex CLI uses WebSocket connections to wss://api.openai.com/v1/responses
// instead of HTTP POST. The protocol is:
//
// Client frames (WS_REQ):
//   {"type":"response.create", "model":"...", "instructions":"...", "input":[...], ...}
//   Same fields as the HTTP POST body, with an extra "type" field and
//   "instructions" at the top level (instead of a developer role in input).
//
// Server frames (WS_RESP):
//   Individual event objects: response.created, response.in_progress,
//   response.output_text.delta, response.completed, etc.
//   The response.completed frame contains the full response with output items.
//
// Ping/pong frames (typically 4 bytes) are silently skipped.

import (
	"encoding/json"
	"strings"
)

// OpenAIWSDissector parses both WS_REQ and WS_RESP frames from the
// OpenAI Responses API WebSocket protocol.
type OpenAIWSDissector struct{}

func (d *OpenAIWSDissector) Name() string        { return "openai-ws" }
func (d *OpenAIWSDissector) Description() string { return "OpenAI Responses API over WebSocket (Codex)" }

func (d *OpenAIWSDissector) CanHandle(url, method, host string) bool {
	if method != "WS_REQ" && method != "WS_RESP" {
		return false
	}
	return strings.Contains(url, "api.openai.com") && strings.Contains(url, "/v1/responses")
}

func (d *OpenAIWSDissector) Extract(input ExtractionInput) (*ExtractionResult, error) {
	if len(input.RequestBody) < 10 {
		return nil, nil // skip ping/pong frames
	}
	switch input.Method {
	case "WS_REQ":
		return d.extractRequest(input)
	case "WS_RESP":
		return d.extractResponse(input)
	}
	return nil, nil
}

// extractRequest parses WS_REQ frames (client sends response.create requests).
func (d *OpenAIWSDissector) extractRequest(input ExtractionInput) (*ExtractionResult, error) {
	result := &ExtractionResult{Provider: "openai"}

	var body struct {
		Type           string            `json:"type"`
		Model          string            `json:"model"`
		Instructions   string            `json:"instructions"`
		Input          []json.RawMessage `json:"input"`
		Tools          []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
		PromptCacheKey string `json:"prompt_cache_key"`
		ClientMetadata struct {
			CodexTurnMeta string `json:"x-codex-turn-metadata"`
		} `json:"client_metadata"`
	}

	if err := json.Unmarshal(input.RequestBody, &body); err != nil {
		return nil, nil // not valid JSON, skip
	}

	if body.Type != "response.create" {
		return nil, nil // not a request frame
	}

	// Session ID from prompt_cache_key (same as HTTP POST)
	result.SessionID = body.PromptCacheKey
	result.Model = body.Model
	if result.Model == "" {
		result.Model = "unknown"
	}

	// Detect Codex client from metadata
	if body.ClientMetadata.CodexTurnMeta != "" {
		result.ClientHint = "codex"
	}

	// Tools
	for _, t := range body.Tools {
		result.Tools = append(result.Tools, Tool{Name: t.Name, Description: t.Description})
	}

	// System prompt from top-level instructions field
	if body.Instructions != "" {
		result.SystemBlocks = append(result.SystemBlocks, SystemBlock{
			Type: "text",
			Text: body.Instructions,
		})
	}

	// Parse input items (same format as HTTP POST)
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
			text := extractOpenAIText(raw)
			if text != "" {
				result.SystemBlocks = append(result.SystemBlocks, SystemBlock{
					Type: "text",
					Text: text,
				})
			}

		case probe.Role == "user":
			m := Message{Role: "user"}
			text := extractOpenAIInputTextBlocks(raw)
			if text != "" {
				m.Content = []ContentBlock{{Type: "text", Text: text}}
			}
			result.Messages = append(result.Messages, m)
			result.MessageCount++

		case probe.Type == "function_call":
			var fc struct {
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}
			json.Unmarshal(raw, &fc)

			cb := ContentBlock{
				Type: "tool_use",
				Name: fc.Name,
				ID:   fc.CallID,
			}
			var argsMap map[string]any
			if json.Unmarshal([]byte(fc.Arguments), &argsMap) == nil {
				cb.ToolSummary = ExtractToolSummary(fc.Name, argsMap)
			}
			if len(fc.Arguments) > 300 {
				cb.Input = fc.Arguments[:300]
			} else {
				cb.Input = fc.Arguments
			}

			result.Messages = appendToAssistant(result.Messages, cb)
			result.MessageCount++

		case probe.Type == "function_call_output":
			var fco struct {
				CallID string `json:"call_id"`
				Output string `json:"output"`
			}
			json.Unmarshal(raw, &fco)

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
			// Opaque reasoning block; skip

		case probe.Type == "message":
			var msg struct {
				Role    string `json:"role"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			}
			json.Unmarshal(raw, &msg)
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

	return result, nil
}

// extractResponse parses WS_RESP frames. Only response.completed frames
// produce meaningful results; all other event types are skipped.
func (d *OpenAIWSDissector) extractResponse(input ExtractionInput) (*ExtractionResult, error) {
	var envelope struct {
		Type     string          `json:"type"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(input.RequestBody, &envelope); err != nil {
		return nil, nil
	}

	if envelope.Type != "response.completed" {
		return nil, nil // only process completed events
	}

	var resp struct {
		ID     string `json:"id"`
		Model  string `json:"model"`
		Output []struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			// function_call fields
			Name      string `json:"name"`
			CallID    string `json:"call_id"`
			Arguments string `json:"arguments"`
		} `json:"output"`
	}
	if err := json.Unmarshal(envelope.Response, &resp); err != nil {
		return nil, nil
	}

	result := &ExtractionResult{
		Provider: "openai",
		Model:    resp.Model,
	}

	// Build SSEResponseData from output items (same shape as SSE parsing)
	var textParts []string
	var toolCalls []ToolCall

	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			for _, c := range item.Content {
				if c.Type == "output_text" && c.Text != "" {
					textParts = append(textParts, c.Text)
				}
			}
		case "function_call":
			tc := ToolCall{
				Tool:      item.Name,
				ToolUseID: item.CallID,
			}
			if len(item.Arguments) > 200 {
				tc.InputPreview = item.Arguments[:200]
			} else {
				tc.InputPreview = item.Arguments
			}
			var argsMap map[string]any
			if json.Unmarshal([]byte(item.Arguments), &argsMap) == nil {
				tc.ToolSummary = ExtractToolSummary(item.Name, argsMap)
			}
			toolCalls = append(toolCalls, tc)
		}
	}

	if len(textParts) == 0 && len(toolCalls) == 0 {
		return nil, nil
	}

	result.SSEResponse = &SSEResponseData{}
	if len(textParts) > 0 {
		result.SSEResponse.Text = strings.Join(textParts, "")
	}
	if len(toolCalls) > 0 {
		result.SSEResponse.ToolCalls = toolCalls
	}

	return result, nil
}

func init() {
	Register(&OpenAIWSDissector{})
}
