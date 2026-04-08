package dissector

// Google AI (Gemini) API dissector.
//
// Handles traffic from Gemini CLI to generativelanguage.googleapis.com.
//
// Endpoints:
//   - POST /v1beta/models/{model}:generateContent (non-streaming)
//   - POST /v1beta/models/{model}:streamGenerateContent?alt=sse (streaming)
//
// Request body structure:
//   - contents[]: array of {role, parts[]} where parts contain text, functionCall, functionResponse
//   - systemInstruction: {parts[]} (role is always "user"; ignore it)
//   - tools[].functionDeclarations[]: array of {name, description, parametersJsonSchema}
//   - generationConfig: {temperature, thinkingConfig, responseMimeType}
//
// Model is extracted from the URL path, not the body.
//
// Response (non-streaming): JSON with candidates[0].content.parts[]
// Response (streaming): SSE data: lines (no event prefix, no [DONE]),
//   each chunk is a complete candidates object, finishes at chunk with finishReason.

import (
	"encoding/json"
	"strings"
)

// GoogleAIDissector parses Google AI (Gemini) API transactions.
type GoogleAIDissector struct{}

func (d *GoogleAIDissector) Name() string        { return "google-ai" }
func (d *GoogleAIDissector) Description() string { return "Google Gemini API (/v1beta/models)" }

func (d *GoogleAIDissector) CanHandle(url, method, host string) bool {
	if method != "POST" {
		return false
	}
	return host == "generativelanguage.googleapis.com" &&
		strings.Contains(url, "/v1beta/models/")
}

func (d *GoogleAIDissector) Extract(input ExtractionInput) (*ExtractionResult, error) {
	result := &ExtractionResult{Provider: d.Name()}

	// Model from URL path: /v1beta/models/{model}:{method}
	result.Model = extractModelFromGoogleURL(input.URL)

	var body struct {
		Contents []struct {
			Role  string            `json:"role"`
			Parts []json.RawMessage `json:"parts"`
		} `json:"contents"`
		SystemInstruction *struct {
			Parts []json.RawMessage `json:"parts"`
		} `json:"systemInstruction"`
		Tools []struct {
			FunctionDeclarations []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"functionDeclarations"`
		} `json:"tools"`
	}

	if len(input.RequestBody) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(input.RequestBody, &body); err != nil {
		return result, nil
	}

	// System instruction
	if body.SystemInstruction != nil {
		for _, raw := range body.SystemInstruction.Parts {
			text := extractGooglePartText(raw)
			if text != "" {
				result.SystemBlocks = append(result.SystemBlocks, SystemBlock{
					Type: "text",
					Text: text,
				})
			}
		}
	}

	// Tools
	for _, toolGroup := range body.Tools {
		for _, decl := range toolGroup.FunctionDeclarations {
			result.Tools = append(result.Tools, Tool{
				Name:        decl.Name,
				Description: decl.Description,
			})
		}
	}

	// Contents -> Messages
	for _, content := range body.Contents {
		role := "user"
		if content.Role == "model" {
			role = "assistant"
		}

		m := Message{Role: role}
		for _, raw := range content.Parts {
			cb := parseGooglePart(raw)
			if cb.Type != "" {
				m.Content = append(m.Content, cb)
			}
		}
		if len(m.Content) > 0 {
			result.Messages = append(result.Messages, m)
			result.MessageCount++
		}
	}

	// Parse response
	if len(input.ResponseBody) > 0 {
		if strings.Contains(input.ResponseCT, "text/event-stream") ||
			strings.Contains(input.URL, "alt=sse") {
			result.SSEResponse = extractGoogleStreamingResponse(input.ResponseBody)
		} else {
			result.SSEResponse = extractGoogleNonStreamingResponse(input.ResponseBody)
		}
	}

	return result, nil
}

// extractModelFromGoogleURL extracts model name from URL like
// /v1beta/models/gemini-2.5-pro:streamGenerateContent
func extractModelFromGoogleURL(url string) string {
	idx := strings.Index(url, "/v1beta/models/")
	if idx < 0 {
		return "unknown"
	}
	rest := url[idx+len("/v1beta/models/"):]
	// Model ends at ':' (method separator) or '?' (query)
	if i := strings.IndexAny(rest, ":?"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "unknown"
	}
	return rest
}

// extractGooglePartText extracts text from a Google AI part.
func extractGooglePartText(raw json.RawMessage) string {
	var part struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &part) == nil && part.Text != "" {
		return part.Text
	}
	return ""
}

// parseGooglePart converts a Google AI part to a ContentBlock.
func parseGooglePart(raw json.RawMessage) ContentBlock {
	// Try text
	var textPart struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &textPart) == nil && textPart.Text != "" {
		return ContentBlock{Type: "text", Text: textPart.Text}
	}

	// Try functionCall
	var fcPart struct {
		FunctionCall *struct {
			Name string         `json:"name"`
			Args map[string]any `json:"args"`
		} `json:"functionCall"`
	}
	if json.Unmarshal(raw, &fcPart) == nil && fcPart.FunctionCall != nil {
		cb := ContentBlock{
			Type: "tool_use",
			Name: fcPart.FunctionCall.Name,
		}
		if fcPart.FunctionCall.Args != nil {
			cb.ToolSummary = ExtractToolSummary(fcPart.FunctionCall.Name, fcPart.FunctionCall.Args)
			if b, err := json.Marshal(fcPart.FunctionCall.Args); err == nil {
				s := string(b)
				if len(s) > 300 {
					s = s[:300]
				}
				cb.Input = s
			}
		}
		return cb
	}

	// Try functionResponse
	var frPart struct {
		FunctionResponse *struct {
			Name     string         `json:"name"`
			Response map[string]any `json:"response"`
		} `json:"functionResponse"`
	}
	if json.Unmarshal(raw, &frPart) == nil && frPart.FunctionResponse != nil {
		content := ""
		if frPart.FunctionResponse.Response != nil {
			if b, err := json.Marshal(frPart.FunctionResponse.Response); err == nil {
				content = string(b)
				if len(content) > 500 {
					content = content[:500]
				}
			}
		}
		return ContentBlock{
			Type:    "tool_result",
			Name:    frPart.FunctionResponse.Name,
			Content: content,
		}
	}

	// Try thoughtSignature (opaque thinking)
	var tsPart struct {
		ThoughtSignature string `json:"thoughtSignature"`
	}
	if json.Unmarshal(raw, &tsPart) == nil && tsPart.ThoughtSignature != "" {
		return ContentBlock{
			Type:     "thinking",
			Thinking: "[thinking: opaque signature]",
		}
	}

	return ContentBlock{}
}

// extractGoogleStreamingResponse parses streaming SSE response from Google AI.
// Each data: line is a complete candidates object (text is per-chunk delta).
func extractGoogleStreamingResponse(body []byte) *SSEResponseData {
	chunks := ParseSSEDataOnly(string(body))
	if len(chunks) == 0 {
		return nil
	}

	var textParts []string
	var toolCalls []ToolCall

	for _, chunk := range chunks {
		var data struct {
			Candidates []struct {
				Content struct {
					Parts []json.RawMessage `json:"parts"`
					Role  string            `json:"role"`
				} `json:"content"`
				FinishReason string `json:"finishReason"`
			} `json:"candidates"`
		}
		if json.Unmarshal([]byte(chunk), &data) != nil || len(data.Candidates) == 0 {
			continue
		}

		for _, part := range data.Candidates[0].Content.Parts {
			// Text
			text := extractGooglePartText(part)
			if text != "" {
				textParts = append(textParts, text)
			}

			// Function call
			var fcPart struct {
				FunctionCall *struct {
					Name string         `json:"name"`
					Args map[string]any `json:"args"`
				} `json:"functionCall"`
			}
			if json.Unmarshal(part, &fcPart) == nil && fcPart.FunctionCall != nil {
				tc := ToolCall{Tool: fcPart.FunctionCall.Name}
				if fcPart.FunctionCall.Args != nil {
					tc.ToolSummary = ExtractToolSummary(fcPart.FunctionCall.Name, fcPart.FunctionCall.Args)
					if b, err := json.Marshal(fcPart.FunctionCall.Args); err == nil {
						s := string(b)
						if len(s) > 200 {
							s = s[:200]
						}
						tc.InputPreview = s
					}
				}
				toolCalls = append(toolCalls, tc)
			}
		}

		if data.Candidates[0].FinishReason != "" {
			break
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

// extractGoogleNonStreamingResponse parses non-streaming response from Google AI.
func extractGoogleNonStreamingResponse(body []byte) *SSEResponseData {
	var resp struct {
		Candidates []struct {
			Content struct {
				Parts []json.RawMessage `json:"parts"`
				Role  string            `json:"role"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal(body, &resp) != nil || len(resp.Candidates) == 0 {
		return nil
	}

	result := &SSEResponseData{}
	var textParts []string

	for _, part := range resp.Candidates[0].Content.Parts {
		text := extractGooglePartText(part)
		if text != "" {
			textParts = append(textParts, text)
		}

		var fcPart struct {
			FunctionCall *struct {
				Name string         `json:"name"`
				Args map[string]any `json:"args"`
			} `json:"functionCall"`
		}
		if json.Unmarshal(part, &fcPart) == nil && fcPart.FunctionCall != nil {
			tc := ToolCall{Tool: fcPart.FunctionCall.Name}
			if fcPart.FunctionCall.Args != nil {
				tc.ToolSummary = ExtractToolSummary(fcPart.FunctionCall.Name, fcPart.FunctionCall.Args)
				if b, err := json.Marshal(fcPart.FunctionCall.Args); err == nil {
					s := string(b)
					if len(s) > 200 {
						s = s[:200]
					}
					tc.InputPreview = s
				}
			}
			result.ToolCalls = append(result.ToolCalls, tc)
		}
	}

	if len(textParts) > 0 {
		result.Text = strings.Join(textParts, "")
	}

	if result.Text == "" && len(result.ToolCalls) == 0 {
		return nil
	}
	return result
}

func init() {
	Register(&GoogleAIDissector{})
}
