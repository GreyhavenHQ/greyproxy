package dissector

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenAIWSDissector_CanHandle(t *testing.T) {
	d := &OpenAIWSDissector{}
	if !d.CanHandle("wss://api.openai.com:80/v1/responses", "WS_REQ", "api.openai.com") {
		t.Error("should handle WS_REQ to api.openai.com/v1/responses")
	}
	if !d.CanHandle("wss://api.openai.com:80/v1/responses", "WS_RESP", "api.openai.com") {
		t.Error("should handle WS_RESP to api.openai.com/v1/responses")
	}
	if d.CanHandle("wss://api.openai.com:80/v1/responses", "POST", "api.openai.com") {
		t.Error("should not handle POST")
	}
}

func TestOpenAIWSDissector_Extract_PingFrame(t *testing.T) {
	d := &OpenAIWSDissector{}
	result, err := d.Extract(ExtractionInput{
		RequestBody: []byte{0x96, 0x6c, 0xec, 0xf9}, // 4-byte ping
		Method:      "WS_REQ",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("ping frames should return nil result")
	}
}

func TestOpenAIWSDissector_Extract_ResponseCreate(t *testing.T) {
	d := &OpenAIWSDissector{}
	body := map[string]any{
		"type":             "response.create",
		"model":            "gpt-5.4",
		"instructions":     "You are Codex, a coding agent.",
		"prompt_cache_key": "019d6a97-4577-7130-8100-ad0e118bf762",
		"input": []any{
			map[string]any{
				"role":    "user",
				"content": []any{map[string]any{"type": "input_text", "text": "Hello, please help me"}},
			},
			map[string]any{
				"type":    "message",
				"role":    "assistant",
				"content": []any{map[string]any{"type": "output_text", "text": "Sure, what do you need?"}},
			},
			map[string]any{
				"type":      "function_call",
				"call_id":   "call_123",
				"name":      "shell",
				"arguments": `{"command":"ls -la"}`,
			},
			map[string]any{
				"type":    "function_call_output",
				"call_id": "call_123",
				"output":  "total 42\ndrwxr-xr-x ...",
			},
			map[string]any{
				"role":    "user",
				"content": []any{map[string]any{"type": "input_text", "text": "Now fix the bug"}},
			},
		},
		"tools": []any{
			map[string]any{"name": "shell", "description": "Run a shell command"},
			map[string]any{"name": "read_file", "description": "Read a file"},
		},
		"client_metadata": map[string]any{
			"x-codex-turn-metadata": `{"session_id":"019d6a97","turn_id":"","sandbox":"seccomp"}`,
		},
	}
	bodyJSON, _ := json.Marshal(body)

	result, err := d.Extract(ExtractionInput{
		RequestBody: bodyJSON,
		Method:      "WS_REQ",
		URL:         "wss://api.openai.com:80/v1/responses",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.Provider != "openai" {
		t.Errorf("provider = %q, want openai", result.Provider)
	}
	if result.Model != "gpt-5.4" {
		t.Errorf("model = %q, want gpt-5.4", result.Model)
	}
	if result.SessionID != "019d6a97-4577-7130-8100-ad0e118bf762" {
		t.Errorf("sessionID = %q, want 019d6a97-4577-7130-8100-ad0e118bf762", result.SessionID)
	}
	if result.ClientHint != "codex" {
		t.Errorf("clientHint = %q, want codex", result.ClientHint)
	}
	if len(result.Tools) != 2 {
		t.Errorf("tools count = %d, want 2", len(result.Tools))
	}

	// System prompt from instructions
	if len(result.SystemBlocks) == 0 {
		t.Fatal("expected system blocks from instructions")
	}
	if !strings.Contains(result.SystemBlocks[0].Text, "Codex") {
		t.Errorf("system prompt should mention Codex, got: %s", result.SystemBlocks[0].Text[:50])
	}

	// Messages: user, assistant(message), assistant(tool_use), user(tool_result), user
	if result.MessageCount < 4 {
		t.Errorf("messageCount = %d, want >= 4", result.MessageCount)
	}

	// Check first user message
	if len(result.Messages) == 0 || result.Messages[0].Role != "user" {
		t.Fatal("first message should be user")
	}
	if len(result.Messages[0].Content) == 0 || result.Messages[0].Content[0].Text != "Hello, please help me" {
		t.Error("first user message text mismatch")
	}
}

func TestOpenAIWSDissector_CanHandle_RESP(t *testing.T) {
	d := &OpenAIWSDissector{}
	if !d.CanHandle("wss://api.openai.com:80/v1/responses", "WS_RESP", "api.openai.com") {
		t.Error("should handle WS_RESP to api.openai.com/v1/responses")
	}
	if !d.CanHandle("wss://api.openai.com:80/v1/responses", "WS_REQ", "api.openai.com") {
		t.Error("should handle WS_REQ to api.openai.com/v1/responses")
	}
	if d.CanHandle("wss://api.openai.com:80/v1/responses", "POST", "api.openai.com") {
		t.Error("should not handle POST")
	}
}

func TestOpenAIWSDissector_Extract_Completed(t *testing.T) {
	d := &OpenAIWSDissector{}
	body := map[string]any{
		"type": "response.completed",
		"response": map[string]any{
			"id":    "resp_123",
			"model": "gpt-5.4",
			"output": []any{
				map[string]any{
					"type": "message",
					"role": "assistant",
					"content": []any{
						map[string]any{"type": "output_text", "text": "Here is the fix."},
					},
				},
				map[string]any{
					"type":      "function_call",
					"name":      "apply_diff",
					"call_id":   "call_456",
					"arguments": `{"file":"main.go","diff":"..."}`,
				},
			},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	result, err := d.Extract(ExtractionInput{
		RequestBody: bodyJSON,
		Method:      "WS_RESP",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for response.completed")
	}
	if result.SSEResponse == nil {
		t.Fatal("expected SSEResponse")
	}
	if result.SSEResponse.Text != "Here is the fix." {
		t.Errorf("text = %q, want 'Here is the fix.'", result.SSEResponse.Text)
	}
	if len(result.SSEResponse.ToolCalls) != 1 {
		t.Fatalf("tool_calls count = %d, want 1", len(result.SSEResponse.ToolCalls))
	}
	if result.SSEResponse.ToolCalls[0].Tool != "apply_diff" {
		t.Errorf("tool = %q, want apply_diff", result.SSEResponse.ToolCalls[0].Tool)
	}
}

func TestOpenAIWSDissector_Extract_SkipsDelta(t *testing.T) {
	d := &OpenAIWSDissector{}
	body := `{"type":"response.output_text.delta","delta":"Hello"}`
	result, err := d.Extract(ExtractionInput{
		RequestBody: []byte(body),
		Method:      "WS_RESP",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("delta frames should return nil result")
	}
}

func TestFindDissectorByName_WS(t *testing.T) {
	d := FindDissectorByName("openai-ws")
	if d == nil {
		t.Fatal("openai-ws dissector not registered")
	}
	if d.Name() != "openai-ws" {
		t.Errorf("name = %q, want openai-ws", d.Name())
	}

	// Merged dissector handles both WS_REQ and WS_RESP
	if !d.CanHandle("wss://api.openai.com/v1/responses", "WS_REQ", "api.openai.com") {
		t.Error("should handle WS_REQ")
	}
	if !d.CanHandle("wss://api.openai.com/v1/responses", "WS_RESP", "api.openai.com") {
		t.Error("should handle WS_RESP")
	}

	// openai-ws-event no longer exists as separate dissector
	if FindDissectorByName("openai-ws-event") != nil {
		t.Error("openai-ws-event should no longer be registered")
	}
}
