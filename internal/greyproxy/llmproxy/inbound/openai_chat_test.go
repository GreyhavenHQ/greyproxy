package inbound

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
)

func TestOpenAIChat_Decode_StringContent(t *testing.T) {
	body := `{
		"model": "fast",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user",   "content": "Hi"}
		],
		"temperature": 0.5,
		"max_tokens": 100,
		"stream": false
	}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	ir, err := DecodeOpenAIChat(req)
	if err != nil {
		t.Fatal(err)
	}
	if ir.Model != "fast" {
		t.Fatalf("model: %q", ir.Model)
	}
	if ir.InboundShape != llmproxy.ShapeOpenAIChat {
		t.Fatalf("inbound shape: %q", ir.InboundShape)
	}
	if len(ir.Messages) != 2 {
		t.Fatalf("messages: %d", len(ir.Messages))
	}
	if ir.Messages[0].Role != "system" || ir.Messages[0].Content[0].Text != "You are helpful." {
		t.Fatalf("first msg: %+v", ir.Messages[0])
	}
	if ir.Temperature == nil || *ir.Temperature != 0.5 {
		t.Fatalf("temperature: %v", ir.Temperature)
	}
	if ir.MaxTokens == nil || *ir.MaxTokens != 100 {
		t.Fatalf("max_tokens: %v", ir.MaxTokens)
	}
	if ir.Stream {
		t.Fatalf("stream should be false")
	}
}

func TestOpenAIChat_Decode_StructuredContent(t *testing.T) {
	body := `{
		"model": "x",
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "describe this image"},
				{"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}}
			]}
		]
	}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(body))
	ir, err := DecodeOpenAIChat(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Messages) != 1 {
		t.Fatalf("messages: %d", len(ir.Messages))
	}
	blocks := ir.Messages[0].Content
	if len(blocks) != 2 {
		t.Fatalf("blocks: %d", len(blocks))
	}
	if blocks[0].Type != "text" || blocks[0].Text != "describe this image" {
		t.Fatalf("text block: %+v", blocks[0])
	}
	if blocks[1].Type != "image" || blocks[1].Image == nil || blocks[1].Image.URL != "https://example.com/cat.png" {
		t.Fatalf("image block: %+v", blocks[1])
	}
}

func TestOpenAIChat_Decode_Tools(t *testing.T) {
	body := `{
		"model": "x",
		"messages": [{"role": "user", "content": "hi"}],
		"tools": [{
			"type": "function",
			"function": {
				"name": "get_weather",
				"description": "lookup weather",
				"parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
			}
		}],
		"tool_choice": "auto"
	}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(body))
	ir, err := DecodeOpenAIChat(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Tools) != 1 {
		t.Fatalf("tools: %d", len(ir.Tools))
	}
	if ir.Tools[0].Name != "get_weather" || ir.Tools[0].Description != "lookup weather" {
		t.Fatalf("tool: %+v", ir.Tools[0])
	}
	if ir.ToolChoice == nil || ir.ToolChoice.Type != "auto" {
		t.Fatalf("tool_choice: %+v", ir.ToolChoice)
	}
}

func TestOpenAIChat_Decode_RejectsNonJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString("not json"))
	if _, err := DecodeOpenAIChat(req); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestOpenAIChat_Encode_NonStreaming(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := &llmproxy.ChatResponse{
		ID:    "chatcmpl-abc",
		Model: "gpt-4o-mini",
		Choices: []llmproxy.Choice{{
			Index:        0,
			FinishReason: "stop",
			Message: llmproxy.Message{
				Role:    "assistant",
				Content: []llmproxy.ContentBlock{{Type: "text", Text: "Hello!"}},
			},
		}},
		Usage:    llmproxy.Usage{InputTokens: 5, OutputTokens: 2},
		Provider: "openai",
	}
	if err := EncodeOpenAIChat(rec, resp); err != nil {
		t.Fatal(err)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type: %q", got)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "chatcmpl-abc" {
		t.Fatalf("id: %v", got["id"])
	}
	if got["object"] != "chat.completion" {
		t.Fatalf("object: %v", got["object"])
	}
	choices := got["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("choices: %v", choices)
	}
	c0 := choices[0].(map[string]any)
	msg := c0["message"].(map[string]any)
	if msg["content"] != "Hello!" {
		t.Fatalf("content: %v", msg["content"])
	}
	usage := got["usage"].(map[string]any)
	if usage["prompt_tokens"].(float64) != 5 || usage["completion_tokens"].(float64) != 2 {
		t.Fatalf("usage: %v", usage)
	}
}

func TestOpenAIChat_EncodeError(t *testing.T) {
	rec := httptest.NewRecorder()
	EncodeOpenAIChatError(rec, http.StatusNotFound, "alias_unknown", "unknown alias")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: %d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	errBlock, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error envelope, got %v", got)
	}
	if errBlock["message"] != "unknown alias" || errBlock["code"] != "alias_unknown" {
		t.Fatalf("error block: %v", errBlock)
	}
}
