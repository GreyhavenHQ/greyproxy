package llmproxy

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

)

func TestOpenAI_BuildRequest_AddsAuthAndJSONBody(t *testing.T) {
	p, err := NewBackend("openai", "https://api.openai.com", "sk-test", nil)
	if err != nil {
		t.Fatal(err)
	}

	tmp := 0.7
	ir := &ChatRequest{
		Model: "fast", // public alias
		Messages: []Message{
			{Role: "user", Content: []ContentBlock{{Type: "text", Text: "Hi"}}},
		},
		Temperature: &tmp,
		Stream:      false,
	}
	req, err := p.BuildRequest(context.Background(), ir, "gpt-4o-mini")
	if err != nil {
		t.Fatal(err)
	}

	if req.Method != "POST" {
		t.Fatalf("method: got %s", req.Method)
	}
	if !strings.HasSuffix(req.URL.String(), "/v1/chat/completions") {
		t.Fatalf("url: %s", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("auth: got %q", got)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type: got %q", ct)
	}

	body, _ := io.ReadAll(req.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body json: %v", err)
	}
	if got["model"] != "gpt-4o-mini" {
		t.Fatalf("model in body: got %v", got["model"])
	}
	if got["temperature"].(float64) != 0.7 {
		t.Fatalf("temperature in body: got %v", got["temperature"])
	}
	msgs, ok := got["messages"].([]any)
	if !ok || len(msgs) != 1 {
		t.Fatalf("messages shape: got %v", got["messages"])
	}
	m0 := msgs[0].(map[string]any)
	if m0["role"] != "user" || m0["content"] != "Hi" {
		t.Fatalf("message body: %v", m0)
	}
}

func TestOpenAI_BuildRequest_NoAuthWhenEmptyKey(t *testing.T) {
	// openai-compat with a local server (Ollama) usually has no auth.
	p, _ := NewBackend("openai-compat", "http://localhost:11434/v1", "", nil)
	req, err := p.BuildRequest(context.Background(), &ChatRequest{Model: "x"}, "llama3.2")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected no auth header, got %q", got)
	}
}

func TestOpenAI_ParseResponse(t *testing.T) {
	p, _ := NewBackend("openai", "https://api.openai.com", "sk-x", nil)
	body := `{
		"id": "chatcmpl-123",
		"model": "gpt-4o-mini",
		"choices": [
			{"index": 0, "finish_reason": "stop",
			 "message": {"role": "assistant", "content": "Hello!"}}
		],
		"usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
	}`
	resp, err := p.ParseResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != "chatcmpl-123" {
		t.Fatalf("id: %q", resp.ID)
	}
	if resp.Model != "gpt-4o-mini" {
		t.Fatalf("model: %q", resp.Model)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices: %d", len(resp.Choices))
	}
	c := resp.Choices[0]
	if c.FinishReason != "stop" {
		t.Fatalf("finish_reason: %q", c.FinishReason)
	}
	if c.Message.Role != "assistant" {
		t.Fatalf("role: %q", c.Message.Role)
	}
	if len(c.Message.Content) != 1 || c.Message.Content[0].Text != "Hello!" {
		t.Fatalf("content: %+v", c.Message.Content)
	}
	if resp.Usage.InputTokens != 5 || resp.Usage.OutputTokens != 2 {
		t.Fatalf("usage: %+v", resp.Usage)
	}
}

func TestRegistry_BackendTypesIncludesOpenAIVariants(t *testing.T) {
	want := []string{"openai", "openai-compat"}
	got := BackendTypes()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("BackendTypes() missing %q; got %v", w, got)
		}
	}
}
