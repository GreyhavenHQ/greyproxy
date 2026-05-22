package llmproxy

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// helper: build an openai backend and marshal a request body to a map.
func buildBody(t *testing.T, ir *ChatRequest, modelID string) map[string]any {
	t.Helper()
	b, err := NewBackend("openai", "https://api.openai.com", "sk-x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.BuildRequest(context.Background(), ir, modelID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(req.Body)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("body json: %v", err)
	}
	return m
}

func TestBuildRequest_ToolsAndToolChoiceFunction(t *testing.T) {
	ir := &ChatRequest{
		Model:    "x",
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "weather?"}}}},
		Tools: []Tool{{
			Name:        "get_weather",
			Description: "lookup",
			Parameters:  map[string]any{"type": "object"},
		}},
		ToolChoice: &ToolChoice{Type: "function", Name: "get_weather"},
	}
	body := buildBody(t, ir, "gpt-4o")

	tools, ok := body["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools: %v", body["tools"])
	}
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "get_weather" {
		t.Fatalf("tool fn name: %v", fn)
	}
	tc, ok := body["tool_choice"].(map[string]any)
	if !ok || tc["type"] != "function" {
		t.Fatalf("tool_choice: %v", body["tool_choice"])
	}
	if tc["function"].(map[string]any)["name"] != "get_weather" {
		t.Fatalf("tool_choice fn: %v", tc)
	}
}

func TestBuildRequest_ToolChoiceStringForms(t *testing.T) {
	for _, want := range []string{"auto", "none", "required"} {
		ir := &ChatRequest{Model: "x", ToolChoice: &ToolChoice{Type: want}}
		body := buildBody(t, ir, "gpt-4o")
		if body["tool_choice"] != want {
			t.Fatalf("tool_choice %q: got %v", want, body["tool_choice"])
		}
	}
}

func TestBuildRequest_ResponseFormatJSONSchema(t *testing.T) {
	ir := &ChatRequest{
		Model: "x",
		ResponseFormat: &ResponseFormat{
			Type:       "json_schema",
			JSONSchema: map[string]any{"name": "out", "schema": map[string]any{"type": "object"}},
		},
	}
	body := buildBody(t, ir, "gpt-4o")
	rf, ok := body["response_format"].(map[string]any)
	if !ok || rf["type"] != "json_schema" {
		t.Fatalf("response_format: %v", body["response_format"])
	}
	if _, ok := rf["json_schema"].(map[string]any); !ok {
		t.Fatalf("json_schema missing: %v", rf)
	}
}

func TestBuildRequest_ResponseFormatJSONObject(t *testing.T) {
	ir := &ChatRequest{Model: "x", ResponseFormat: &ResponseFormat{Type: "json_object"}}
	body := buildBody(t, ir, "gpt-4o")
	rf := body["response_format"].(map[string]any)
	if rf["type"] != "json_object" {
		t.Fatalf("rf: %v", rf)
	}
	if _, has := rf["json_schema"]; has {
		t.Fatalf("json_object should not carry json_schema: %v", rf)
	}
}

func TestBuildRequest_MaxTokensAndStream(t *testing.T) {
	n := 256
	ir := &ChatRequest{Model: "x", MaxTokens: &n, Stream: true}
	body := buildBody(t, ir, "gpt-4o")
	if body["max_tokens"].(float64) != 256 {
		t.Fatalf("max_tokens: %v", body["max_tokens"])
	}
	if body["stream"] != true {
		t.Fatalf("stream: %v", body["stream"])
	}
}

func TestBuildRequest_EmptyModelIDRejected(t *testing.T) {
	b, _ := NewBackend("openai", "https://x", "k", nil)
	if _, err := b.BuildRequest(context.Background(), &ChatRequest{Model: "x"}, ""); err == nil {
		t.Fatal("expected error for empty model id")
	}
}

func TestEncodeMessages_ImageAndToolCall(t *testing.T) {
	msgs := []Message{
		{Role: "user", Content: []ContentBlock{
			{Type: "text", Text: "look"},
			{Type: "image", Image: &ImageRef{URL: "https://example.com/a.png"}},
		}},
		{Role: "assistant", Content: []ContentBlock{
			{Type: "tool_call", ToolCall: &ToolCall{ID: "call_1", Name: "f", Arguments: `{"x":1}`}},
		}},
		{Role: "user", Content: []ContentBlock{
			{Type: "image", Image: &ImageRef{Base64: "QUJD", MimeType: "image/png"}},
		}},
	}
	out := encodeMessages(msgs)
	if len(out) != 3 {
		t.Fatalf("len: %d", len(out))
	}

	// message 0: mixed content → parts array with text + image_url(url)
	parts := out[0]["content"].([]map[string]any)
	if parts[0]["type"] != "text" || parts[1]["type"] != "image_url" {
		t.Fatalf("parts: %+v", parts)
	}
	if parts[1]["image_url"].(map[string]any)["url"] != "https://example.com/a.png" {
		t.Fatalf("image url: %+v", parts[1])
	}

	// message 1: assistant tool_calls
	tcs := out[1]["tool_calls"].([]map[string]any)
	if len(tcs) != 1 || tcs[0]["id"] != "call_1" {
		t.Fatalf("tool_calls: %+v", tcs)
	}

	// message 2: base64 image becomes a data: URL
	p2 := out[2]["content"].([]map[string]any)
	url := p2[0]["image_url"].(map[string]any)["url"].(string)
	if !strings.HasPrefix(url, "data:image/png;base64,QUJD") {
		t.Fatalf("data url: %q", url)
	}
}

func TestNewOpenRouter_DefaultsAndAuth(t *testing.T) {
	b, err := NewBackend("openrouter", "", "sk-or", nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.Name() != "openrouter" {
		t.Fatalf("name: %s", b.Name())
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	req, err := b.BuildRequest(context.Background(), &ChatRequest{Model: "x"}, "anthropic/claude-3.5")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req.URL.String(), "https://openrouter.ai/api/v1/") {
		t.Fatalf("default base url not applied: %s", req.URL.String())
	}
	if req.Header.Get("Authorization") != "Bearer sk-or" {
		t.Fatalf("auth: %q", req.Header.Get("Authorization"))
	}
}

func TestBuildRequest_MetadataHeaders(t *testing.T) {
	b, _ := NewBackend("openai", "https://x", "k", map[string]string{"header.X-Title": "grey"})
	req, _ := b.BuildRequest(context.Background(), &ChatRequest{Model: "x"}, "gpt-4o")
	if req.Header.Get("X-Title") != "grey" {
		t.Fatalf("custom header not set: %q", req.Header.Get("X-Title"))
	}
}

func TestParseStream_EmitsDeltasAndDone(t *testing.T) {
	b, _ := NewBackend("openai", "https://x", "k", nil)
	sse := strings.Join([]string{
		`data: {"id":"1","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}`,
		`data: {"id":"1","choices":[{"index":0,"delta":{"content":"lo"}}]}`,
		`data: {"id":"1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
		``,
	}, "\n")

	ch := make(chan *StreamEvent, 16)
	done := make(chan error, 1)
	go func() { done <- b.ParseStream(strings.NewReader(sse), ch); close(ch) }()

	var text strings.Builder
	var sawDone, sawStop bool
	for ev := range ch {
		switch ev.Type {
		case "delta":
			if ev.Delta != nil {
				text.WriteString(ev.Delta.Content)
				if ev.Delta.FinishReason == "stop" {
					sawStop = true
				}
			}
		case "done":
			sawDone = true
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("parse stream: %v", err)
	}
	if text.String() != "Hello" {
		t.Fatalf("assembled text: %q", text.String())
	}
	if !sawDone {
		t.Fatal("missing done event")
	}
	if !sawStop {
		t.Fatal("missing stop finish_reason")
	}
}

func TestParseStream_IgnoresNonDataLines(t *testing.T) {
	b, _ := NewBackend("openai", "https://x", "k", nil)
	sse := ": comment\nevent: ping\n\ndata: [DONE]\n"
	ch := make(chan *StreamEvent, 4)
	go func() { _ = b.ParseStream(strings.NewReader(sse), ch); close(ch) }()
	n := 0
	for range ch {
		n++
	}
	if n != 1 {
		t.Fatalf("expected only the DONE event, got %d events", n)
	}
}

func TestParseResponse_ToolCalls(t *testing.T) {
	b, _ := NewBackend("openai", "https://x", "k", nil)
	body := `{
		"id":"c1","model":"gpt-4o",
		"choices":[{"index":0,"finish_reason":"tool_calls","message":{
			"role":"assistant","content":"",
			"tool_calls":[{"id":"call_9","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]
		}}],
		"usage":{"prompt_tokens":3,"completion_tokens":4,
			"prompt_tokens_details":{"cached_tokens":2},
			"completion_tokens_details":{"reasoning_tokens":1}}
	}`
	resp, err := b.ParseResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	c := resp.Choices[0]
	if c.FinishReason != "tool_calls" {
		t.Fatalf("finish: %q", c.FinishReason)
	}
	var tc *ToolCall
	for _, blk := range c.Message.Content {
		if blk.Type == "tool_call" {
			tc = blk.ToolCall
		}
	}
	if tc == nil || tc.ID != "call_9" || tc.Name != "f" || tc.Arguments != `{"a":1}` {
		t.Fatalf("tool call block: %+v", tc)
	}
	if resp.Usage.CachedTokens != 2 || resp.Usage.ReasoningTokens != 1 {
		t.Fatalf("usage details: %+v", resp.Usage)
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	b, _ := NewBackend("openai", "https://x", "k", nil)
	if _, err := b.ParseResponse([]byte("not json")); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestNewBackend_UnknownType(t *testing.T) {
	if _, err := NewBackend("does-not-exist", "https://x", "k", nil); err == nil {
		t.Fatal("expected ErrUnknownBackendType")
	}
}
