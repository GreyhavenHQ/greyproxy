package llmproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decodeBody(t *testing.T, body string) *ChatRequest {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(body))
	ir, err := DecodeOpenAIChat(req)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return ir
}

func TestDecode_ToolChoiceFunctionObject(t *testing.T) {
	ir := decodeBody(t, `{
		"model":"x","messages":[{"role":"user","content":"hi"}],
		"tool_choice":{"type":"function","function":{"name":"get_weather"}}
	}`)
	if ir.ToolChoice == nil || ir.ToolChoice.Type != "function" || ir.ToolChoice.Name != "get_weather" {
		t.Fatalf("tool_choice: %+v", ir.ToolChoice)
	}
}

func TestDecode_AssistantToolCalls(t *testing.T) {
	ir := decodeBody(t, `{
		"model":"x","messages":[
			{"role":"assistant","content":null,"tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}
			]}
		]
	}`)
	blocks := ir.Messages[0].Content
	if len(blocks) != 1 || blocks[0].Type != "tool_call" {
		t.Fatalf("blocks: %+v", blocks)
	}
	tc := blocks[0].ToolCall
	if tc.ID != "call_1" || tc.Name != "f" || tc.Arguments != `{"a":1}` {
		t.Fatalf("tool call: %+v", tc)
	}
}

func TestDecode_ToolResultMessage(t *testing.T) {
	ir := decodeBody(t, `{
		"model":"x","messages":[
			{"role":"tool","tool_call_id":"call_1","content":"42"}
		]
	}`)
	blocks := ir.Messages[0].Content
	if len(blocks) != 1 || blocks[0].Type != "tool_result" {
		t.Fatalf("blocks: %+v", blocks)
	}
	tr := blocks[0].ToolResult
	if tr.ToolUseID != "call_1" || tr.Content != "42" {
		t.Fatalf("tool result: %+v", tr)
	}
}

func TestDecode_MaxCompletionTokensFallback(t *testing.T) {
	ir := decodeBody(t, `{"model":"x","messages":[],"max_completion_tokens":512}`)
	if ir.MaxTokens == nil || *ir.MaxTokens != 512 {
		t.Fatalf("max_completion_tokens fallback: %v", ir.MaxTokens)
	}
}

func TestDecode_MaxTokensWinsOverCompletion(t *testing.T) {
	ir := decodeBody(t, `{"model":"x","messages":[],"max_tokens":100,"max_completion_tokens":512}`)
	if ir.MaxTokens == nil || *ir.MaxTokens != 100 {
		t.Fatalf("max_tokens should win: %v", ir.MaxTokens)
	}
}

func TestDecode_ResponseFormatJSONSchema(t *testing.T) {
	ir := decodeBody(t, `{
		"model":"x","messages":[],
		"response_format":{"type":"json_schema","json_schema":{"name":"out"}}
	}`)
	if ir.ResponseFormat == nil || ir.ResponseFormat.Type != "json_schema" {
		t.Fatalf("response_format: %+v", ir.ResponseFormat)
	}
	if ir.ResponseFormat.JSONSchema["name"] != "out" {
		t.Fatalf("json_schema: %+v", ir.ResponseFormat.JSONSchema)
	}
}

func TestDecode_StreamFlag(t *testing.T) {
	ir := decodeBody(t, `{"model":"x","messages":[],"stream":true}`)
	if !ir.Stream {
		t.Fatal("stream should be true")
	}
	if ir.InboundShape != ShapeOpenAIChat {
		t.Fatalf("inbound shape: %q", ir.InboundShape)
	}
	if ir.InboundRawPath != "/v1/chat/completions" {
		t.Fatalf("raw path: %q", ir.InboundRawPath)
	}
}

func TestEncode_ToolCallResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := &ChatResponse{
		ID:    "c1",
		Model: "gpt-4o",
		Choices: []Choice{{
			Index:        0,
			FinishReason: "tool_calls",
			Message: Message{Role: "assistant", Content: []ContentBlock{
				{Type: "tool_call", ToolCall: &ToolCall{ID: "call_1", Name: "f", Arguments: `{"a":1}`}},
			}},
		}},
	}
	if err := EncodeOpenAIChat(rec, resp); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	choices := got["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	tcs, ok := msg["tool_calls"].([]any)
	if !ok || len(tcs) != 1 {
		t.Fatalf("tool_calls in encoded response: %v", msg)
	}
	fn := tcs[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "f" || fn["arguments"] != `{"a":1}` {
		t.Fatalf("encoded tool call fn: %v", fn)
	}
}

func TestEncodeModelsList_And_Single(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := EncodeOpenAIModelsList(rec, []string{"fast", "smart"}); err != nil {
		t.Fatal(err)
	}
	var list map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if list["object"] != "list" {
		t.Fatalf("object: %v", list["object"])
	}
	if len(list["data"].([]any)) != 2 {
		t.Fatalf("data: %v", list["data"])
	}

	rec2 := httptest.NewRecorder()
	if err := EncodeOpenAIModel(rec2, "fast"); err != nil {
		t.Fatal(err)
	}
	var one map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &one)
	if one["id"] != "fast" || one["object"] != "model" {
		t.Fatalf("single model: %v", one)
	}
}

func TestErrorTypeForStatus(t *testing.T) {
	cases := map[int]string{
		400: "invalid_request_error",
		401: "permission_error",
		403: "permission_error",
		404: "not_found_error",
		500: "server_error",
		502: "server_error",
	}
	for status, want := range cases {
		rec := httptest.NewRecorder()
		EncodeOpenAIChatError(rec, status, "code", "msg")
		if rec.Code != status {
			t.Fatalf("status %d: code=%d", status, rec.Code)
		}
		var got map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		typ := got["error"].(map[string]any)["type"]
		if typ != want {
			t.Fatalf("status %d: type=%v want %q", status, typ, want)
		}
	}
}

func TestDecode_BodyReadError(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/chat/completions", errReader{})
	if _, err := DecodeOpenAIChat(req); err == nil {
		t.Fatal("expected read error")
	}
}

// errReader always fails, to exercise the body-read error branch.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, http.ErrBodyNotAllowed }
func (errReader) Close() error             { return nil }
