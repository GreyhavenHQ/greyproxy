package dissector

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

type testFixture struct {
	ID                  int    `json:"id"`
	ContainerName       string `json:"container_name"`
	URL                 string `json:"url"`
	Method              string `json:"method"`
	DestinationHost     string `json:"destination_host"`
	RequestHeaders      string `json:"request_headers"`
	RequestBody         string `json:"request_body"`
	RequestBodySize     int    `json:"request_body_size"`
	RequestContentType  string `json:"request_content_type"`
	ResponseBody        string `json:"response_body"`
	ResponseContentType string `json:"response_content_type"`
	DurationMs          int64  `json:"duration_ms"`
}

func loadFixture(t *testing.T, id string) testFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/" + id + ".json")
	if err != nil {
		t.Fatalf("load fixture %s: %v", id, err)
	}
	var f testFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture %s: %v", id, err)
	}
	return f
}

// fixtureHeaders parses the request_headers JSON string from a fixture
// into an http.Header. Returns nil if empty or unparseable.
func fixtureHeaders(f testFixture) http.Header {
	if f.RequestHeaders == "" {
		return nil
	}
	var multi map[string][]string
	if json.Unmarshal([]byte(f.RequestHeaders), &multi) == nil && len(multi) > 0 {
		return http.Header(multi)
	}
	return nil
}

// extractFromFixture is a convenience helper that runs a dissector on a fixture.
func extractFromFixture(t *testing.T, d Dissector, f testFixture) *ExtractionResult {
	t.Helper()
	result, err := d.Extract(ExtractionInput{
		TransactionID:  int64(f.ID),
		URL:            f.URL,
		Method:         f.Method,
		Host:           f.DestinationHost,
		RequestBody:    []byte(f.RequestBody),
		ResponseBody:   []byte(f.ResponseBody),
		RequestCT:      f.RequestContentType,
		ResponseCT:     f.ResponseContentType,
		RequestHeaders: fixtureHeaders(f),
		ContainerName:  f.ContainerName,
		DurationMs:     f.DurationMs,
	})
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	return result
}

func TestAnthropicCanHandle(t *testing.T) {
	d := &AnthropicDissector{}

	tests := []struct {
		url, method, host string
		want              bool
	}{
		{"https://api.anthropic.com/v1/messages", "POST", "api.anthropic.com", true},
		{"https://api.anthropic.com/v1/messages?beta=true", "POST", "api.anthropic.com", true},
		{"https://api.anthropic.com/v1/messages", "GET", "api.anthropic.com", false},
		{"https://api.openai.com/v1/chat/completions", "POST", "api.openai.com", false},
		{"https://api.anthropic.com/v1/complete", "POST", "api.anthropic.com", false},
	}

	for _, tt := range tests {
		got := d.CanHandle(tt.url, tt.method, tt.host)
		if got != tt.want {
			t.Errorf("CanHandle(%q, %q, %q) = %v, want %v", tt.url, tt.method, tt.host, got, tt.want)
		}
	}
}

func TestAnthropicExtract(t *testing.T) {
	d := &AnthropicDissector{}

	tests := []struct {
		fixtureID     string
		wantSessionID string
		wantModel     string
		wantMsgCount  int
	}{
		{"383", "33a9d683-ef38-4571-92b9-1ae2bf7a6be3", "claude-opus-4-6", 2},
		{"384", "33a9d683-ef38-4571-92b9-1ae2bf7a6be3", "claude-opus-4-6", 4},
		{"427", "33a9d683-ef38-4571-92b9-1ae2bf7a6be3", "claude-opus-4-6", 6},
		{"428", "33a9d683-ef38-4571-92b9-1ae2bf7a6be3", "claude-opus-4-6", 8},
		{"517", "33a9d683-ef38-4571-92b9-1ae2bf7a6be3", "claude-opus-4-6", 8},
	}

	for _, tt := range tests {
		t.Run("fixture_"+tt.fixtureID, func(t *testing.T) {
			f := loadFixture(t, tt.fixtureID)

			result, err := d.Extract(ExtractionInput{
				TransactionID: int64(f.ID),
				URL:           f.URL,
				Method:        "POST",
				Host:          f.DestinationHost,
				RequestBody:   []byte(f.RequestBody),
				ResponseBody:  []byte(f.ResponseBody),
				RequestCT:     "application/json",
				ResponseCT:    f.ResponseContentType,
				ContainerName: f.ContainerName,
				DurationMs:    f.DurationMs,
			})
			if err != nil {
				t.Fatalf("Extract error: %v", err)
			}

			if result.SessionID != tt.wantSessionID {
				t.Errorf("SessionID = %q, want %q", result.SessionID, tt.wantSessionID)
			}
			if result.Model != tt.wantModel {
				t.Errorf("Model = %q, want %q", result.Model, tt.wantModel)
			}
			if result.MessageCount != tt.wantMsgCount {
				t.Errorf("MessageCount = %d, want %d", result.MessageCount, tt.wantMsgCount)
			}
		})
	}
}

func TestAnthropicExtractSSEResponse(t *testing.T) {
	d := &AnthropicDissector{}
	f := loadFixture(t, "383")

	result, err := d.Extract(ExtractionInput{
		TransactionID: int64(f.ID),
		URL:           f.URL,
		Method:        "POST",
		Host:          f.DestinationHost,
		RequestBody:   []byte(f.RequestBody),
		ResponseBody:  []byte(f.ResponseBody),
		RequestCT:     "application/json",
		ResponseCT:    f.ResponseContentType,
		ContainerName: f.ContainerName,
		DurationMs:    f.DurationMs,
	})
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}

	if result.SSEResponse == nil {
		t.Fatal("expected SSEResponse to be non-nil")
	}

	// Fixture 383 should have some response text or tool calls
	if result.SSEResponse.Text == "" && len(result.SSEResponse.ToolCalls) == 0 {
		t.Error("expected SSE response to have text or tool calls")
	}
}

func TestAnthropicExtractSystemPrompt(t *testing.T) {
	d := &AnthropicDissector{}
	f := loadFixture(t, "383")

	result, err := d.Extract(ExtractionInput{
		TransactionID: int64(f.ID),
		URL:           f.URL,
		Method:        "POST",
		Host:          f.DestinationHost,
		RequestBody:   []byte(f.RequestBody),
		ResponseBody:  []byte(f.ResponseBody),
		RequestCT:     "application/json",
		ResponseCT:    f.ResponseContentType,
		ContainerName: f.ContainerName,
		DurationMs:    f.DurationMs,
	})
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}

	if len(result.SystemBlocks) == 0 {
		t.Fatal("expected system blocks to be non-empty")
	}

	sysLen := SystemPromptLength(result.SystemBlocks)
	if sysLen < 10000 {
		t.Errorf("expected system prompt >10K chars (main conversation), got %d", sysLen)
	}

	threadType := ClassifyThread("anthropic", result.SystemBlocks, result.Tools)
	if threadType != "main" {
		t.Errorf("expected thread type 'main', got %q", threadType)
	}
}

func TestExtractSessionIDFromUserID(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			"legacy string format",
			`"user_abc123_account_5a3241c6-4cbe-47e2-a7d3-981f6bf69be8_session_9d4a2584-4176-4653-be44-7d5f270feb21"`,
			"9d4a2584-4176-4653-be44-7d5f270feb21",
		},
		{
			"json object format",
			`{"device_id":"d8c2852a","account_uuid":"5a3241c6-4cbe-47e2-a7d3-981f6bf69be8","session_id":"9d4a2584-4176-4653-be44-7d5f270feb21"}`,
			"9d4a2584-4176-4653-be44-7d5f270feb21",
		},
		{
			"string-encoded json object",
			`"{\"device_id\":\"d8c2852a\",\"account_uuid\":\"5a3241c6-4cbe-47e2-a7d3-981f6bf69be8\",\"session_id\":\"9d4a2584-4176-4653-be44-7d5f270feb21\"}"`,
			"9d4a2584-4176-4653-be44-7d5f270feb21",
		},
		{
			"empty",
			`""`,
			"",
		},
		{
			"null",
			`null`,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSessionIDFromUserID(json.RawMessage(tt.raw))
			if got != tt.want {
				t.Errorf("extractSessionIDFromUserID(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestFindDissector(t *testing.T) {
	d := FindDissector("https://api.anthropic.com/v1/messages?beta=true", "POST", "api.anthropic.com")
	if d == nil {
		t.Fatal("expected to find Anthropic dissector")
	}
	if d.Name() != "anthropic" {
		t.Errorf("expected dissector name 'anthropic', got %q", d.Name())
	}

	d = FindDissector("https://example.com/api", "GET", "example.com")
	if d != nil {
		t.Error("expected no dissector for non-matching URL")
	}
}

func TestSSEParser(t *testing.T) {
	body := "event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	events := ParseSSE(body)
	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}

	resp := ExtractResponseFromSSE(events)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Text != "Hello world" {
		t.Errorf("expected text 'Hello world', got %q", resp.Text)
	}
}
