package dissector

import (
	"testing"
)

func TestGoogleAICanHandle(t *testing.T) {
	d := &GoogleAIDissector{}

	tests := []struct {
		url, method, host string
		want              bool
	}{
		// Non-streaming generateContent
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent", "POST", "generativelanguage.googleapis.com", true},
		// Streaming streamGenerateContent
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:streamGenerateContent?alt=sse", "POST", "generativelanguage.googleapis.com", true},
		// Different model
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent", "POST", "generativelanguage.googleapis.com", true},
		// Wrong method
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent", "GET", "generativelanguage.googleapis.com", false},
		// Wrong host
		{"https://api.openai.com/v1/chat/completions", "POST", "api.openai.com", false},
		// No /v1beta/models/ path
		{"https://generativelanguage.googleapis.com/v1/something", "POST", "generativelanguage.googleapis.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := d.CanHandle(tt.url, tt.method, tt.host)
			if got != tt.want {
				t.Errorf("CanHandle(%q, %q, %q) = %v, want %v", tt.url, tt.method, tt.host, got, tt.want)
			}
		})
	}
}

func TestGoogleAIExtract_ScorerNonStreaming(t *testing.T) {
	d := &GoogleAIDissector{}
	f := loadFixture(t, "gemini_scorer_2570")

	result := extractFromFixture(t, d, f)

	// Model should be extracted from URL
	if result.Model != "gemini-2.5-flash-lite" {
		t.Errorf("Model = %q, want %q", result.Model, "gemini-2.5-flash-lite")
	}

	// Google AI has no session concept
	if result.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", result.SessionID)
	}

	// Should have system instruction
	if len(result.SystemBlocks) == 0 {
		t.Error("expected system blocks from systemInstruction")
	}

	// Scorer has user messages (2 contents with role=user)
	if result.MessageCount < 1 {
		t.Errorf("MessageCount = %d, want >= 1", result.MessageCount)
	}

	// Scorer has no tools
	if len(result.Tools) != 0 {
		t.Errorf("Tools count = %d, want 0", len(result.Tools))
	}

	// Non-streaming response should be parsed
	if result.SSEResponse == nil {
		t.Fatal("expected SSEResponse to be non-nil")
	}
	if result.SSEResponse.Text == "" {
		t.Error("expected non-empty response text")
	}

	// Scorer thread classification: system prompt > 1000 chars with no tools
	// falls into the default heuristic which returns "subagent" for sysLen > 1000.
	// The actual complexity-scorer classification happens at the ClientAdapter level
	// (GeminiCLIAdapter.ClassifyThread checks model name).
	threadType := ClassifyThread("google-ai", result.SystemBlocks, result.Tools)
	if threadType == "" {
		t.Error("expected non-empty thread type")
	}
}

func TestGoogleAIExtract_MainStreaming(t *testing.T) {
	d := &GoogleAIDissector{}
	f := loadFixture(t, "gemini_main_2571")

	result := extractFromFixture(t, d, f)

	// Model should be extracted from URL
	if result.Model != "gemini-3-flash-preview" {
		t.Errorf("Model = %q, want %q", result.Model, "gemini-3-flash-preview")
	}

	// Should have system instruction
	if len(result.SystemBlocks) == 0 {
		t.Error("expected system blocks from systemInstruction")
	}

	// Should have messages
	if result.MessageCount < 1 {
		t.Errorf("MessageCount = %d, want >= 1", result.MessageCount)
	}

	// Main agent should have tools (26 function declarations)
	if len(result.Tools) < 10 {
		t.Errorf("Tools count = %d, want >= 10", len(result.Tools))
	}

	// Streaming SSE response should be parsed
	if result.SSEResponse == nil {
		t.Fatal("expected SSEResponse to be non-nil for streaming response")
	}
	if result.SSEResponse.Text == "" {
		t.Error("expected non-empty streaming response text")
	}

	// Main agent thread classification (has tools)
	threadType := ClassifyThread("google-ai", result.SystemBlocks, result.Tools)
	// With tools it should be main or subagent depending on which tools
	if threadType == "utility" {
		t.Errorf("expected non-utility thread type for main agent with tools, got %q", threadType)
	}
}

func TestExtractModelFromGoogleURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent", "gemini-2.5-flash-lite"},
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:streamGenerateContent?alt=sse", "gemini-3-flash-preview"},
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent", "gemini-2.5-pro"},
		{"https://example.com/no/models/path", "unknown"},
		{"https://generativelanguage.googleapis.com/v1beta/models/", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := extractModelFromGoogleURL(tt.url)
			if got != tt.want {
				t.Errorf("extractModelFromGoogleURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestFindDissectorGoogleAI(t *testing.T) {
	d := FindDissector(
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent",
		"POST",
		"generativelanguage.googleapis.com",
	)
	if d == nil {
		t.Fatal("expected to find Google AI dissector")
	}
	if d.Name() != "google-ai" {
		t.Errorf("expected dissector name 'google-ai', got %q", d.Name())
	}
}
