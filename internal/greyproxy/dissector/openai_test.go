package dissector

import (
	"testing"
)

func TestOpenAICanHandle(t *testing.T) {
	d := &OpenAIDissector{}

	tests := []struct {
		url, method, host string
		want              bool
	}{
		{"https://api.openai.com/v1/responses", "POST", "api.openai.com", true},
		{"https://api.openai.com/v1/responses?stream=true", "POST", "api.openai.com", true},
		{"https://api.openai.com/v1/responses", "GET", "api.openai.com", false},
		{"https://api.openai.com/v1/chat/completions", "POST", "api.openai.com", false},
		{"https://api.anthropic.com/v1/messages", "POST", "api.anthropic.com", false},
	}

	for _, tt := range tests {
		got := d.CanHandle(tt.url, tt.method, tt.host)
		if got != tt.want {
			t.Errorf("CanHandle(%q, %q, %q) = %v, want %v", tt.url, tt.method, tt.host, got, tt.want)
		}
	}
}

func TestOpenAIExtract(t *testing.T) {
	d := &OpenAIDissector{}

	tests := []struct {
		fixtureID        string
		wantSessionID    string
		wantModel        string
		wantMinMsgCount  int
		wantSystemBlocks bool
	}{
		// Utility: title generator, no session, gpt-5-nano
		{"openai_1163", "", "gpt-5-nano", 2, true},
		// First subagent turn: session, gpt-5.1, user + developer
		{"openai_1166", "ses_2fd479e75ffepAe8R23CkidGZC", "gpt-5.1", 1, true},
		// Mid-conversation with tool calls: reasoning + function_call + function_call_output
		{"openai_1170", "ses_2fd479e84ffeWtEMMxa6aH6Smi", "gpt-5.1", 3, true},
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
			if result.MessageCount < tt.wantMinMsgCount {
				t.Errorf("MessageCount = %d, want >= %d", result.MessageCount, tt.wantMinMsgCount)
			}
			if tt.wantSystemBlocks && len(result.SystemBlocks) == 0 {
				t.Error("expected system blocks to be non-empty")
			}
		})
	}
}

func TestOpenAIExtractSSEResponse(t *testing.T) {
	d := &OpenAIDissector{}

	// 1163: simple text response (title generator)
	t.Run("text_response", func(t *testing.T) {
		f := loadFixture(t, "openai_1163")
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
		if result.SSEResponse.Text == "" {
			t.Error("expected SSE response to have text")
		}
	})

	// 1170: function call response
	t.Run("function_call_response", func(t *testing.T) {
		f := loadFixture(t, "openai_1170")
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
		if len(result.SSEResponse.ToolCalls) == 0 {
			t.Error("expected SSE response to have tool calls")
		}
	})
}

func TestOpenAIExtractToolCalls(t *testing.T) {
	d := &OpenAIDissector{}
	f := loadFixture(t, "openai_1170")

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

	// Should have function_call and function_call_output parsed as messages
	hasToolUse := false
	hasToolResult := false
	for _, msg := range result.Messages {
		for _, cb := range msg.Content {
			if cb.Type == "tool_use" {
				hasToolUse = true
				if cb.Name == "" {
					t.Error("tool_use block has empty Name")
				}
			}
			if cb.Type == "tool_result" {
				hasToolResult = true
			}
		}
	}
	if !hasToolUse {
		t.Error("expected at least one tool_use content block from function_call items")
	}
	if !hasToolResult {
		t.Error("expected at least one tool_result content block from function_call_output items")
	}
}

func TestOpenAIClassifyThread(t *testing.T) {
	d := &OpenAIDissector{}

	// Utility: title generator (short developer prompt, no tools)
	t.Run("utility", func(t *testing.T) {
		f := loadFixture(t, "openai_1163")
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
		threadType := ClassifyThread("openai", result.SystemBlocks, result.Tools)
		if threadType != "utility" {
			t.Errorf("expected utility for title generator (no tools), got %q", threadType)
		}
	})

	// Subagent: 7 tools (no task/question/todowrite), developer prompt truncated in fixture
	t.Run("subagent_fixture", func(t *testing.T) {
		f := loadFixture(t, "openai_1166")
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
		if len(result.Tools) != 7 {
			t.Errorf("expected 7 tools, got %d", len(result.Tools))
		}
		threadType := ClassifyThread("openai", result.SystemBlocks, result.Tools)
		// Has tools but no management tools (task/question/todowrite) -> subagent
		if threadType != "subagent" {
			t.Errorf("expected subagent for 7-tool session without task tool, got %q", threadType)
		}
	})
}

func TestOpenAIClassifyThreadDirect(t *testing.T) {
	sysBlocks := []SystemBlock{{Type: "text", Text: "You are a coding agent..."}}

	tests := []struct {
		name  string
		tools []Tool
		want  string
	}{
		{
			"main with task tool",
			[]Tool{{Name: "question"}, {Name: "bash"}, {Name: "read"}, {Name: "task"}, {Name: "webfetch"}},
			"main",
		},
		{
			"subagent without management tools",
			[]Tool{{Name: "bash"}, {Name: "read"}, {Name: "glob"}, {Name: "grep"}, {Name: "webfetch"}},
			"subagent",
		},
		{
			"utility no tools",
			nil,
			"utility",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyThread("openai", sysBlocks, tt.tools)
			if got != tt.want {
				t.Errorf("ClassifyThread(openai) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindDissectorOpenAI(t *testing.T) {
	d := FindDissector("https://api.openai.com/v1/responses", "POST", "api.openai.com")
	if d == nil {
		t.Fatal("expected to find OpenAI dissector")
	}
	if d.Name() != "openai" {
		t.Errorf("expected dissector name 'openai', got %q", d.Name())
	}
}

func TestOpenAIToolSummary(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		input    map[string]any
		want     string
	}{
		{"bash with command", "bash", map[string]any{"command": "ls -la"}, "ls -la"},
		{"read file", "read", map[string]any{"file_path": "/home/user/src/main.go"}, "src/main.go"},
		{"webfetch", "webfetch", map[string]any{"url": "https://example.com"}, "https://example.com"},
		{"grep", "grep", map[string]any{"pattern": "TODO", "path": "/src"}, "pattern: TODO in src"},
		{"glob", "glob", map[string]any{"pattern": "**/*.go"}, "**/*.go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractToolSummary(tt.toolName, tt.input)
			if got != tt.want {
				t.Errorf("ExtractToolSummary(%q, ...) = %q, want %q", tt.toolName, got, tt.want)
			}
		})
	}
}
