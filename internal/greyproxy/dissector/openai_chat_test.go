package dissector

import (
	"testing"
)

func TestOpenAIChatCanHandle(t *testing.T) {
	d := &OpenAIChatDissector{}

	tests := []struct {
		url, method, host string
		want              bool
	}{
		// Standard OpenAI chat completions (not used in practice, but the URL matches)
		{"https://api.openai.com/v1/chat/completions", "POST", "api.openai.com", true},
		// OpenRouter path
		{"https://openrouter.ai/api/v1/chat/completions", "POST", "openrouter.ai", true},
		// LiteLLM: unknown host, NOT matched by CanHandle (routed via EndpointRegistry)
		{"https://litellm-notrack.app.monadical.io/chat/completions", "POST", "litellm-notrack.app.monadical.io", false},
		// With query string
		{"https://openrouter.ai/api/v1/chat/completions?stream=true", "POST", "openrouter.ai", true},
		// GET should not match
		{"https://openrouter.ai/api/v1/chat/completions", "GET", "openrouter.ai", false},
		// OpenAI responses endpoint should NOT match
		{"https://api.openai.com/v1/responses", "POST", "api.openai.com", false},
		// Anthropic should NOT match
		{"https://api.anthropic.com/v1/messages", "POST", "api.anthropic.com", false},
		// Google AI should NOT match
		{"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent", "POST", "generativelanguage.googleapis.com", false},
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

func TestOpenAIChatExtract_AiderNonStreaming(t *testing.T) {
	d := &OpenAIChatDissector{}
	f := loadFixture(t, "aider_openrouter_2459")

	result := extractFromFixture(t, d, f)

	// Aider via OpenRouter: model should be anthropic/claude-sonnet-4
	if result.Model != "anthropic/claude-sonnet-4" {
		t.Errorf("Model = %q, want %q", result.Model, "anthropic/claude-sonnet-4")
	}

	// Aider has no prompt_cache_key, so session should be empty
	if result.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", result.SessionID)
	}

	// Should have system blocks (system message)
	if len(result.SystemBlocks) == 0 {
		t.Error("expected system blocks from system message")
	}

	// Should have messages (user + assistant messages)
	if result.MessageCount < 5 {
		t.Errorf("MessageCount = %d, want >= 5", result.MessageCount)
	}

	// Aider has no tools in this fixture
	if len(result.Tools) != 0 {
		t.Errorf("Tools count = %d, want 0", len(result.Tools))
	}

	// Non-streaming response should be parsed
	if result.SSEResponse == nil {
		t.Fatal("expected SSEResponse to be non-nil for non-streaming response")
	}
	if result.SSEResponse.Text == "" {
		t.Error("expected non-empty response text")
	}
}

func TestOpenAIChatExtract_OpenCodeLiteLLMStreaming(t *testing.T) {
	d := &OpenAIChatDissector{}
	f := loadFixture(t, "opencode_litellm_302")

	result := extractFromFixture(t, d, f)

	// OpenCode via LiteLLM: model should be Minimax-M2.5-noiac
	if result.Model != "Minimax-M2.5-noiac" {
		t.Errorf("Model = %q, want %q", result.Model, "Minimax-M2.5-noiac")
	}

	// LiteLLM has no prompt_cache_key, so session should be empty
	if result.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", result.SessionID)
	}

	// Should have system blocks
	if len(result.SystemBlocks) == 0 {
		t.Error("expected system blocks")
	}

	// Should have user message
	if result.MessageCount < 1 {
		t.Errorf("MessageCount = %d, want >= 1", result.MessageCount)
	}

	// Should have tools (opencode sends tools)
	if len(result.Tools) < 5 {
		t.Errorf("Tools count = %d, want >= 5", len(result.Tools))
	}

	// Streaming SSE response should be parsed
	if result.SSEResponse == nil {
		t.Fatal("expected SSEResponse to be non-nil for streaming response")
	}
	if result.SSEResponse.Text == "" && len(result.SSEResponse.ToolCalls) == 0 {
		t.Error("expected SSE response to have text or tool calls")
	}
}

func TestOpenAIChatExtract_OpenCodeOpenRouter(t *testing.T) {
	d := &OpenAIChatDissector{}
	f := loadFixture(t, "opencode_openrouter_2469")

	result := extractFromFixture(t, d, f)

	// OpenCode via OpenRouter: model should be openai/gpt-5.4
	if result.Model != "openai/gpt-5.4" {
		t.Errorf("Model = %q, want %q", result.Model, "openai/gpt-5.4")
	}

	// OpenCode via OpenRouter uses prompt_cache_key for session
	if result.SessionID == "" {
		t.Error("expected non-empty SessionID from prompt_cache_key")
	}

	// Should have system blocks
	if len(result.SystemBlocks) == 0 {
		t.Error("expected system blocks")
	}

	// Should have tools
	if len(result.Tools) < 5 {
		t.Errorf("Tools count = %d, want >= 5", len(result.Tools))
	}

	// Streaming SSE response
	if result.SSEResponse == nil {
		t.Fatal("expected SSEResponse to be non-nil")
	}
}

func TestFindDissectorOpenAIChat(t *testing.T) {
	// Known hosts are matched by CanHandle (fallback path)
	d := FindDissector("https://openrouter.ai/api/v1/chat/completions", "POST", "openrouter.ai")
	if d == nil {
		t.Fatal("expected to find dissector for openrouter.ai")
	}
	if d.Name() != "openai-chat" {
		t.Errorf("dissector name = %q, want %q", d.Name(), "openai-chat")
	}

	// Unknown hosts (LiteLLM, Ollama, etc.) are NOT found by FindDissector.
	// They must be routed via EndpointRegistry.FindDissector() which maps
	// user-added host patterns to decoder names.
	d = FindDissector("https://litellm-notrack.app.monadical.io/chat/completions", "POST", "litellm-notrack.app.monadical.io")
	if d != nil {
		t.Errorf("expected nil for unknown host, got %q (should be routed via registry)", d.Name())
	}
}

func TestOpenAIChatClassifyThread(t *testing.T) {
	d := &OpenAIChatDissector{}

	t.Run("aider_no_tools", func(t *testing.T) {
		f := loadFixture(t, "aider_openrouter_2459")
		result := extractFromFixture(t, d, f)

		threadType := ClassifyThread("openai-chat", result.SystemBlocks, result.Tools)
		// Aider has no tools but system prompt > 1000 chars, so the default
		// heuristic classifies as "subagent". Proper classification happens
		// at the ClientAdapter level (AiderAdapter.ClassifyThread returns "main").
		if threadType == "" {
			t.Error("expected non-empty thread type")
		}
	})

	t.Run("opencode_with_tools", func(t *testing.T) {
		f := loadFixture(t, "opencode_litellm_302")
		result := extractFromFixture(t, d, f)

		threadType := ClassifyThread("openai-chat", result.SystemBlocks, result.Tools)
		// OpenCode has tools; check what tools are present to predict thread type
		if threadType == "" {
			t.Error("expected non-empty thread type")
		}
	})
}
