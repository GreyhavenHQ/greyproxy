package greyproxy

import "testing"

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		// Exact match
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "api.anthropic.com", false},

		// Wildcard prefix
		{"*.local", "litellm.local", true},
		{"*.local", "ollama.local", true},
		{"*.local", "api.openai.com", false},

		// Wildcard suffix
		{"/v1/chat/*", "/v1/chat/completions", true},
		{"/v1/chat/*", "/v1/responses", false},

		// Wildcard in the middle
		{"/v1beta/models/*/generate", "/v1beta/models/gemini-pro/generate", true},
		{"/v1beta/models/*", "/v1beta/models/gemini-2.5-pro:streamGenerateContent", true},

		// Multiple wildcards
		{"*openai*", "api.openai.com", true},
		{"*openai*", "my.proxy.openai.relay.local", true},
		{"*openai*", "api.anthropic.com", false},

		// Empty and edge cases
		{"*", "", true},
		{"*", "anything", true},
		{"", "", true},
		{"", "nonempty", false},

		// No wildcard, exact match only
		{"/v1/messages", "/v1/messages", true},
		{"/v1/messages", "/v1/messages/extra", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.input, func(t *testing.T) {
			got := matchGlob(tt.pattern, tt.input)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractPath(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		// Full URL with scheme
		{"https://api.openai.com/v1/chat/completions", "/v1/chat/completions"},
		{"https://api.openai.com/v1/chat/completions?model=gpt-4", "/v1/chat/completions"},

		// URL without scheme
		{"api.openai.com/v1/responses", "/v1/responses"},

		// Bare path
		{"/v1/messages", "/v1/messages"},

		// Path with query string
		{"/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse", "/v1beta/models/gemini-2.5-pro:streamGenerateContent"},

		// No path component
		{"api.openai.com", "/"},

		// Root path
		{"https://example.com/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractPath(tt.url)
			if got != tt.want {
				t.Errorf("extractPath(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
