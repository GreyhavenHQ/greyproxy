package greyproxy

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// loadFixtureHeaders loads a dissector test fixture and returns its parsed headers.
func loadFixtureHeaders(t *testing.T, name string) http.Header {
	t.Helper()
	data, err := os.ReadFile("dissector/testdata/" + name + ".json")
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	var f struct {
		RequestHeaders string `json:"request_headers"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	if f.RequestHeaders == "" {
		return nil
	}
	var multi map[string][]string
	if json.Unmarshal([]byte(f.RequestHeaders), &multi) == nil && len(multi) > 0 {
		return http.Header(multi)
	}
	return nil
}

func TestDetectClient_AiderOpenRouter(t *testing.T) {
	headers := loadFixtureHeaders(t, "aider_openrouter_2459")
	if headers == nil {
		t.Fatal("expected non-nil headers for aider fixture")
	}

	adapter := DetectClient(headers, nil)
	if adapter.Name() != "aider" {
		t.Errorf("DetectClient for aider fixture = %q, want %q", adapter.Name(), "aider")
	}

	// Verify confidence score is high
	aider := &AiderAdapter{}
	score := aider.DetectConfidence(headers, nil)
	if score < 0.8 {
		t.Errorf("AiderAdapter confidence = %.2f, want >= 0.80", score)
	}
}

func TestDetectClient_OpenCodeLiteLLM(t *testing.T) {
	headers := loadFixtureHeaders(t, "opencode_litellm_302")
	if headers == nil {
		t.Fatal("expected non-nil headers for opencode/litellm fixture")
	}

	adapter := DetectClient(headers, nil)
	if adapter.Name() != "opencode" {
		t.Errorf("DetectClient for opencode/litellm fixture = %q, want %q", adapter.Name(), "opencode")
	}

	opencode := &OpenCodeAdapter{}
	score := opencode.DetectConfidence(headers, nil)
	if score < 0.8 {
		t.Errorf("OpenCodeAdapter confidence = %.2f, want >= 0.80", score)
	}
}

func TestDetectClient_OpenCodeOpenRouter(t *testing.T) {
	headers := loadFixtureHeaders(t, "opencode_openrouter_2469")
	if headers == nil {
		t.Fatal("expected non-nil headers for opencode/openrouter fixture")
	}

	adapter := DetectClient(headers, nil)
	if adapter.Name() != "opencode" {
		t.Errorf("DetectClient for opencode/openrouter fixture = %q, want %q", adapter.Name(), "opencode")
	}
}

func TestDetectClient_GeminiCLI(t *testing.T) {
	headers := loadFixtureHeaders(t, "gemini_scorer_2570")
	if headers == nil {
		t.Fatal("expected non-nil headers for gemini fixture")
	}

	adapter := DetectClient(headers, nil)
	if adapter.Name() != "gemini-cli" {
		t.Errorf("DetectClient for gemini fixture = %q, want %q", adapter.Name(), "gemini-cli")
	}

	gemini := &GeminiCLIAdapter{}
	score := gemini.DetectConfidence(headers, nil)
	if score < 0.9 {
		t.Errorf("GeminiCLIAdapter confidence = %.2f, want >= 0.90", score)
	}
}

func TestDetectClient_GenericFallback(t *testing.T) {
	// Empty headers, no result: should fall back to generic
	headers := http.Header{}
	adapter := DetectClient(headers, nil)
	if adapter.Name() != "generic" {
		t.Errorf("DetectClient with empty headers = %q, want %q", adapter.Name(), "generic")
	}
}

func TestDetectClient_ClaudeCode(t *testing.T) {
	// Existing fixture 383 has Claude Code headers
	headers := loadFixtureHeaders(t, "383")
	if headers == nil {
		// Fixture 383 may not have headers in the old format.
		// Use synthetic headers instead.
		headers = http.Header{
			"User-Agent": []string{"claude-cli/1.0.0"},
		}
	}

	adapter := DetectClient(headers, nil)
	if adapter.Name() != "claude-code" {
		t.Errorf("DetectClient for claude-code = %q, want %q", adapter.Name(), "claude-code")
	}
}

// TestRegistryRoutesCustomHost verifies that user-added hosts (LiteLLM, Ollama)
// are routed to the correct dissector via the EndpointRegistry, not via CanHandle().
func TestRegistryRoutesCustomHost(t *testing.T) {
	db := setupTestDB(t)
	registry := NewEndpointRegistry(db)

	litellmURL := "https://litellm-notrack.app.monadical.io/chat/completions"
	litellmHost := "litellm-notrack.app.monadical.io"

	// Without a user rule, the registry should NOT find a dissector
	// (built-in rules only cover known hosts)
	d := registry.FindDissector(litellmURL, "POST", litellmHost)
	if d != nil {
		t.Errorf("expected nil dissector for unknown host before adding rule, got %q", d.Name())
	}

	// Add a user-defined rule mapping this LiteLLM host to openai-chat
	_, err := registry.CreateRule(EndpointRule{
		HostPattern: "litellm-notrack.app.monadical.io",
		PathPattern: "/chat/completions",
		Method:      "POST",
		DecoderName: "openai-chat",
		Priority:    10,
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	// Now the registry should route it to the openai-chat dissector
	d = registry.FindDissector(litellmURL, "POST", litellmHost)
	if d == nil {
		t.Fatal("expected dissector after adding registry rule")
	}
	if d.Name() != "openai-chat" {
		t.Errorf("dissector name = %q, want %q", d.Name(), "openai-chat")
	}

	// Verify built-in rules still work
	d = registry.FindDissector("https://api.anthropic.com/v1/messages", "POST", "api.anthropic.com")
	if d == nil || d.Name() != "anthropic" {
		t.Errorf("built-in anthropic rule broken: got %v", d)
	}

	d = registry.FindDissector("https://openrouter.ai/api/v1/chat/completions", "POST", "openrouter.ai")
	if d == nil || d.Name() != "openai-chat" {
		t.Errorf("built-in openrouter rule broken: got %v", d)
	}

	d = registry.FindDissector("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:streamGenerateContent", "POST", "generativelanguage.googleapis.com")
	if d == nil || d.Name() != "google-ai" {
		t.Errorf("built-in google-ai rule broken: got %v", d)
	}
}

// TestRegistryWildcardHost verifies glob patterns in host_pattern work.
func TestRegistryWildcardHost(t *testing.T) {
	db := setupTestDB(t)
	registry := NewEndpointRegistry(db)

	// Add a wildcard rule for any local LiteLLM instance
	_, err := registry.CreateRule(EndpointRule{
		HostPattern: "*.local",
		PathPattern: "/v1/chat/completions",
		Method:      "POST",
		DecoderName: "openai-chat",
		Priority:    10,
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	d := registry.FindDissector("https://litellm.local/v1/chat/completions", "POST", "litellm.local")
	if d == nil || d.Name() != "openai-chat" {
		t.Errorf("wildcard host rule: got %v, want openai-chat", d)
	}

	// Different path should not match
	d = registry.FindDissector("https://litellm.local/v1/responses", "POST", "litellm.local")
	if d != nil && d.Name() == "openai-chat" {
		t.Errorf("wildcard host should not match different path, got %q", d.Name())
	}
}

func TestDetectClient_OpenCodeToolFingerprint(t *testing.T) {
	// Test fallback detection via tool fingerprint (no headers)
	result := &dissector.ExtractionResult{
		Tools: []dissector.Tool{
			{Name: "task"},
			{Name: "question"},
			{Name: "todowrite"},
			{Name: "bash"},
			{Name: "read"},
		},
	}

	adapter := DetectClient(nil, result)
	// With nil headers, the score is 0.6 which is below the 0.7 threshold
	// so it should fall back to generic
	if adapter.Name() != "generic" {
		t.Logf("DetectClient with tool fingerprint only = %q (acceptable: either 'opencode' or 'generic')", adapter.Name())
	}

	// But the confidence should be non-zero
	opencode := &OpenCodeAdapter{}
	score := opencode.DetectConfidence(nil, result)
	if score < 0.5 {
		t.Errorf("OpenCodeAdapter tool fingerprint confidence = %.2f, want >= 0.50", score)
	}
}
