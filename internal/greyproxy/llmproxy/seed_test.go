package llmproxy

import (
	"os"
	"testing"
)

func TestSeed_PopulatesEmptyDB(t *testing.T) {
	s := newTestStore(t)
	t.Setenv("OPENAI_API_KEY", "sk-from-env-12345678")

	cfg := SeedConfig{
		Providers: []SeedProvider{
			{Name: "openai-cloud", Type: "openai", BaseURL: "https://api.openai.com", APIKey: "env:OPENAI_API_KEY"},
			{Name: "ollama", Type: "openai-compat", BaseURL: "http://localhost:11434/v1"},
		},
		Models: []SeedAlias{
			{Name: "fast", Target: "openai-cloud/gpt-4o-mini"},
			{Name: "local", Target: "ollama/llama3.2"},
		},
	}
	p, a, err := s.Seed(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p != 2 || a != 2 {
		t.Fatalf("seeded p=%d a=%d, want 2/2", p, a)
	}

	// env:NAME indirection: the openai-cloud provider got its key from
	// the environment variable.
	got, _ := s.GetProviderByName("openai-cloud")
	secret, _ := s.GetProviderSecret(got.ID)
	if secret != "sk-from-env-12345678" {
		t.Fatalf("env resolution: got %q", secret)
	}

	// Alias splits provider/model correctly.
	resolved, err := s.ResolveAlias("fast")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Provider.Name != "openai-cloud" || resolved.ModelID != "gpt-4o-mini" {
		t.Fatalf("resolved=%+v", resolved)
	}
}

func TestSeed_SkipsWhenAlreadyPopulated(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateProvider(ProviderInput{Name: "existing", Type: "openai", BaseURL: "https://x"}); err != nil {
		t.Fatal(err)
	}
	cfg := SeedConfig{
		Providers: []SeedProvider{{Name: "openai-cloud", Type: "openai", BaseURL: "https://y"}},
	}
	p, a, err := s.Seed(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p != 0 || a != 0 {
		t.Fatalf("expected no-op, got p=%d a=%d", p, a)
	}
}

func TestSeed_MissingEnvVarYieldsEmptyKey(t *testing.T) {
	_ = os.Unsetenv("LLM_TEST_MISSING_KEY")
	s := newTestStore(t)
	cfg := SeedConfig{
		Providers: []SeedProvider{
			{Name: "p", Type: "openai-compat", BaseURL: "http://x", APIKey: "env:LLM_TEST_MISSING_KEY"},
		},
	}
	if _, _, err := s.Seed(cfg); err != nil {
		t.Fatal(err)
	}
	p, _ := s.GetProviderByName("p")
	if p.KeySet {
		t.Fatal("expected KeySet=false when env var is unset")
	}
}
