package llmproxy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// TestSeedConfig_ViperRoundTrip guards against the snake_case binding
// trap: cmd/greyproxy loads the `llm:` block through viper (mapstructure),
// not the yaml library, so SeedConfig must carry mapstructure tags or
// `base_url`/`api_key` silently bind to nothing.
func TestSeedConfig_ViperRoundTrip(t *testing.T) {
	yml := []byte(`
llm:
  providers:
    - name: openai-cloud
      type: openai
      base_url: https://api.openai.com
      api_key: env:OPENAI_API_KEY
      metadata:
        header.X-Title: greyproxy
    - name: ollama
      type: openai-compat
      base_url: http://localhost:11434/v1
  models:
    - name: fast
      target: openai-cloud/gpt-4o-mini
    - name: smart
      target: openai-cloud/gpt-4o
      fallbacks: [ollama/llama3.2]
`)
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(yml)); err != nil {
		t.Fatal(err)
	}
	var seed SeedConfig
	if err := v.UnmarshalKey("llm", &seed); err != nil {
		t.Fatal(err)
	}

	if len(seed.Providers) != 2 {
		t.Fatalf("providers: got %d, want 2", len(seed.Providers))
	}
	p0 := seed.Providers[0]
	if p0.Name != "openai-cloud" || p0.Type != "openai" {
		t.Fatalf("provider0 name/type: %+v", p0)
	}
	if p0.BaseURL != "https://api.openai.com" {
		t.Fatalf("base_url did not bind (mapstructure tag missing?): %q", p0.BaseURL)
	}
	if p0.APIKey != "env:OPENAI_API_KEY" {
		t.Fatalf("api_key did not bind: %q", p0.APIKey)
	}
	// viper lowercases all map keys; HTTP header names are
	// case-insensitive so this is harmless, but the test must match.
	if p0.Metadata["header.x-title"] != "greyproxy" {
		t.Fatalf("metadata did not bind: %+v", p0.Metadata)
	}

	if len(seed.Models) != 2 {
		t.Fatalf("models: got %d, want 2", len(seed.Models))
	}
	if seed.Models[1].Target != "openai-cloud/gpt-4o" {
		t.Fatalf("model target: %q", seed.Models[1].Target)
	}
	if len(seed.Models[1].Fallbacks) != 1 || seed.Models[1].Fallbacks[0] != "ollama/llama3.2" {
		t.Fatalf("fallbacks did not bind: %+v", seed.Models[1].Fallbacks)
	}
}

// TestEmbeddedYAML_SeedsCleanly loads the shipped greyproxy.yml the same
// way cmd/greyproxy does and seeds a fresh DB from it. Catches drift
// between the default config and the seed code (e.g. a provider type that
// isn't a registered backend, or an alias pointing at an unknown
// provider).
func TestEmbeddedYAML_SeedsCleanly(t *testing.T) {
	path := filepath.Join("..", "..", "..", "greyproxy.yml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("embedded config not found at %s: %v", path, err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(b)); err != nil {
		t.Fatalf("parse embedded yaml: %v", err)
	}
	var seed SeedConfig
	if err := v.UnmarshalKey("llm", &seed); err != nil {
		t.Fatalf("unmarshal llm: %v", err)
	}
	if len(seed.Providers) == 0 {
		t.Fatal("embedded greyproxy.yml has no llm.providers — the default block went missing")
	}

	s := newTestStore(t)
	provs, aliases, err := s.Seed(seed)
	if err != nil {
		t.Fatalf("seed embedded config: %v", err)
	}
	if provs != len(seed.Providers) {
		t.Fatalf("seeded %d providers, want %d", provs, len(seed.Providers))
	}

	// Every seeded provider must carry a non-empty base_url, and every
	// non-auto alias must resolve to one of the seeded providers.
	list, _ := s.ListProviders()
	for _, p := range list {
		if p.BaseURL == "" {
			t.Errorf("provider %q seeded with empty base_url", p.Name)
		}
	}
	t.Logf("embedded config seeded %d providers, %d aliases", provs, aliases)
}
