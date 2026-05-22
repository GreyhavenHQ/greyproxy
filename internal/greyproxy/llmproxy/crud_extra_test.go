package llmproxy

import (
	"context"
	"errors"
	"testing"
)

func TestStore_DeleteAlias(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "https://x"})
	a, _ := s.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o"})

	if err := s.DeleteAlias(a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetAlias(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	// Deleting again is a not-found.
	if err := s.DeleteAlias(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-delete: %v", err)
	}
	// And the provider can now be deleted (no references left).
	if err := s.DeleteProvider(p.ID); err != nil {
		t.Fatalf("provider delete after alias gone: %v", err)
	}
}

func TestStore_UpdateProviderMetadataAndEnabled(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "https://x"})

	disabled := false
	updated, err := s.UpdateProvider(p.ID, ProviderInput{
		Metadata: map[string]string{"header.X-Title": "grey"},
		Enabled:  &disabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled {
		t.Fatal("provider should be disabled")
	}
	if updated.Metadata["header.X-Title"] != "grey" {
		t.Fatalf("metadata: %+v", updated.Metadata)
	}
}

func TestStore_UpdateProviderNoFieldsIsNoop(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "https://x", APIKey: "sk-keep"})
	if _, err := s.UpdateProvider(p.ID, ProviderInput{}); err != nil {
		t.Fatal(err)
	}
	secret, _ := s.GetProviderSecret(p.ID)
	if secret != "sk-keep" {
		t.Fatalf("noop update changed key: %q", secret)
	}
}

func TestStore_UpdateProviderNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.UpdateProvider(999, ProviderInput{BaseURL: "https://y"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStore_UpdateAliasFallbacksAndModel(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "https://x"})
	a, _ := s.CreateAlias(AliasInput{Name: "smart", ProviderID: p.ID, ModelID: "gpt-4o"})

	updated, err := s.UpdateAlias(a.ID, AliasInput{
		ModelID:   "gpt-4o-2025",
		Fallbacks: []string{"p/gpt-4o-mini", "p/gpt-3.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ModelID != "gpt-4o-2025" {
		t.Fatalf("model: %q", updated.ModelID)
	}
	if len(updated.Fallbacks) != 2 {
		t.Fatalf("fallbacks: %+v", updated.Fallbacks)
	}
}

func TestStore_UpdateAliasIsAutoAndRules(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "https://x"})
	a, _ := s.CreateAlias(AliasInput{Name: "auto", ProviderID: p.ID, ModelID: "gpt-4o"})

	yes := true
	updated, err := s.UpdateAlias(a.ID, AliasInput{
		IsAuto:    &yes,
		AutoRules: []any{map[string]any{"if": map[string]any{"complexity": "high"}, "target": "smart"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.IsAuto {
		t.Fatal("is_auto should be true")
	}
	if len(updated.AutoRules) != 1 {
		t.Fatalf("auto rules: %+v", updated.AutoRules)
	}
}

func TestStore_UpdateAliasNoFieldsIsNoop(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "https://x"})
	a, _ := s.CreateAlias(AliasInput{Name: "x", ProviderID: p.ID, ModelID: "m"})
	got, err := s.UpdateAlias(a.ID, AliasInput{})
	if err != nil {
		t.Fatal(err)
	}
	if got.ModelID != "m" {
		t.Fatalf("noop changed model: %q", got.ModelID)
	}
}

func TestStore_GetProviderByNameNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetProviderByName("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStore_ListOrdersByName(t *testing.T) {
	s := newTestStore(t)
	for _, n := range []string{"zebra", "alpha", "mike"} {
		if _, err := s.CreateProvider(ProviderInput{Name: n, Type: "openai", BaseURL: "https://x"}); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := s.ListProviders()
	if list[0].Name != "alpha" || list[1].Name != "mike" || list[2].Name != "zebra" {
		t.Fatalf("not name-ordered: %v", []string{list[0].Name, list[1].Name, list[2].Name})
	}

	// Aliases too.
	pid := list[0].ID
	for _, n := range []string{"gamma", "beta"} {
		if _, err := s.CreateAlias(AliasInput{Name: n, ProviderID: pid, ModelID: "m"}); err != nil {
			t.Fatal(err)
		}
	}
	aliases, _ := s.ListAliases()
	if aliases[0].Name != "beta" || aliases[1].Name != "gamma" {
		t.Fatalf("aliases not name-ordered: %+v", aliases)
	}
}

func TestStore_CreateAliasUnknownProviderRejected(t *testing.T) {
	s := newTestStore(t)
	// provider_id references a non-existent provider; CreateAlias does an
	// application-level existence check (SQLite FK isn't enforced under
	// the modernc driver).
	_, err := s.CreateAlias(AliasInput{Name: "x", ProviderID: 4242, ModelID: "m"})
	if !errors.Is(err, ErrBadInput) {
		t.Fatalf("expected ErrBadInput for unknown provider, got %v", err)
	}
}

func TestStoreRouter_ResolveDelegatesToStore(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "openai", Type: "openai", BaseURL: "https://x", APIKey: "k"})
	_, _ = s.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o-mini"})

	r := NewStoreRouter(s)
	resolved, err := r.Resolve(context.Background(), &ChatRequest{Model: "fast"})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ModelID != "gpt-4o-mini" || resolved.Provider.Name != "openai" {
		t.Fatalf("resolved: %+v", resolved)
	}

	if _, err := r.Resolve(context.Background(), &ChatRequest{Model: "ghost"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
