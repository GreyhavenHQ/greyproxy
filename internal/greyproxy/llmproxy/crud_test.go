package llmproxy

import (
	"crypto/rand"
	"errors"
	"os"
	"testing"

	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	_ "modernc.org/sqlite"
)

// newTestStore opens a fresh on-disk SQLite database, runs migrations, and
// hands back a Store wired with a random 32-byte encryption key. The DB
// file is deleted at test end.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	f, err := os.CreateTemp("", "llmproxy_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	db, err := greyproxy.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	return NewStore(db, key)
}

func TestStore_CreateAndGetProvider(t *testing.T) {
	s := newTestStore(t)

	p, err := s.CreateProvider(ProviderInput{
		Name:    "openai-cloud",
		Type:    "openai",
		BaseURL: "https://api.openai.com",
		APIKey:  "sk-test-1234567890abcdef",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == 0 {
		t.Fatalf("expected non-zero ID")
	}
	if !p.KeySet {
		t.Fatalf("KeySet should be true after creating with an api_key")
	}
	if p.KeyPreview == "" {
		t.Fatalf("KeyPreview should be non-empty")
	}

	got, err := s.GetProvider(p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "openai-cloud" || got.Type != "openai" || got.BaseURL != "https://api.openai.com" {
		t.Fatalf("got wrong fields: %+v", got)
	}
	if !got.KeySet || got.KeyPreview != p.KeyPreview {
		t.Fatalf("key fields not roundtripped: got KeySet=%v preview=%q", got.KeySet, got.KeyPreview)
	}

	// The decrypted secret must round-trip via GetProviderSecret (used by
	// the provider plumbing when issuing the upstream call).
	secret, err := s.GetProviderSecret(p.ID)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if secret != "sk-test-1234567890abcdef" {
		t.Fatalf("secret mismatch: got %q", secret)
	}
}

func TestStore_CreateProviderWithoutKey(t *testing.T) {
	s := newTestStore(t)
	p, err := s.CreateProvider(ProviderInput{Name: "ollama", Type: "openai-compat", BaseURL: "http://localhost:11434/v1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.KeySet {
		t.Fatalf("KeySet should be false when api_key is empty")
	}
	if p.KeyPreview != "" {
		t.Fatalf("KeyPreview should be empty when api_key is empty, got %q", p.KeyPreview)
	}
}

func TestStore_DuplicateProviderNameRejected(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateProvider(ProviderInput{Name: "dup", Type: "openai", BaseURL: "https://x"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := s.CreateProvider(ProviderInput{Name: "dup", Type: "openai", BaseURL: "https://y"}); err == nil {
		t.Fatalf("expected duplicate-name error, got nil")
	}
}

func TestStore_ListProviders(t *testing.T) {
	s := newTestStore(t)
	for _, n := range []string{"a", "b", "c"} {
		if _, err := s.CreateProvider(ProviderInput{Name: n, Type: "openai", BaseURL: "https://x"}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListProviders()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(list))
	}
}

func TestStore_UpdateProviderKeepsKeyWhenNotSet(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "x", Type: "openai", BaseURL: "https://a", APIKey: "sk-original-1234"})

	// Update without supplying APIKey: must keep the old key.
	updated, err := s.UpdateProvider(p.ID, ProviderInput{BaseURL: "https://b"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.BaseURL != "https://b" {
		t.Fatalf("base_url not updated")
	}
	secret, err := s.GetProviderSecret(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "sk-original-1234" {
		t.Fatalf("key changed unexpectedly: %q", secret)
	}
}

func TestStore_UpdateProviderRotatesKey(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "x", Type: "openai", BaseURL: "https://a", APIKey: "sk-original"})
	if _, err := s.UpdateProvider(p.ID, ProviderInput{APIKey: "sk-rotated-99999"}); err != nil {
		t.Fatal(err)
	}
	secret, err := s.GetProviderSecret(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "sk-rotated-99999" {
		t.Fatalf("key not rotated: %q", secret)
	}
}

func TestStore_DeleteProvider(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "x", Type: "openai", BaseURL: "https://a"})
	if err := s.DeleteProvider(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetProvider(p.ID); err == nil {
		t.Fatal("expected not-found after delete")
	}
}

func TestStore_DeleteProviderRejectedWhenReferenced(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "https://a"})
	if _, err := s.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o-mini"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProvider(p.ID); err == nil {
		t.Fatal("expected delete to be rejected when alias references provider")
	}
}

// Alias CRUD ----------------------------------------------------------------

func TestStore_CreateAndGetAlias(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "openai", Type: "openai", BaseURL: "https://api.openai.com", APIKey: "sk-x"})

	a, err := s.CreateAlias(AliasInput{
		Name:       "fast",
		ProviderID: p.ID,
		ModelID:    "gpt-4o-mini",
		Fallbacks:  []string{"openai/gpt-4o"},
	})
	if err != nil {
		t.Fatalf("create alias: %v", err)
	}
	if a.ID == 0 || a.Name != "fast" || a.ModelID != "gpt-4o-mini" || a.ProviderID != p.ID {
		t.Fatalf("bad alias: %+v", a)
	}
	if len(a.Fallbacks) != 1 || a.Fallbacks[0] != "openai/gpt-4o" {
		t.Fatalf("fallbacks not roundtripped: %+v", a.Fallbacks)
	}
}

func TestStore_ResolveAliasByName(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "openai", Type: "openai", BaseURL: "https://api.openai.com", APIKey: "sk-x"})
	_, err := s.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o-mini"})
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := s.ResolveAlias("fast")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Provider.Type != "openai" {
		t.Fatalf("wrong provider type: %s", resolved.Provider.Type)
	}
	if resolved.ModelID != "gpt-4o-mini" {
		t.Fatalf("wrong model id: %s", resolved.ModelID)
	}
}

func TestStore_ResolveAliasUnknownReturnsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.ResolveAlias("does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStore_ResolveAliasDisabled(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "openai", Type: "openai", BaseURL: "https://x", APIKey: "k"})
	disabled := false
	a, _ := s.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o"})
	if _, err := s.UpdateAlias(a.ID, AliasInput{Enabled: &disabled, ProviderID: p.ID, ModelID: "gpt-4o", Name: "fast"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.ResolveAlias("fast")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
}

func TestStore_ResolveAliasProviderDisabled(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreateProvider(ProviderInput{Name: "openai", Type: "openai", BaseURL: "https://x", APIKey: "k"})
	_, _ = s.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o"})

	disabled := false
	if _, err := s.UpdateProvider(p.ID, ProviderInput{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAlias("fast"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled when provider disabled, got %v", err)
	}
}
