package llmproxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_GetModel_Disabled404(t *testing.T) {
	store := newTestStore(t)
	p, _ := store.CreateProvider(ProviderInput{Name: "p", Type: "openai", BaseURL: "http://x"})
	a, _ := store.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "m"})
	disabled := false
	_, _ = store.UpdateAlias(a.ID, AliasInput{Enabled: &disabled})

	srv := NewServer(store, NewStoreRouter(store))
	req := httptest.NewRequest("GET", "/v1/models/fast", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled model should 404, got %d", rec.Code)
	}
}

func TestServer_ChatUnknownProviderType422(t *testing.T) {
	store := newTestStore(t)
	// Provider with a type that has no registered Backend factory.
	p, _ := store.CreateProvider(ProviderInput{Name: "weird", Type: "not-a-backend", BaseURL: "http://x", APIKey: "k"})
	_, _ = store.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "m"})

	srv := NewServer(store, NewStoreRouter(store))
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		bytes.NewBufferString(`{"model":"fast","messages":[]}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown provider type should 422, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServer_ChatMissingModel400(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		bytes.NewBufferString(`{"messages":[]}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing model should 400, got %d", rec.Code)
	}
}

func TestServer_ChatInvalidJSON400(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString("not json"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid json should 400, got %d", rec.Code)
	}
}

func TestGlobalHandler_SetGetClear(t *testing.T) {
	t.Cleanup(func() { SetGlobalHandler(nil) })

	if GlobalHandler() != nil {
		SetGlobalHandler(nil)
	}
	if GlobalHandler() != nil {
		t.Fatal("expected nil before set")
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	SetGlobalHandler(h)
	if GlobalHandler() == nil {
		t.Fatal("expected handler after set")
	}
	SetGlobalHandler(nil)
	if GlobalHandler() != nil {
		t.Fatal("expected nil after clear")
	}
}
