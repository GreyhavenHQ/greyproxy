package llmproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// upstream is a stub OpenAI server used to verify the proxy's end-to-end
// behaviour without hitting the real cloud.
func upstream(t *testing.T, fn func(r *http.Request) (int, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body := fn(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// seedProxy spins up a Server with one provider (pointed at the given
// upstream URL) and one alias ("fast"). Returns the server.
func seedProxy(t *testing.T, upstreamURL string) *Server {
	t.Helper()
	store := newTestStore(t)
	p, err := store.CreateProvider(ProviderInput{
		Name: "openai-cloud", Type: "openai",
		BaseURL: upstreamURL, APIKey: "sk-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAlias(AliasInput{
		Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o-mini",
	}); err != nil {
		t.Fatal(err)
	}
	return NewServer(store, NewStoreRouter(store))
}

func TestServer_OpenAIChat_HappyPath(t *testing.T) {
	var seenAuth, seenPath, seenBody string
	up := upstream(t, func(r *http.Request) (int, string) {
		seenAuth = r.Header.Get("Authorization")
		seenPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		seenBody = string(b)
		return 200, `{
			"id":"chatcmpl-1","model":"gpt-4o-mini","object":"chat.completion",
			"choices":[{"index":0,"finish_reason":"stop",
				"message":{"role":"assistant","content":"Hello!"}}],
			"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}
		}`
	})
	defer up.Close()
	srv := seedProxy(t, up.URL)

	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"fast","messages":[{"role":"user","content":"Hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	if seenAuth != "Bearer sk-test" {
		t.Fatalf("upstream auth: %q", seenAuth)
	}
	if seenPath != "/v1/chat/completions" {
		t.Fatalf("upstream path: %q", seenPath)
	}
	// The body sent to upstream must have the resolved model id, not the
	// alias the client used.
	if !strings.Contains(seenBody, `"model":"gpt-4o-mini"`) {
		t.Fatalf("upstream body missing resolved model: %s", seenBody)
	}
	// Response must be valid OpenAI Chat Completions shape.
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["object"] != "chat.completion" {
		t.Fatalf("object: %v", got["object"])
	}
	choices := got["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "Hello!" {
		t.Fatalf("content: %v", msg["content"])
	}
}

func TestServer_OpenAIChat_UnknownAlias(t *testing.T) {
	srv := seedProxy(t, "http://unreachable")
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"unknown","messages":[{"role":"user","content":"Hi"}]}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	err := got["error"].(map[string]any)
	if err["code"] != "alias_unknown" {
		t.Fatalf("error envelope: %v", err)
	}
}

func TestServer_OpenAIChat_DisabledAlias(t *testing.T) {
	store := newTestStore(t)
	p, _ := store.CreateProvider(ProviderInput{Name: "x", Type: "openai", BaseURL: "http://x"})
	a, _ := store.CreateAlias(AliasInput{Name: "fast", ProviderID: p.ID, ModelID: "y"})
	disabled := false
	if _, err := store.UpdateAlias(a.ID, AliasInput{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, NewStoreRouter(store))

	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"fast","messages":[]}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServer_OpenAIChat_UpstreamError(t *testing.T) {
	up := upstream(t, func(r *http.Request) (int, string) {
		return 503, `{"error":{"message":"upstream down","type":"server_error"}}`
	})
	defer up.Close()
	srv := seedProxy(t, up.URL)

	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"fast","messages":[]}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: %d", rec.Code)
	}
}

func TestServer_ListModels(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("GET", "/v1/models", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	data := got["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("data len: %d", len(data))
	}
	if data[0].(map[string]any)["id"] != "fast" {
		t.Fatalf("data[0].id: %v", data[0])
	}
}

func TestServer_GetSingleModel(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("GET", "/v1/models/fast", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["id"] != "fast" {
		t.Fatalf("id: %v", got["id"])
	}
}

func TestServer_GetSingleModel_NotFound(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("GET", "/v1/models/missing", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: %d", rec.Code)
	}
}

func TestServer_Healthz(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["status"] != "ok" {
		t.Fatalf("status field: %v", got["status"])
	}
}

func TestServer_OPTIONS(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("OPTIONS", "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: %d", rec.Code)
	}
}

func TestServer_UnknownPath(t *testing.T) {
	srv := seedProxy(t, "http://x")
	req := httptest.NewRequest("POST", "/v1/embeddings", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: %d", rec.Code)
	}
}
