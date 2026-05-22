package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
)

// setupLLMRouter builds a gin engine with the /api/llm/* routes wired to
// a Shared that has a real DB-backed llmproxy.Store. When withStore is
// false, LLMStore is left nil to exercise the 503-disabled path.
func setupLLMRouter(t *testing.T, withStore bool) (*gin.Engine, *Shared) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := setupTestShared(t)
	if withStore {
		s.LLMStore = llmproxy.NewStore(s.DB, testEncryptionKey())
	}

	r := gin.New()
	api := r.Group("/api")
	api.GET("/llm/providers", LLMProvidersListHandler(s))
	api.POST("/llm/providers", LLMProvidersCreateHandler(s))
	api.GET("/llm/providers/:id", LLMProvidersGetHandler(s))
	api.PUT("/llm/providers/:id", LLMProvidersUpdateHandler(s))
	api.DELETE("/llm/providers/:id", LLMProvidersDeleteHandler(s))
	api.GET("/llm/aliases", LLMAliasesListHandler(s))
	api.POST("/llm/aliases", LLMAliasesCreateHandler(s))
	api.GET("/llm/aliases/:id", LLMAliasesGetHandler(s))
	api.PUT("/llm/aliases/:id", LLMAliasesUpdateHandler(s))
	api.DELETE("/llm/aliases/:id", LLMAliasesDeleteHandler(s))
	api.GET("/llm/provider-types", LLMProviderTypesHandler())
	return r, s
}

func doJSON(t *testing.T, r http.Handler, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr *bytes.Buffer
	if body != "" {
		rdr = bytes.NewBufferString(body)
	} else {
		rdr = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

func TestAPI_ProviderCRUD(t *testing.T) {
	r, _ := setupLLMRouter(t, true)

	// Create
	rec, body := doJSON(t, r, "POST", "/api/llm/providers",
		`{"name":"openai-cloud","type":"openai","base_url":"https://api.openai.com","api_key":"sk-secret-123456"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status: %d body=%s", rec.Code, rec.Body.String())
	}
	id := int64(body["id"].(float64))
	if id == 0 {
		t.Fatal("no id returned")
	}
	// Secret never returned in plaintext.
	if s := rec.Body.String(); strings.Contains(s, "sk-secret-123456") {
		t.Fatalf("plaintext api_key leaked in create response: %s", s)
	}
	if body["key_set"] != true {
		t.Fatalf("key_set should be true: %v", body["key_set"])
	}

	// List
	rec, body = doJSON(t, r, "GET", "/api/llm/providers", "")
	if rec.Code != 200 {
		t.Fatalf("list status: %d", rec.Code)
	}
	if items := body["items"].([]any); len(items) != 1 {
		t.Fatalf("list len: %d", len(items))
	}

	// Get
	rec, body = doJSON(t, r, "GET", "/api/llm/providers/1", "")
	if rec.Code != 200 || body["name"] != "openai-cloud" {
		t.Fatalf("get: %d %v", rec.Code, body)
	}

	// Update base_url, leave key
	rec, _ = doJSON(t, r, "PUT", "/api/llm/providers/1", `{"base_url":"https://proxy.local"}`)
	if rec.Code != 200 {
		t.Fatalf("update status: %d", rec.Code)
	}
	rec, body = doJSON(t, r, "GET", "/api/llm/providers/1", "")
	if body["base_url"] != "https://proxy.local" {
		t.Fatalf("update did not persist: %v", body["base_url"])
	}

	// Delete
	rec, _ = doJSON(t, r, "DELETE", "/api/llm/providers/1", "")
	if rec.Code != 200 {
		t.Fatalf("delete status: %d", rec.Code)
	}
	rec, _ = doJSON(t, r, "GET", "/api/llm/providers/1", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete status: %d", rec.Code)
	}
}

func TestAPI_ProviderCreateBadInput(t *testing.T) {
	r, _ := setupLLMRouter(t, true)
	// Missing required fields → 400.
	rec, _ := doJSON(t, r, "POST", "/api/llm/providers", `{"name":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAPI_ProviderDuplicateName(t *testing.T) {
	r, _ := setupLLMRouter(t, true)
	doJSON(t, r, "POST", "/api/llm/providers", `{"name":"dup","type":"openai","base_url":"https://x"}`)
	rec, _ := doJSON(t, r, "POST", "/api/llm/providers", `{"name":"dup","type":"openai","base_url":"https://y"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate, got %d", rec.Code)
	}
}

func TestAPI_ProviderDeleteInUseReturns409(t *testing.T) {
	r, _ := setupLLMRouter(t, true)
	doJSON(t, r, "POST", "/api/llm/providers", `{"name":"p","type":"openai","base_url":"https://x"}`)
	doJSON(t, r, "POST", "/api/llm/aliases", `{"name":"fast","provider_id":1,"model_id":"gpt-4o"}`)
	rec, _ := doJSON(t, r, "DELETE", "/api/llm/providers/1", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestAPI_AliasCRUD(t *testing.T) {
	r, _ := setupLLMRouter(t, true)
	doJSON(t, r, "POST", "/api/llm/providers", `{"name":"p","type":"openai","base_url":"https://x"}`)

	rec, body := doJSON(t, r, "POST", "/api/llm/aliases",
		`{"name":"fast","provider_id":1,"model_id":"gpt-4o-mini","fallbacks":["p/gpt-4o"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create alias: %d body=%s", rec.Code, rec.Body.String())
	}
	if body["model_id"] != "gpt-4o-mini" {
		t.Fatalf("model_id: %v", body["model_id"])
	}

	rec, body = doJSON(t, r, "GET", "/api/llm/aliases", "")
	if len(body["items"].([]any)) != 1 {
		t.Fatalf("list aliases: %v", body["items"])
	}

	rec, _ = doJSON(t, r, "PUT", "/api/llm/aliases/1", `{"model_id":"gpt-4o"}`)
	if rec.Code != 200 {
		t.Fatalf("update alias: %d", rec.Code)
	}
	rec, body = doJSON(t, r, "GET", "/api/llm/aliases/1", "")
	if body["model_id"] != "gpt-4o" {
		t.Fatalf("alias update not persisted: %v", body["model_id"])
	}

	rec, _ = doJSON(t, r, "DELETE", "/api/llm/aliases/1", "")
	if rec.Code != 200 {
		t.Fatalf("delete alias: %d", rec.Code)
	}
}

func TestAPI_AliasCreateUnknownProvider(t *testing.T) {
	r, _ := setupLLMRouter(t, true)
	rec, _ := doJSON(t, r, "POST", "/api/llm/aliases", `{"name":"x","provider_id":999,"model_id":"m"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAPI_GetUnknownIDs(t *testing.T) {
	r, _ := setupLLMRouter(t, true)
	rec, _ := doJSON(t, r, "GET", "/api/llm/providers/123", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("provider 404: got %d", rec.Code)
	}
	rec, _ = doJSON(t, r, "GET", "/api/llm/aliases/123", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("alias 404: got %d", rec.Code)
	}
	rec, _ = doJSON(t, r, "GET", "/api/llm/providers/not-an-int", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("provider bad-id: got %d", rec.Code)
	}
}

func TestAPI_DisabledWhenNoStore(t *testing.T) {
	r, _ := setupLLMRouter(t, false)
	for _, path := range []string{"/api/llm/providers", "/api/llm/aliases"} {
		rec, _ := doJSON(t, r, "GET", path, "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: expected 503 when store nil, got %d", path, rec.Code)
		}
	}
}

func TestAPI_ProviderTypes(t *testing.T) {
	r, _ := setupLLMRouter(t, true)
	rec, body := doJSON(t, r, "GET", "/api/llm/provider-types", "")
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	items := body["items"].([]any)
	found := map[string]bool{}
	for _, it := range items {
		found[it.(string)] = true
	}
	for _, want := range []string{"openai", "openai-compat", "openrouter"} {
		if !found[want] {
			t.Errorf("provider-types missing %q: %v", want, items)
		}
	}
}
