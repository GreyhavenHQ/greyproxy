package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLLMPageRoute(t *testing.T) {
	db := setupTestDB(t)
	r := setupRouter(t, db)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/llm", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	body := w.Body.String()

	checks := []string{
		"LLM Proxy",          // page heading
		"providers-tbody",    // providers table body
		"aliases-tbody",      // aliases table body
		"provider-modal",     // add/edit provider modal
		"alias-modal",        // add/edit alias modal
		`/api/llm`,           // JS targets the management API
		"Add provider",       // providers CTA
		"Add model",          // aliases CTA
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("llm page missing %q", want)
		}
	}
}

func TestLLMNavEntryPresent(t *testing.T) {
	db := setupTestDB(t)
	r := setupRouter(t, db)

	// The nav is rendered on every page via base.html; check the dashboard.
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/dashboard", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `href="/llm"`) {
		t.Error("dashboard nav missing the LLM link")
	}
}

func TestLLMPageActiveNavHighlight(t *testing.T) {
	db := setupTestDB(t)
	r := setupRouter(t, db)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/llm", nil)
	r.ServeHTTP(w, req)
	body := w.Body.String()
	// When on /llm, the LLM nav link should carry the active classes.
	// base.html applies "border-primary text-foreground" when CurrentPath
	// contains "/llm".
	if !strings.Contains(body, `href="/llm"`) {
		t.Fatal("missing /llm nav link on the llm page")
	}
	if !strings.Contains(body, "border-primary text-foreground") {
		t.Error("expected an active nav highlight on the llm page")
	}
}
