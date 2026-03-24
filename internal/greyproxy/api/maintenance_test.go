package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	_ "modernc.org/sqlite"
)

func TestRedactHeadersAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestShared(t)

	// Set up settings manager with default redaction patterns
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	s.Settings = greyproxy.NewSettingsManager(settingsPath, true)

	// Seed transactions with plaintext sensitive headers
	for _, input := range []greyproxy.HttpTransactionCreateInput{
		{
			ContainerName:   "app",
			DestinationHost: "api.example.com",
			DestinationPort: 443,
			Method:          "POST",
			URL:             "https://api.example.com/v1/data",
			RequestHeaders: http.Header{
				"Authorization": {"Bearer sk-secret"},
				"Content-Type":  {"application/json"},
			},
			StatusCode: 200,
			ResponseHeaders: http.Header{
				"Set-Cookie":   {"session=abc"},
				"Content-Type": {"application/json"},
			},
			Result: "auto",
		},
	} {
		if _, err := greyproxy.CreateHttpTransaction(s.DB, input); err != nil {
			t.Fatal(err)
		}
	}

	r := gin.New()
	r.POST("/api/maintenance/redact-headers", RedactHeadersHandler(s))

	t.Run("starts redaction", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/maintenance/redact-headers", nil)
		r.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Fatalf("status: got %d, want 200", w.Code)
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp["status"] != "redaction started" {
			t.Errorf("status = %q, want 'redaction started'", resp["status"])
		}

		// Wait for background goroutine to finish
		time.Sleep(100 * time.Millisecond)

		// Verify headers were redacted in the DB
		txn, err := greyproxy.GetHttpTransaction(s.DB, 1)
		if err != nil {
			t.Fatal(err)
		}
		var reqHeaders map[string][]string
		if err := json.Unmarshal([]byte(txn.RequestHeaders.String), &reqHeaders); err != nil {
			t.Fatal(err)
		}
		if v := reqHeaders["Authorization"]; len(v) != 1 || v[0] != greyproxy.RedactedValue {
			t.Errorf("Authorization = %v, want [%q]", v, greyproxy.RedactedValue)
		}
		if v := reqHeaders["Content-Type"]; len(v) != 1 || v[0] != "application/json" {
			t.Errorf("Content-Type = %v, want [application/json]", v)
		}

		var respHeaders map[string][]string
		if err := json.Unmarshal([]byte(txn.ResponseHeaders.String), &respHeaders); err != nil {
			t.Fatal(err)
		}
		if v := respHeaders["Set-Cookie"]; len(v) != 1 || v[0] != greyproxy.RedactedValue {
			t.Errorf("Set-Cookie = %v, want [%q]", v, greyproxy.RedactedValue)
		}
	})

	t.Run("rejects concurrent runs", func(t *testing.T) {
		// Simulate a running job
		redactHeadersState.mu.Lock()
		redactHeadersState.running = true
		redactHeadersState.mu.Unlock()
		defer func() {
			redactHeadersState.mu.Lock()
			redactHeadersState.running = false
			redactHeadersState.mu.Unlock()
		}()

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/maintenance/redact-headers", nil)
		r.ServeHTTP(w, req)

		if w.Code != 409 {
			t.Errorf("status: got %d, want 409", w.Code)
		}
	})
}
