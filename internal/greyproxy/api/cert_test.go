package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newCertTestRouter(s *Shared) *gin.Engine {
	r := gin.New()
	r.POST("/api/cert/reload", CertReloadHandler(s))
	return r
}

// =============================================================================
// CertReloadHandler
// =============================================================================

func TestCertReloadHandler_nilFn_returns503(t *testing.T) {
	s := &Shared{DataHome: t.TempDir()}
	// ReloadCertFn is nil

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cert/reload", nil)
	newCertTestRouter(s).ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestCertReloadHandler_fnError_returns500(t *testing.T) {
	s := &Shared{
		DataHome:     t.TempDir(),
		ReloadCertFn: func() error { return errors.New("reload failed") },
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cert/reload", nil)
	newCertTestRouter(s).ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestCertReloadHandler_success_returns200(t *testing.T) {
	s := &Shared{
		DataHome:     t.TempDir(),
		ReloadCertFn: func() error { return nil },
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cert/reload", nil)
	newCertTestRouter(s).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["message"] != "MITM cert reloaded" {
		t.Errorf("unexpected message: %v", body["message"])
	}
}

func TestCertReloadHandler_unchanged_skipsReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca-cert.pem")
	if err := os.WriteFile(certFile, []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(certFile)
	loadedAt := info.ModTime()

	reloadCalled := false
	s := &Shared{
		DataHome:     dir,
		ReloadCertFn: func() error { reloadCalled = true; return nil },
		CertMtimeFn:  func() time.Time { return loadedAt },
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cert/reload", nil)
	newCertTestRouter(s).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got %d, want %d", w.Code, http.StatusOK)
	}
	if reloadCalled {
		t.Error("ReloadCertFn should not be called when cert is unchanged")
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["message"] != "cert unchanged, no reload needed" {
		t.Errorf("unexpected message: %v", body["message"])
	}
}

func TestCertReloadHandler_changed_triggersReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca-cert.pem")
	if err := os.WriteFile(certFile, []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	// loadedAt is before the file's mtime → cert is "newer"
	loadedAt := time.Time{}

	reloadCalled := false
	s := &Shared{
		DataHome:     dir,
		ReloadCertFn: func() error { reloadCalled = true; return nil },
		CertMtimeFn:  func() time.Time { return loadedAt },
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cert/reload", nil)
	newCertTestRouter(s).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got %d, want %d", w.Code, http.StatusOK)
	}
	if !reloadCalled {
		t.Error("ReloadCertFn should be called when cert has changed")
	}
}
