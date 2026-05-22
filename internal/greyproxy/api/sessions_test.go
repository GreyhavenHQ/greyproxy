package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	_ "modernc.org/sqlite"
)

func testEncryptionKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func setupTestSharedWithCreds(t *testing.T) *Shared {
	t.Helper()
	s := setupTestShared(t)
	key := testEncryptionKey()
	s.EncryptionKey = key

	store, err := greyproxy.NewCredentialStore(s.DB, key, s.Bus)
	if err != nil {
		t.Fatal(err)
	}
	s.CredentialStore = store
	return s
}

func TestSessionsCreate_WithGlobalCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestSharedWithCreds(t)
	key := testEncryptionKey()

	// Create a global credential in the DB
	cred, err := greyproxy.CreateGlobalCredential(s.DB, greyproxy.GlobalCredentialCreateInput{
		Label: "ANTHROPIC_API_KEY",
		Value: "sk-ant-real-secret",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.POST("/api/sessions", SessionsCreateHandler(s))

	body := map[string]any{
		"session_id":         "gw-test-global",
		"container_name":     "sandbox-1",
		"global_credentials": []string{"ANTHROPIC_API_KEY"},
		"ttl_seconds":        300,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/sessions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	// Should have 1 credential (the global one)
	if count, ok := resp["credential_count"].(float64); !ok || int(count) != 1 {
		t.Errorf("credential_count = %v, want 1", resp["credential_count"])
	}

	// Should return the resolved global credentials
	globals, ok := resp["global_credentials"].(map[string]any)
	if !ok {
		t.Fatalf("global_credentials missing or wrong type: %v", resp["global_credentials"])
	}
	placeholder, ok := globals["ANTHROPIC_API_KEY"].(string)
	if !ok || placeholder == "" {
		t.Fatalf("ANTHROPIC_API_KEY placeholder missing: %v", globals)
	}
	if placeholder != cred.Placeholder {
		t.Errorf("placeholder = %q, want %q", placeholder, cred.Placeholder)
	}

	// Verify the session was stored WITHOUT the global credential value in mappings
	// (global credentials are resolved at substitution time from the global store)
	session, err := greyproxy.GetSession(s.DB, "gw-test-global")
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := greyproxy.DecryptSessionMappings(session, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mappings[cred.Placeholder]; ok {
		t.Error("global credential value should NOT be duplicated into session mappings")
	}

	// Verify labels still contain the global credential label (for dashboard display)
	labels := greyproxy.GetSessionLabels(session)
	if labels[cred.Placeholder] != "ANTHROPIC_API_KEY" {
		t.Errorf("label = %q, want %q", labels[cred.Placeholder], "ANTHROPIC_API_KEY")
	}
}

func TestSessionsCreate_MixedCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestSharedWithCreds(t)
	key := testEncryptionKey()

	// Create a global credential
	_, err := greyproxy.CreateGlobalCredential(s.DB, greyproxy.GlobalCredentialCreateInput{
		Label: "GLOBAL_KEY",
		Value: "sk-global-value",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	// Create session with both session-specific mappings and global credentials
	sessionPlaceholder := "greyproxy:credential:v1:gw-mixed:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	body := map[string]any{
		"session_id":     "gw-mixed",
		"container_name": "sandbox",
		"mappings": map[string]string{
			sessionPlaceholder: "sk-session-value",
		},
		"labels": map[string]string{
			sessionPlaceholder: "SESSION_KEY",
		},
		"global_credentials": []string{"GLOBAL_KEY"},
		"ttl_seconds":        300,
	}
	b, _ := json.Marshal(body)

	router := gin.New()
	router.POST("/api/sessions", SessionsCreateHandler(s))

	req := httptest.NewRequest("POST", "/api/sessions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)

	// Should have 2 credentials total
	if count := int(resp["credential_count"].(float64)); count != 2 {
		t.Errorf("credential_count = %d, want 2", count)
	}
}

func TestSessionsCreate_UnknownGlobalCredential(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestSharedWithCreds(t)

	body := map[string]any{
		"session_id":         "gw-fail",
		"container_name":     "sandbox",
		"global_credentials": []string{"NONEXISTENT_KEY"},
		"ttl_seconds":        300,
	}
	b, _ := json.Marshal(body)

	router := gin.New()
	router.POST("/api/sessions", SessionsCreateHandler(s))

	req := httptest.NewRequest("POST", "/api/sessions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	errMsg, _ := resp["error"].(string)
	if errMsg == "" {
		t.Error("expected error message")
	}
}

func TestSessionsCreate_OnlyGlobalNoMappings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestSharedWithCreds(t)
	key := testEncryptionKey()

	// Create a global credential
	_, err := greyproxy.CreateGlobalCredential(s.DB, greyproxy.GlobalCredentialCreateInput{
		Label: "ONLY_GLOBAL",
		Value: "sk-only-global",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	// Session with only global credentials, no explicit mappings
	body := map[string]any{
		"session_id":         "gw-global-only",
		"container_name":     "sandbox",
		"global_credentials": []string{"ONLY_GLOBAL"},
		"ttl_seconds":        300,
	}
	b, _ := json.Marshal(body)

	router := gin.New()
	router.POST("/api/sessions", SessionsCreateHandler(s))

	req := httptest.NewRequest("POST", "/api/sessions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if count := int(resp["credential_count"].(float64)); count != 1 {
		t.Errorf("credential_count = %d, want 1", count)
	}
}

// TestSessionsHeartbeat_IngestsFsEvents drives the full path greywall uses:
// create session, POST a heartbeat carrying FsEvents in the JSON body, then
// read them back via GET /sessions/:id/fsevents.
func TestSessionsHeartbeat_IngestsFsEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestSharedWithCreds(t)
	s.FsEvents = greyproxy.NewFsEventStore(16)

	// Seed a session by POSTing through the create handler.
	placeholder := "greyproxy:credential:v1:gw-fs:0123456789abcdef0123456789abcdef"
	createBody, _ := json.Marshal(map[string]any{
		"session_id":     "gw-fs",
		"container_name": "sandbox-fs",
		"mappings":       map[string]string{placeholder: "secret-value"},
		"labels":         map[string]string{placeholder: "ANTHROPIC_API_KEY"},
		"ttl_seconds":    300,
	})

	r := gin.New()
	r.POST("/api/sessions", SessionsCreateHandler(s))
	r.POST("/api/sessions/:id/heartbeat", SessionsHeartbeatHandler(s))
	r.GET("/api/sessions/:id/fsevents", SessionsFsEventsHandler(s))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/sessions", bytes.NewReader(createBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("create session: status %d body %s", w.Code, w.Body.String())
	}

	// Heartbeat with FsEvents in the body.
	hb, _ := json.Marshal(map[string]any{
		"events": []greyproxy.FsEvent{
			{Ts: "2026-05-22T17:00:00Z", Op: "open_read", Path: "/etc/hostname", PID: 4242},
			{Ts: "2026-05-22T17:00:01Z", Op: "create", Path: "/tmp/out"},
			{Ts: "2026-05-22T17:00:02Z", Op: "rename", Path: "/tmp/out", Path2: "/tmp/final"},
		},
		"dropped": 7,
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/sessions/gw-fs/heartbeat", bytes.NewReader(hb)))
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: status %d body %s", w.Code, w.Body.String())
	}
	var hbResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &hbResp)
	if got, _ := hbResp["fs_events_ingested"].(float64); int(got) != 3 {
		t.Errorf("fs_events_ingested = %v, want 3", hbResp["fs_events_ingested"])
	}
	if got, _ := hbResp["fs_events_dropped"].(float64); int(got) != 7 {
		t.Errorf("fs_events_dropped = %v, want 7", hbResp["fs_events_dropped"])
	}

	// Read snapshot.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/sessions/gw-fs/fsevents", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("fsevents: status %d body %s", w.Code, w.Body.String())
	}
	var snap greyproxy.FsEventsSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.SessionID != "gw-fs" {
		t.Errorf("session_id = %q, want %q", snap.SessionID, "gw-fs")
	}
	if len(snap.Events) != 3 {
		t.Fatalf("len(events) = %d, want 3", len(snap.Events))
	}
	if snap.Events[2].Op != "rename" || snap.Events[2].Path2 != "/tmp/final" {
		t.Errorf("rename event not preserved: %+v", snap.Events[2])
	}
	if snap.Dropped != 7 {
		t.Errorf("dropped = %d, want 7", snap.Dropped)
	}
	if snap.TotalEvents != 3 {
		t.Errorf("total = %d, want 3", snap.TotalEvents)
	}
}

// TestSessionsHeartbeat_NoBodyBackCompat ensures heartbeats with no body
// (pre-fs-events greywall, or a tick with nothing to ship) still refresh
// the TTL and return 200.
func TestSessionsHeartbeat_NoBodyBackCompat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestSharedWithCreds(t)
	s.FsEvents = greyproxy.NewFsEventStore(0)

	placeholder := "greyproxy:credential:v1:gw-nb:0123456789abcdef0123456789abcdef"
	createBody, _ := json.Marshal(map[string]any{
		"session_id":     "gw-nb",
		"container_name": "sandbox",
		"mappings":       map[string]string{placeholder: "x"},
		"labels":         map[string]string{placeholder: "K"},
		"ttl_seconds":    300,
	})
	r := gin.New()
	r.POST("/api/sessions", SessionsCreateHandler(s))
	r.POST("/api/sessions/:id/heartbeat", SessionsHeartbeatHandler(s))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/sessions", bytes.NewReader(createBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/sessions/gw-nb/heartbeat", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, present := resp["fs_events_ingested"]; present {
		t.Errorf("fs_events_ingested should be absent when no body: %v", resp)
	}
}

func TestSessionsCreate_NoCredentialsAtAll(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestSharedWithCreds(t)

	body := map[string]any{
		"session_id":     "gw-empty",
		"container_name": "sandbox",
		"ttl_seconds":    300,
	}
	b, _ := json.Marshal(body)

	router := gin.New()
	router.POST("/api/sessions", SessionsCreateHandler(s))

	req := httptest.NewRequest("POST", "/api/sessions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
}
