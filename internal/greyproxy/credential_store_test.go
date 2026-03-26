package greyproxy

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func testEncryptionKey() []byte {
	key := make([]byte, sessionKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func setupCredentialStore(t *testing.T) (*CredentialStore, *DB) {
	t.Helper()
	db := setupTestDB(t)
	bus := NewEventBus()
	key := testEncryptionKey()

	cs, err := NewCredentialStore(db, key, bus)
	if err != nil {
		t.Fatal(err)
	}
	return cs, db
}

func TestCredentialStore_SubstituteRequest_HeaderExactMatch(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	placeholder := "greyproxy:credential:v1:test:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	realKey := "sk-ant-api03-real-key"

	cs.RegisterSession(&Session{SessionID: "test"}, map[string]string{
		placeholder: realKey,
	})

	req := &http.Request{
		Header: http.Header{
			"Authorization": []string{"Bearer " + placeholder},
		},
		URL: &url.URL{Path: "/v1/chat"},
	}

	result := cs.SubstituteRequest(req)
	if result.Count != 1 {
		t.Errorf("substitution count = %d, want 1", result.Count)
	}
	if req.Header.Get("Authorization") != "Bearer "+realKey {
		t.Errorf("got header %q, want %q", req.Header.Get("Authorization"), "Bearer "+realKey)
	}
}

func TestCredentialStore_SubstituteRequest_NoMatch(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	cs.RegisterSession(&Session{SessionID: "test"}, map[string]string{
		"greyproxy:credential:v1:test:aaaa": "real",
	})

	req := &http.Request{
		Header: http.Header{
			"Authorization": []string{"Bearer sk-regular-key"},
		},
		URL: &url.URL{Path: "/v1/chat"},
	}

	result := cs.SubstituteRequest(req)
	if result.Count != 0 {
		t.Errorf("substitution count = %d, want 0", result.Count)
	}
	if req.Header.Get("Authorization") != "Bearer sk-regular-key" {
		t.Error("header should not be modified")
	}
}

func TestCredentialStore_SubstituteRequest_QueryParam(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	placeholder := "greyproxy:credential:v1:test:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	realKey := "actual-api-key"

	cs.RegisterSession(&Session{SessionID: "test"}, map[string]string{
		placeholder: realKey,
	})

	req := &http.Request{
		Header: http.Header{},
		URL: &url.URL{
			Path:     "/api/data",
			RawQuery: "api_key=" + placeholder + "&other=value",
		},
	}

	result := cs.SubstituteRequest(req)
	if result.Count != 1 {
		t.Errorf("substitution count = %d, want 1", result.Count)
	}
	if req.URL.Query().Get("api_key") != realKey {
		t.Errorf("got query param %q, want %q", req.URL.Query().Get("api_key"), realKey)
	}
	if req.URL.Query().Get("other") != "value" {
		t.Error("other query params should be preserved")
	}
}

func TestCredentialStore_SubstituteRequest_MultipleHeaders(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	p1 := "greyproxy:credential:v1:s1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	p2 := "greyproxy:credential:v1:s1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"

	cs.RegisterSession(&Session{SessionID: "s1"}, map[string]string{
		p1: "real-key-1",
		p2: "real-key-2",
	})

	req := &http.Request{
		Header: http.Header{
			"Authorization": []string{p1},
			"X-Api-Key":     []string{p2},
		},
		URL: &url.URL{Path: "/"},
	}

	result := cs.SubstituteRequest(req)
	if result.Count != 2 {
		t.Errorf("substitution count = %d, want 2", result.Count)
	}
	if req.Header.Get("Authorization") != "real-key-1" {
		t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "real-key-1")
	}
	if req.Header.Get("X-Api-Key") != "real-key-2" {
		t.Errorf("X-Api-Key = %q, want %q", req.Header.Get("X-Api-Key"), "real-key-2")
	}
}

func TestCredentialStore_SubstituteRequest_EmptyStore(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	req := &http.Request{
		Header: http.Header{
			"Authorization": []string{"Bearer something"},
		},
		URL: &url.URL{Path: "/"},
	}

	result := cs.SubstituteRequest(req)
	if result.Count != 0 {
		t.Errorf("substitution count = %d, want 0", result.Count)
	}
}

func TestCredentialStore_RegisterUnregisterSession(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	p := "greyproxy:credential:v1:sess1:cccccccccccccccccccccccccccccccc"
	cs.RegisterSession(&Session{SessionID: "sess1"}, map[string]string{
		p: "real",
	})

	if cs.Size() != 1 {
		t.Errorf("size = %d, want 1", cs.Size())
	}

	cs.UnregisterSession("sess1")

	if cs.Size() != 0 {
		t.Errorf("size = %d, want 0 after unregister", cs.Size())
	}

	// Substitution should no longer work
	req := &http.Request{
		Header: http.Header{"Authorization": []string{p}},
		URL:    &url.URL{Path: "/"},
	}
	res := cs.SubstituteRequest(req)
	if res.Count != 0 {
		t.Errorf("substitution count = %d after unregister, want 0", res.Count)
	}
}

func TestCredentialStore_RegisterGlobalCredential(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	p := "greyproxy:credential:v1:global:dddddddddddddddddddddddddddddddd"
	cs.RegisterGlobalCredential(p, "global-secret", "GLOBAL_KEY")

	req := &http.Request{
		Header: http.Header{"X-Api-Key": []string{p}},
		URL:    &url.URL{Path: "/"},
	}

	result := cs.SubstituteRequest(req)
	if result.Count != 1 {
		t.Errorf("substitution count = %d, want 1", result.Count)
	}
	if req.Header.Get("X-Api-Key") != "global-secret" {
		t.Errorf("got %q, want %q", req.Header.Get("X-Api-Key"), "global-secret")
	}
}

func TestCredentialStore_SessionUpsert(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	p1 := "greyproxy:credential:v1:s1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	p2 := "greyproxy:credential:v1:s1:ffffffffffffffffffffffffffffffff"

	cs.RegisterSession(&Session{SessionID: "s1"}, map[string]string{p1: "old-key"})
	if cs.Size() != 1 {
		t.Fatalf("size = %d, want 1", cs.Size())
	}

	// Upsert with new mappings
	cs.RegisterSession(&Session{SessionID: "s1"}, map[string]string{p2: "new-key"})
	if cs.Size() != 1 {
		t.Errorf("size after upsert = %d, want 1 (old entry should be removed)", cs.Size())
	}

	// Old placeholder should not work
	req := &http.Request{
		Header: http.Header{"Authorization": []string{p1}},
		URL:    &url.URL{Path: "/"},
	}
	res := cs.SubstituteRequest(req)
	if res.Count != 0 {
		t.Error("old placeholder should not be substituted after upsert")
	}

	// New placeholder should work
	req = &http.Request{
		Header: http.Header{"Authorization": []string{p2}},
		URL:    &url.URL{Path: "/"},
	}
	res = cs.SubstituteRequest(req)
	if res.Count != 1 {
		t.Error("new placeholder should be substituted after upsert")
	}
}

func TestCredentialStore_ConcurrentAccess(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	p := "greyproxy:credential:v1:conc:11111111111111111111111111111111"
	cs.RegisterSession(&Session{SessionID: "conc"}, map[string]string{p: "real"})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &http.Request{
				Header: http.Header{"Authorization": []string{p}},
				URL:    &url.URL{Path: "/"},
			}
			cs.SubstituteRequest(req)
		}()
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cs.RegisterSession(&Session{SessionID: "conc"}, map[string]string{p: "real"})
		}()
	}

	wg.Wait()
}

func TestCredentialStore_SessionCount(t *testing.T) {
	cs, _ := setupCredentialStore(t)

	cs.RegisterSession(&Session{SessionID: "s1"}, map[string]string{
		"greyproxy:credential:v1:s1:aaaa": "r1",
	})
	cs.RegisterSession(&Session{SessionID: "s2"}, map[string]string{
		"greyproxy:credential:v1:s2:bbbb": "r2",
	})

	if cs.SessionCount() != 2 {
		t.Errorf("session count = %d, want 2", cs.SessionCount())
	}

	cs.UnregisterSession("s1")
	if cs.SessionCount() != 1 {
		t.Errorf("session count = %d, want 1", cs.SessionCount())
	}
}

// --- CRUD Tests ---

func TestSessionCreateAndGet(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	session, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-test1",
		ContainerName: "sandbox-1",
		Mappings: map[string]string{
			"greyproxy:credential:v1:gw-test1:aaaa": "sk-real-key",
		},
		Labels: map[string]string{
			"greyproxy:credential:v1:gw-test1:aaaa": "ANTHROPIC_API_KEY",
		},
		TTLSeconds: 300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if session.SessionID != "gw-test1" {
		t.Errorf("session_id = %q, want %q", session.SessionID, "gw-test1")
	}
	if session.TTLSeconds != 300 {
		t.Errorf("ttl = %d, want 300", session.TTLSeconds)
	}

	// Read back
	got, err := GetSession(db, "gw-test1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ContainerName != "sandbox-1" {
		t.Errorf("container = %q, want %q", got.ContainerName, "sandbox-1")
	}

	// Decrypt and verify mappings
	mappings, err := DecryptSessionMappings(got, key)
	if err != nil {
		t.Fatal(err)
	}
	if mappings["greyproxy:credential:v1:gw-test1:aaaa"] != "sk-real-key" {
		t.Error("decrypted mapping does not match")
	}

	// Verify labels
	labels, err := ParseSessionLabels(got)
	if err != nil {
		t.Fatal(err)
	}
	if labels["greyproxy:credential:v1:gw-test1:aaaa"] != "ANTHROPIC_API_KEY" {
		t.Error("label does not match")
	}
}

func TestSessionUpsert(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	input := SessionCreateInput{
		SessionID:     "gw-upsert",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p1": "v1"},
		Labels:        map[string]string{"p1": "L1"},
		TTLSeconds:    300,
	}

	_, err := CreateOrUpdateSession(db, input, key)
	if err != nil {
		t.Fatal(err)
	}

	// Upsert with different mappings
	input.Mappings = map[string]string{"p2": "v2"}
	input.Labels = map[string]string{"p2": "L2"}
	_, err = CreateOrUpdateSession(db, input, key)
	if err != nil {
		t.Fatal(err)
	}

	got, err := GetSession(db, "gw-upsert")
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := DecryptSessionMappings(got, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mappings["p1"]; ok {
		t.Error("old mapping should be replaced on upsert")
	}
	if mappings["p2"] != "v2" {
		t.Error("new mapping should be present after upsert")
	}
}

func TestSessionHeartbeat(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-hb",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p": "v"},
		Labels:        map[string]string{},
		TTLSeconds:    300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	before, _ := GetSession(db, "gw-hb")

	// SQLite datetime has second-level precision, so we need to wait at least 1s
	time.Sleep(1100 * time.Millisecond)

	updated, err := HeartbeatSession(db, "gw-hb")
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil {
		t.Fatal("heartbeat returned nil")
	}
	if !updated.ExpiresAt.After(before.ExpiresAt) {
		t.Error("expires_at should be extended after heartbeat")
	}
}

func TestSessionHeartbeat_Expired(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-expired",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p": "v"},
		Labels:        map[string]string{},
		TTLSeconds:    1, // 1 second TTL
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1100 * time.Millisecond)

	updated, err := HeartbeatSession(db, "gw-expired")
	if err != nil {
		t.Fatal(err)
	}
	if updated != nil {
		t.Error("heartbeat should return nil for expired session")
	}
}

func TestSessionDelete(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-del",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p": "v"},
		Labels:        map[string]string{},
		TTLSeconds:    300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := DeleteSession(db, "gw-del")
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("expected deletion to succeed")
	}

	got, err := GetSession(db, "gw-del")
	if err == nil && got != nil {
		t.Error("session should not exist after delete")
	}

	// Delete non-existent
	deleted, err = DeleteSession(db, "gw-del")
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Error("deleting non-existent should return false")
	}
}

func TestListSessions(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	for _, id := range []string{"s1", "s2", "s3"} {
		_, err := CreateOrUpdateSession(db, SessionCreateInput{
			SessionID:     id,
			ContainerName: "sandbox",
			Mappings:      map[string]string{"p": "v"},
			Labels:        map[string]string{},
			TTLSeconds:    300,
		}, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	sessions, err := ListSessions(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 3 {
		t.Errorf("got %d sessions, want 3", len(sessions))
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	// Create session with 1s TTL
	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-expire",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p": "v"},
		Labels:        map[string]string{},
		TTLSeconds:    1,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	// Create session with long TTL
	_, err = CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-keep",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p": "v"},
		Labels:        map[string]string{},
		TTLSeconds:    300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1100 * time.Millisecond)

	expired, err := DeleteExpiredSessions(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0] != "gw-expire" {
		t.Errorf("expired = %v, want [gw-expire]", expired)
	}

	remaining, err := ListSessions(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Errorf("remaining = %d, want 1", len(remaining))
	}
}

func TestSubstitutionCount(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-count",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p": "v"},
		Labels:        map[string]string{},
		TTLSeconds:    300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := IncrementSubstitutionCount(db, "gw-count", 5); err != nil {
		t.Fatal(err)
	}

	got, err := GetSession(db, "gw-count")
	if err != nil {
		t.Fatal(err)
	}
	if got.SubstitutionCount != 5 {
		t.Errorf("substitution_count = %d, want 5", got.SubstitutionCount)
	}
}

// --- Global Credential CRUD Tests ---

func TestGlobalCredentialCreateAndList(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	cred, err := CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "ANTHROPIC_API_KEY",
		Value: "sk-ant-api03-abcdefghijk",
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Label != "ANTHROPIC_API_KEY" {
		t.Errorf("label = %q, want %q", cred.Label, "ANTHROPIC_API_KEY")
	}
	if cred.ValuePreview != "sk-ant***ijk" {
		t.Errorf("preview = %q, want %q", cred.ValuePreview, "sk-ant***ijk")
	}
	if cred.Placeholder == "" {
		t.Error("placeholder should not be empty")
	}

	// List
	creds, err := ListGlobalCredentials(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Errorf("got %d credentials, want 1", len(creds))
	}

	// Decrypt and verify
	value, err := DecryptGlobalCredentialValue(&creds[0], key)
	if err != nil {
		t.Fatal(err)
	}
	if value != "sk-ant-api03-abcdefghijk" {
		t.Errorf("decrypted value = %q", value)
	}
}

func TestGlobalCredentialDuplicateLabel(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	_, err := CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "MY_KEY",
		Value: "val1",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "MY_KEY",
		Value: "val2",
	}, key)
	if err == nil {
		t.Error("expected error for duplicate label")
	}
}

func TestGlobalCredentialDelete(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	cred, err := CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "DEL_KEY",
		Value: "val",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := DeleteGlobalCredential(db, cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("delete should succeed")
	}

	creds, err := ListGlobalCredentials(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 0 {
		t.Errorf("got %d credentials after delete, want 0", len(creds))
	}
}

func TestCredentialStore_LoadFromDB(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()
	bus := NewEventBus()

	placeholder := "greyproxy:credential:v1:reload:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"

	// Create session in DB
	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "reload-test",
		ContainerName: "sandbox",
		Mappings:      map[string]string{placeholder: "real-key"},
		Labels:        map[string]string{placeholder: "MY_KEY"},
		TTLSeconds:    300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	// Create global credential in DB
	_, err = CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "GLOBAL_KEY",
		Value: "global-real",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new store that should load from DB
	cs, err := NewCredentialStore(db, key, bus)
	if err != nil {
		t.Fatal(err)
	}

	// Session credential should be loaded
	if cs.Size() != 2 { // 1 session + 1 global
		t.Errorf("size = %d, want 2", cs.Size())
	}

	// Verify session placeholder works
	req := &http.Request{
		Header: http.Header{"Authorization": []string{placeholder}},
		URL:    &url.URL{Path: "/"},
	}
	res := cs.SubstituteRequest(req)
	if res.Count != 1 {
		t.Error("session placeholder should work after DB reload")
	}
	if req.Header.Get("Authorization") != "real-key" {
		t.Errorf("got %q, want %q", req.Header.Get("Authorization"), "real-key")
	}
}

func TestCredentialStore_CleanupLoop(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()
	bus := NewEventBus()

	placeholder := "greyproxy:credential:v1:cleanup:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"

	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "cleanup-test",
		ContainerName: "sandbox",
		Mappings:      map[string]string{placeholder: "real"},
		Labels:        map[string]string{},
		TTLSeconds:    2, // expires in 2s
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	cs, err := NewCredentialStore(db, key, bus)
	if err != nil {
		t.Fatal(err)
	}

	if cs.Size() != 1 {
		t.Fatalf("initial size = %d, want 1", cs.Size())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cs.StartCleanupLoop(ctx, 500*time.Millisecond)

	// Wait for session to expire and cleanup to run
	time.Sleep(3 * time.Second)

	if cs.Size() != 0 {
		t.Errorf("size after cleanup = %d, want 0", cs.Size())
	}
}

func TestCredentialStore_PurgeUnreadableCredentials(t *testing.T) {
	db := setupTestDB(t)
	key1 := testEncryptionKey()

	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "purge-test",
		ContainerName: "sandbox",
		Mappings:      map[string]string{"p": "v"},
		Labels:        map[string]string{},
		TTLSeconds:    300,
	}, key1)
	if err != nil {
		t.Fatal(err)
	}

	// Also create a global credential with the old key
	_, err = CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "OLD_CRED",
		Value: "old-secret-value",
	}, key1)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different key (simulating key rotation)
	key2 := make([]byte, sessionKeySize)
	key2[0] = 99

	bus := NewEventBus()
	cs, err := NewCredentialStore(db, key2, bus)
	if err != nil {
		t.Fatal(err)
	}

	// Both should have been skipped during load
	if cs.Size() != 0 {
		t.Errorf("size = %d, want 0 (all encrypted with old key)", cs.Size())
	}

	sessions, globals, err := cs.PurgeUnreadableCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Errorf("purged sessions = %d, want 1", sessions)
	}
	if globals != 1 {
		t.Errorf("purged globals = %d, want 1", globals)
	}

	remainingSessions, err := LoadAllSessions(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(remainingSessions) != 0 {
		t.Errorf("sessions in DB = %d, want 0 after purge", len(remainingSessions))
	}

	remainingCreds, err := ListGlobalCredentials(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(remainingCreds) != 0 {
		t.Errorf("global credentials in DB = %d, want 0 after purge", len(remainingCreds))
	}
}

// --- GetGlobalCredentialsByLabels Tests ---

func TestGetGlobalCredentialsByLabels(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()

	// Create two global credentials
	cred1, err := CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "ANTHROPIC_API_KEY",
		Value: "sk-ant-real-key",
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "OPENAI_API_KEY",
		Value: "sk-oai-real-key",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("all found", func(t *testing.T) {
		found, missing, err := GetGlobalCredentialsByLabels(db, []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"})
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 0 {
			t.Errorf("unexpected missing labels: %v", missing)
		}
		if len(found) != 2 {
			t.Fatalf("got %d found, want 2", len(found))
		}
		if found["ANTHROPIC_API_KEY"].Placeholder != cred1.Placeholder {
			t.Errorf("placeholder mismatch for ANTHROPIC_API_KEY")
		}
	})

	t.Run("some missing", func(t *testing.T) {
		found, missing, err := GetGlobalCredentialsByLabels(db, []string{"ANTHROPIC_API_KEY", "NONEXISTENT"})
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 {
			t.Errorf("got %d found, want 1", len(found))
		}
		if len(missing) != 1 || missing[0] != "NONEXISTENT" {
			t.Errorf("missing = %v, want [NONEXISTENT]", missing)
		}
	})

	t.Run("empty labels", func(t *testing.T) {
		found, missing, err := GetGlobalCredentialsByLabels(db, nil)
		if err != nil {
			t.Fatal(err)
		}
		if found != nil || missing != nil {
			t.Error("expected nil for empty labels")
		}
	})
}

func TestSessionWithGlobalCredentials_Substitution(t *testing.T) {
	db := setupTestDB(t)
	key := testEncryptionKey()
	bus := NewEventBus()

	// Create a global credential
	globalCred, err := CreateGlobalCredential(db, GlobalCredentialCreateInput{
		Label: "GLOBAL_KEY",
		Value: "sk-global-secret",
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	// Create a session with only session-specific credentials.
	// Global credentials are NOT stored in session mappings; the store
	// loads them separately from the global_credentials table.
	sessionPlaceholder := "greyproxy:credential:v1:gw-mixed:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	sessionMappings := map[string]string{
		sessionPlaceholder: "sk-session-secret",
	}

	session, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID:     "gw-mixed",
		ContainerName: "sandbox",
		Mappings:      sessionMappings,
		Labels: map[string]string{
			sessionPlaceholder:     "SESSION_KEY",
			globalCred.Placeholder: "GLOBAL_KEY",
		},
		TTLSeconds: 300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	// Build a credential store (loads both sessions and global creds from DB)
	store, err := NewCredentialStore(db, key, bus)
	if err != nil {
		t.Fatal(err)
	}
	store.RegisterSession(session, sessionMappings)

	// Test substitution of session credential
	req1, _ := http.NewRequest("GET", "https://api.example.com", nil)
	req1.Header.Set("Authorization", "Bearer "+sessionPlaceholder)
	result1 := store.SubstituteRequest(req1)
	if result1.Count != 1 {
		t.Fatalf("session cred: count = %d, want 1", result1.Count)
	}
	if req1.Header.Get("Authorization") != "Bearer sk-session-secret" {
		t.Errorf("session cred: got %q", req1.Header.Get("Authorization"))
	}

	// Test substitution of global credential (loaded from global_credentials table, not session)
	req2, _ := http.NewRequest("GET", "https://api.example.com", nil)
	req2.Header.Set("Authorization", "Bearer "+globalCred.Placeholder)
	result2 := store.SubstituteRequest(req2)
	if result2.Count != 1 {
		t.Fatalf("global cred: count = %d, want 1", result2.Count)
	}
	if req2.Header.Get("Authorization") != "Bearer sk-global-secret" {
		t.Errorf("global cred: got %q", req2.Header.Get("Authorization"))
	}

	// Verify labels are tracked for both
	if len(result1.Labels) != 1 || result1.Labels[0] != "SESSION_KEY" {
		t.Errorf("session cred labels = %v, want [SESSION_KEY]", result1.Labels)
	}
	if len(result2.Labels) != 1 || result2.Labels[0] != "GLOBAL_KEY" {
		t.Errorf("global cred labels = %v, want [GLOBAL_KEY]", result2.Labels)
	}
}
