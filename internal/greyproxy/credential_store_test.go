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

func TestCredentialStore_PurgeUnreadableSessions(t *testing.T) {
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

	// Use a different key (simulating key rotation)
	key2 := make([]byte, sessionKeySize)
	key2[0] = 99

	bus := NewEventBus()
	cs, err := NewCredentialStore(db, key2, bus)
	if err != nil {
		t.Fatal(err)
	}

	// The session should have been skipped during load
	if cs.Size() != 0 {
		t.Errorf("size = %d, want 0 (session encrypted with old key)", cs.Size())
	}

	purged, err := cs.PurgeUnreadableSessions()
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Errorf("purged = %d, want 1", purged)
	}

	sessions, err := LoadAllSessions(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Errorf("sessions in DB = %d, want 0 after purge", len(sessions))
	}
}
