package greyproxy

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Session event types.
const (
	EventSessionCreated      = "session.created"
	EventSessionExpired      = "session.expired"
	EventSessionDeleted      = "session.deleted"
	EventSessionHeartbeat    = "session.heartbeat"
	EventSessionSubstitution = "session.substitution"
)

// SubstitutionResult holds the outcome of a credential substitution pass.
type SubstitutionResult struct {
	Count      int
	Labels     []string
	SessionIDs []string
}

// CredentialStore provides fast in-memory credential placeholder lookup
// backed by encrypted DB persistence.
type CredentialStore struct {
	mu sync.RWMutex

	// placeholder -> decrypted real credential
	lookup map[string]string

	// placeholder -> session_id (for substitution counting)
	sessionMap map[string]string

	// placeholder -> human-readable label (e.g. "OPENAI_API_KEY")
	labelsMap map[string]string

	// pending substitution counts per session (batched to reduce DB writes)
	pendingCounts map[string]*atomic.Int64

	db            *DB
	encryptionKey []byte
	bus           *EventBus
}

// NewCredentialStore creates a new store and loads existing sessions/credentials from the DB.
func NewCredentialStore(db *DB, encryptionKey []byte, bus *EventBus) (*CredentialStore, error) {
	cs := &CredentialStore{
		lookup:        make(map[string]string),
		sessionMap:    make(map[string]string),
		labelsMap:     make(map[string]string),
		pendingCounts: make(map[string]*atomic.Int64),
		db:            db,
		encryptionKey: encryptionKey,
		bus:           bus,
	}

	if err := cs.loadFromDB(); err != nil {
		return nil, err
	}

	return cs, nil
}

// loadFromDB rebuilds the in-memory lookup from all active sessions and global credentials.
func (cs *CredentialStore) loadFromDB() error {
	now := time.Now().UTC()

	sessions, err := LoadAllSessions(cs.db)
	if err != nil {
		return err
	}

	for _, s := range sessions {
		if s.ExpiresAt.Before(now) {
			continue
		}
		mappings, err := DecryptSessionMappings(&s, cs.encryptionKey)
		if err != nil {
			log.Printf("[credential_store] WARN: failed to decrypt session %s (stale key?), skipping", s.SessionID)
			continue
		}
		labels := GetSessionLabels(&s)
		for placeholder, real := range mappings {
			cs.lookup[placeholder] = real
			cs.sessionMap[placeholder] = s.SessionID
			if label, ok := labels[placeholder]; ok {
				cs.labelsMap[placeholder] = label
			}
		}
	}

	creds, err := ListGlobalCredentials(cs.db)
	if err != nil {
		return err
	}

	for _, c := range creds {
		value, err := DecryptGlobalCredentialValue(&c, cs.encryptionKey)
		if err != nil {
			log.Printf("[credential_store] WARN: failed to decrypt global credential %s, skipping", c.ID)
			continue
		}
		cs.lookup[c.Placeholder] = value
		cs.labelsMap[c.Placeholder] = c.Label
	}

	return nil
}

// RegisterSession adds a session's credential mappings to the in-memory store.
func (cs *CredentialStore) RegisterSession(session *Session, mappings map[string]string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Remove any old entries for this session first
	cs.removeSessionLocked(session.SessionID)

	labels := GetSessionLabels(session)
	for placeholder, real := range mappings {
		cs.lookup[placeholder] = real
		cs.sessionMap[placeholder] = session.SessionID
		if label, ok := labels[placeholder]; ok {
			cs.labelsMap[placeholder] = label
		}
	}
	cs.pendingCounts[session.SessionID] = &atomic.Int64{}

	if cs.bus != nil {
		cs.bus.Publish(Event{Type: EventSessionCreated, Data: session.SessionID})
	}
}

// UnregisterSession removes all credential mappings for a session.
func (cs *CredentialStore) UnregisterSession(sessionID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.removeSessionLocked(sessionID)

	if cs.bus != nil {
		cs.bus.Publish(Event{Type: EventSessionDeleted, Data: sessionID})
	}
}

// removeSessionLocked removes entries for a session (caller must hold write lock).
func (cs *CredentialStore) removeSessionLocked(sessionID string) {
	for placeholder, sid := range cs.sessionMap {
		if sid == sessionID {
			delete(cs.lookup, placeholder)
			delete(cs.sessionMap, placeholder)
			delete(cs.labelsMap, placeholder)
		}
	}
	delete(cs.pendingCounts, sessionID)
}

// RegisterGlobalCredential adds a global credential to the in-memory store.
func (cs *CredentialStore) RegisterGlobalCredential(placeholder, value, label string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.lookup[placeholder] = value
	cs.labelsMap[placeholder] = label
}

// UnregisterGlobalCredential removes a global credential from the in-memory store.
func (cs *CredentialStore) UnregisterGlobalCredential(placeholder string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.lookup, placeholder)
	delete(cs.labelsMap, placeholder)
}

// SubstituteRequest scans HTTP request headers and URL query parameters
// for credential placeholders and replaces them with real values.
// Returns a SubstitutionResult with the count, matched labels, and session IDs.
func (cs *CredentialStore) SubstituteRequest(req *http.Request) SubstitutionResult {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if len(cs.lookup) == 0 {
		return SubstitutionResult{}
	}

	count := 0
	sessionsUsed := make(map[string]bool)
	labelsUsed := make(map[string]bool)

	// Scan headers
	for key, values := range req.Header {
		for i, v := range values {
			if !strings.Contains(v, PlaceholderPrefix) {
				continue
			}
			replaced := cs.replaceInString(v, sessionsUsed, labelsUsed)
			if replaced != v {
				req.Header[key][i] = replaced
				count++
			}
		}
	}

	// Scan URL query parameters
	q := req.URL.Query()
	qChanged := false
	for key, values := range q {
		for i, v := range values {
			if !strings.Contains(v, PlaceholderPrefix) {
				continue
			}
			replaced := cs.replaceInString(v, sessionsUsed, labelsUsed)
			if replaced != v {
				q[key][i] = replaced
				qChanged = true
				count++
			}
		}
	}
	if qChanged {
		req.URL.RawQuery = q.Encode()
	}

	// Track substitution counts per session
	if count > 0 {
		cs.trackSubstitutions(sessionsUsed)
	}

	// Build result
	labels := make([]string, 0, len(labelsUsed))
	for l := range labelsUsed {
		labels = append(labels, l)
	}
	sessionIDs := make([]string, 0, len(sessionsUsed))
	for sid := range sessionsUsed {
		sessionIDs = append(sessionIDs, sid)
	}

	return SubstitutionResult{Count: count, Labels: labels, SessionIDs: sessionIDs}
}

// replaceInString replaces all placeholder occurrences in a string
// and records which sessions and labels were involved.
// Caller must hold at least a read lock.
func (cs *CredentialStore) replaceInString(s string, sessionsUsed, labelsUsed map[string]bool) string {
	for placeholder, real := range cs.lookup {
		if strings.Contains(s, placeholder) {
			s = strings.ReplaceAll(s, placeholder, real)
			if sid, ok := cs.sessionMap[placeholder]; ok {
				sessionsUsed[sid] = true
			}
			if label, ok := cs.labelsMap[placeholder]; ok {
				labelsUsed[label] = true
			}
		}
	}
	return s
}

// trackSubstitutions increments pending counters for the given sessions.
// Caller must hold at least a read lock. Only reads pendingCounts map;
// counters are pre-allocated during RegisterSession.
func (cs *CredentialStore) trackSubstitutions(sessionsUsed map[string]bool) {
	for sid := range sessionsUsed {
		if counter, ok := cs.pendingCounts[sid]; ok {
			counter.Add(1)
		}
	}
}

// Size returns the number of credential mappings in the store.
func (cs *CredentialStore) Size() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.lookup)
}

// SessionCount returns the number of unique sessions with active credentials.
func (cs *CredentialStore) SessionCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	seen := make(map[string]bool)
	for _, sid := range cs.sessionMap {
		seen[sid] = true
	}
	return len(seen)
}

// StartCleanupLoop runs a periodic goroutine that:
// 1. Removes expired sessions from DB and memory
// 2. Flushes pending substitution counts to DB
// The loop runs every interval until ctx is cancelled.
func (cs *CredentialStore) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cs.cleanup()
				cs.flushSubstitutionCounts()
			}
		}
	}()
}

// cleanup removes expired sessions.
func (cs *CredentialStore) cleanup() {
	expiredIDs, err := DeleteExpiredSessions(cs.db)
	if err != nil {
		log.Printf("[credential_store] WARN: cleanup error: %v", err)
		return
	}

	if len(expiredIDs) > 0 {
		cs.mu.Lock()
		for _, id := range expiredIDs {
			cs.removeSessionLocked(id)
		}
		cs.mu.Unlock()

		for _, id := range expiredIDs {
			log.Printf("[credential_store] session %s expired", id)
			if cs.bus != nil {
				cs.bus.Publish(Event{Type: EventSessionExpired, Data: id})
			}
		}
	}
}

// flushSubstitutionCounts writes pending counts to the DB.
func (cs *CredentialStore) flushSubstitutionCounts() {
	cs.mu.RLock()
	toFlush := make(map[string]int64)
	for sid, counter := range cs.pendingCounts {
		if v := counter.Swap(0); v > 0 {
			toFlush[sid] = v
		}
	}
	cs.mu.RUnlock()

	for sid, delta := range toFlush {
		if err := IncrementSubstitutionCount(cs.db, sid, delta); err != nil {
			log.Printf("[credential_store] WARN: failed to flush substitution count for %s: %v", sid, err)
			continue
		}
		if cs.bus != nil {
			cs.bus.Publish(Event{Type: EventSessionSubstitution, Data: sid})
		}
	}
}

// PurgeUnreadableCredentials removes sessions and global credentials that
// cannot be decrypted (e.g., after key rotation). Call on startup if a new
// key was generated. Returns the number of sessions and credentials purged.
func (cs *CredentialStore) PurgeUnreadableCredentials() (sessions int, globals int, err error) {
	allSessions, err := LoadAllSessions(cs.db)
	if err != nil {
		return 0, 0, err
	}

	for _, s := range allSessions {
		if _, decErr := DecryptSessionMappings(&s, cs.encryptionKey); decErr != nil {
			if _, delErr := DeleteSession(cs.db, s.SessionID); delErr == nil {
				sessions++
			}
		}
	}

	allCreds, err := ListGlobalCredentials(cs.db)
	if err != nil {
		return sessions, 0, err
	}

	for _, c := range allCreds {
		if _, decErr := DecryptGlobalCredentialValue(&c, cs.encryptionKey); decErr != nil {
			if _, delErr := DeleteGlobalCredential(cs.db, c.ID); delErr == nil {
				globals++
			}
		}
	}

	return sessions, globals, nil
}

// GetSessionLabels returns the labels map for a session from its JSON field.
func GetSessionLabels(s *Session) map[string]string {
	var labels map[string]string
	if err := json.Unmarshal([]byte(s.LabelsJSON), &labels); err != nil {
		return make(map[string]string)
	}
	return labels
}
