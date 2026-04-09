package greyproxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// --- Sessions ---

type SessionCreateInput struct {
	SessionID         string            `json:"session_id"`
	ContainerName     string            `json:"container_name"`
	Mappings          map[string]string `json:"mappings"`
	Labels            map[string]string `json:"labels"`
	Metadata          map[string]string `json:"metadata"`
	TTLSeconds        int               `json:"ttl_seconds"`
	GlobalCredentials []string          `json:"global_credentials,omitempty"`
}

// CreateOrUpdateSession creates or upserts a credential substitution session.
// Mappings are encrypted before storage. Returns the created/updated session.
func CreateOrUpdateSession(db *DB, input SessionCreateInput, encryptionKey []byte) (*Session, error) {
	db.Lock()
	defer db.Unlock()

	if input.TTLSeconds <= 0 {
		input.TTLSeconds = 900
	}

	mappingsJSON, err := json.Marshal(input.Mappings)
	if err != nil {
		return nil, fmt.Errorf("marshal mappings: %w", err)
	}

	mappingsEnc, err := Encrypt(encryptionKey, mappingsJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt mappings: %w", err)
	}

	labelsJSON, err := json.Marshal(input.Labels)
	if err != nil {
		return nil, fmt.Errorf("marshal labels: %w", err)
	}

	metadata := input.Metadata
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = db.WriteDB().Exec(
		`INSERT INTO sessions (session_id, container_name, mappings_enc, labels_json, metadata_json, ttl_seconds, created_at, expires_at, last_heartbeat)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'), datetime('now'))
		 ON CONFLICT(session_id) DO UPDATE SET
		   container_name = excluded.container_name,
		   mappings_enc = excluded.mappings_enc,
		   labels_json = excluded.labels_json,
		   metadata_json = excluded.metadata_json,
		   ttl_seconds = excluded.ttl_seconds,
		   expires_at = excluded.expires_at,
		   last_heartbeat = excluded.last_heartbeat`,
		input.SessionID, input.ContainerName, mappingsEnc, string(labelsJSON), string(metadataJSON),
		input.TTLSeconds, input.TTLSeconds,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert session: %w", err)
	}

	// Re-read from DB to get the canonical timestamps
	return getSessionLocked(db, input.SessionID)
}

// HeartbeatSession resets the TTL for an active session.
// Returns the updated session or nil if not found/expired.
func HeartbeatSession(db *DB, sessionID string) (*Session, error) {
	db.Lock()
	defer db.Unlock()

	// Update expires_at and last_heartbeat only if the session is still active
	result, err := db.WriteDB().Exec(
		`UPDATE sessions SET
		   expires_at = datetime('now', '+' || ttl_seconds || ' seconds'),
		   last_heartbeat = datetime('now')
		 WHERE session_id = ? AND expires_at > datetime('now')`,
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("heartbeat session: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return nil, nil // not found or expired
	}

	return getSessionLocked(db, sessionID)
}

// DeleteSession removes a session from the database.
func DeleteSession(db *DB, sessionID string) (bool, error) {
	db.Lock()
	defer db.Unlock()

	result, err := db.WriteDB().Exec("DELETE FROM sessions WHERE session_id = ?", sessionID)
	if err != nil {
		return false, fmt.Errorf("delete session: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// GetSession retrieves a session by ID.
func GetSession(db *DB, sessionID string) (*Session, error) {
	return scanSession(db.ReadDB().QueryRow(
		`SELECT session_id, container_name, mappings_enc, labels_json, metadata_json, ttl_seconds,
		        created_at, expires_at, last_heartbeat, substitution_count
		 FROM sessions WHERE session_id = ?`, sessionID,
	))
}

// ListSessions returns all active (non-expired) sessions.
func ListSessions(db *DB) ([]Session, error) {
	rows, err := db.ReadDB().Query(
		`SELECT session_id, container_name, mappings_enc, labels_json, metadata_json, ttl_seconds,
		        created_at, expires_at, last_heartbeat, substitution_count
		 FROM sessions WHERE expires_at > datetime('now') ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []Session
	for rows.Next() {
		s, err := scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, *s)
	}
	return sessions, rows.Err()
}

// DeleteExpiredSessions removes all expired sessions and returns their IDs.
// Uses a single snapshot timestamp to avoid a race where a heartbeat between
// the SELECT and DELETE could extend a session that was already marked expired.
func DeleteExpiredSessions(db *DB) ([]string, error) {
	db.Lock()
	defer db.Unlock()

	// Snapshot the current time once so both queries use the same cutoff.
	var now string
	if err := db.WriteDB().QueryRow("SELECT datetime('now')").Scan(&now); err != nil {
		return nil, fmt.Errorf("get current time: %w", err)
	}

	rows, err := db.WriteDB().Query(
		"SELECT session_id FROM sessions WHERE expires_at <= ?", now,
	)
	if err != nil {
		return nil, fmt.Errorf("find expired sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan expired session: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ids) > 0 {
		_, err = db.WriteDB().Exec(
			"DELETE FROM sessions WHERE expires_at <= ?", now,
		)
		if err != nil {
			return nil, fmt.Errorf("delete expired sessions: %w", err)
		}
	}

	return ids, nil
}

// IncrementSubstitutionCount atomically increments the substitution counter for a session.
func IncrementSubstitutionCount(db *DB, sessionID string, delta int64) error {
	db.Lock()
	defer db.Unlock()

	_, err := db.WriteDB().Exec(
		"UPDATE sessions SET substitution_count = substitution_count + ? WHERE session_id = ?",
		delta, sessionID,
	)
	return err
}

// LoadAllSessions returns all sessions (including expired, for startup reload).
func LoadAllSessions(db *DB) ([]Session, error) {
	rows, err := db.ReadDB().Query(
		`SELECT session_id, container_name, mappings_enc, labels_json, metadata_json, ttl_seconds,
		        created_at, expires_at, last_heartbeat, substitution_count
		 FROM sessions ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("load all sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []Session
	for rows.Next() {
		s, err := scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, *s)
	}
	return sessions, rows.Err()
}

// getSessionLocked retrieves a session (caller must hold write lock).
func getSessionLocked(db *DB, sessionID string) (*Session, error) {
	return scanSession(db.WriteDB().QueryRow(
		`SELECT session_id, container_name, mappings_enc, labels_json, metadata_json, ttl_seconds,
		        created_at, expires_at, last_heartbeat, substitution_count
		 FROM sessions WHERE session_id = ?`, sessionID,
	))
}

type scannable interface {
	Scan(dest ...any) error
}

func scanSession(row scannable) (*Session, error) {
	var s Session
	err := row.Scan(
		&s.SessionID, &s.ContainerName, &s.MappingsEnc, &s.LabelsJSON, &s.MetadataJSON,
		&s.TTLSeconds, &s.CreatedAt, &s.ExpiresAt, &s.LastHeartbeat, &s.SubstitutionCount,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func scanSessionRow(rows scannable) (*Session, error) {
	return scanSession(rows)
}

// DecryptSessionMappings decrypts the encrypted mappings blob.
func DecryptSessionMappings(s *Session, key []byte) (map[string]string, error) {
	plaintext, err := Decrypt(key, s.MappingsEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt mappings: %w", err)
	}
	var mappings map[string]string
	if err := json.Unmarshal(plaintext, &mappings); err != nil {
		return nil, fmt.Errorf("unmarshal mappings: %w", err)
	}
	return mappings, nil
}

// ParseSessionLabels parses the labels JSON string.
func ParseSessionLabels(s *Session) (map[string]string, error) {
	var labels map[string]string
	if err := json.Unmarshal([]byte(s.LabelsJSON), &labels); err != nil {
		return nil, fmt.Errorf("unmarshal labels: %w", err)
	}
	return labels, nil
}

// --- Global Credentials ---

type GlobalCredentialCreateInput struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// CreateGlobalCredential creates a new global credential with an auto-generated placeholder.
func CreateGlobalCredential(db *DB, input GlobalCredentialCreateInput, encryptionKey []byte) (*GlobalCredential, error) {
	db.Lock()
	defer db.Unlock()

	id, err := generateCredentialID()
	if err != nil {
		return nil, err
	}

	placeholder, err := GeneratePlaceholder("global")
	if err != nil {
		return nil, err
	}

	valueEnc, err := Encrypt(encryptionKey, []byte(input.Value))
	if err != nil {
		return nil, fmt.Errorf("encrypt value: %w", err)
	}

	preview := MaskCredentialValue(input.Value)

	_, err = db.WriteDB().Exec(
		`INSERT INTO global_credentials (id, label, placeholder, value_enc, value_preview, created_at)
		 VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		id, input.Label, placeholder, valueEnc, preview,
	)
	if err != nil {
		return nil, fmt.Errorf("insert global credential: %w", err)
	}

	// Re-read to get canonical timestamp
	return GetGlobalCredentialLocked(db, id)
}

// ListGlobalCredentials returns all global credentials (without decrypted values).
func ListGlobalCredentials(db *DB) ([]GlobalCredential, error) {
	rows, err := db.ReadDB().Query(
		`SELECT id, label, placeholder, value_enc, value_preview, created_at
		 FROM global_credentials ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list global credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []GlobalCredential
	for rows.Next() {
		var c GlobalCredential
		if err := rows.Scan(&c.ID, &c.Label, &c.Placeholder, &c.ValueEnc, &c.ValuePreview, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan global credential: %w", err)
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// GetGlobalCredentialsByLabels retrieves global credentials matching the given labels.
// Returns a map of label -> GlobalCredential for found credentials and a list of missing labels.
func GetGlobalCredentialsByLabels(db *DB, labels []string) (map[string]*GlobalCredential, []string, error) {
	if len(labels) == 0 {
		return nil, nil, nil
	}

	creds, err := ListGlobalCredentials(db)
	if err != nil {
		return nil, nil, err
	}

	byLabel := make(map[string]*GlobalCredential, len(creds))
	for i := range creds {
		byLabel[creds[i].Label] = &creds[i]
	}

	found := make(map[string]*GlobalCredential, len(labels))
	var missing []string
	for _, label := range labels {
		if c, ok := byLabel[label]; ok {
			found[label] = c
		} else {
			missing = append(missing, label)
		}
	}
	return found, missing, nil
}

// GetGlobalCredential retrieves a single global credential by ID.
func GetGlobalCredential(db *DB, id string) (*GlobalCredential, error) {
	return scanGlobalCredential(db.ReadDB().QueryRow(
		`SELECT id, label, placeholder, value_enc, value_preview, created_at
		 FROM global_credentials WHERE id = ?`, id,
	))
}

// GetGlobalCredentialLocked retrieves a credential using the write DB (caller must hold lock).
func GetGlobalCredentialLocked(db *DB, id string) (*GlobalCredential, error) {
	return scanGlobalCredential(db.WriteDB().QueryRow(
		`SELECT id, label, placeholder, value_enc, value_preview, created_at
		 FROM global_credentials WHERE id = ?`, id,
	))
}

func scanGlobalCredential(row scannable) (*GlobalCredential, error) {
	var c GlobalCredential
	err := row.Scan(&c.ID, &c.Label, &c.Placeholder, &c.ValueEnc, &c.ValuePreview, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// DeleteGlobalCredential removes a global credential.
func DeleteGlobalCredential(db *DB, id string) (bool, error) {
	db.Lock()
	defer db.Unlock()

	result, err := db.WriteDB().Exec("DELETE FROM global_credentials WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("delete global credential: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// DecryptGlobalCredentialValue decrypts the encrypted credential value.
func DecryptGlobalCredentialValue(c *GlobalCredential, key []byte) (string, error) {
	plaintext, err := Decrypt(key, c.ValueEnc)
	if err != nil {
		return "", fmt.Errorf("decrypt credential: %w", err)
	}
	return string(plaintext), nil
}

func generateCredentialID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate credential ID: %w", err)
	}
	return "cred_" + hex.EncodeToString(b), nil
}
