package llmproxy

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// Sentinel errors returned by the Store. API handlers map these to HTTP
// status codes (404 / 409 / 422 etc.); the gateway uses them to choose
// the right dialect-specific error envelope.
var (
	ErrNotFound  = errors.New("llmproxy: not found")
	ErrDisabled  = errors.New("llmproxy: disabled")
	ErrInUse     = errors.New("llmproxy: in use")
	ErrBadInput  = errors.New("llmproxy: bad input")
)

// Store wraps the greyproxy SQLite DB with the encryption key required
// to read/write provider API keys.
type Store struct {
	db  *greyproxy.DB
	key []byte
}

// NewStore returns a Store wrapping the provided database and AES-256
// master key (the 32-byte key loaded from dataDir/session.key). The key
// may be nil for tests that only exercise non-secret fields, but real
// callers must always supply one.
func NewStore(db *greyproxy.DB, key []byte) *Store {
	return &Store{db: db, key: key}
}

// Provider is the in-memory representation of a row in llm_providers.
// APIKey is intentionally absent — it never crosses the API boundary in
// plaintext. KeyPreview is the safe-to-display masked tail.
type Provider struct {
	ID          int64             `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	BaseURL     string            `json:"base_url"`
	KeySet      bool              `json:"key_set"`
	KeyPreview  string            `json:"key_preview,omitempty"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	UserDefined bool              `json:"user_defined"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ProviderInput is the create/update payload. Zero-value fields on update
// mean "leave unchanged" except for APIKey (a separate empty string can
// be distinguished by the caller — see UpdateProvider semantics below).
type ProviderInput struct {
	Name     string            `json:"name,omitempty"`
	Type     string            `json:"type,omitempty"`
	BaseURL  string            `json:"base_url,omitempty"`
	APIKey   string            `json:"api_key,omitempty"`
	Enabled  *bool             `json:"enabled,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Alias is the in-memory representation of a row in llm_aliases.
type Alias struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	ProviderID int64     `json:"provider_id"`
	ModelID    string    `json:"model_id"`
	Fallbacks  []string  `json:"fallbacks,omitempty"`
	Enabled    bool      `json:"enabled"`
	IsAuto     bool      `json:"is_auto"`
	AutoRules  []any     `json:"auto_rules,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AliasInput is the create/update payload for aliases.
type AliasInput struct {
	Name       string   `json:"name,omitempty"`
	ProviderID int64    `json:"provider_id,omitempty"`
	ModelID    string   `json:"model_id,omitempty"`
	Fallbacks  []string `json:"fallbacks,omitempty"`
	Enabled    *bool    `json:"enabled,omitempty"`
	IsAuto     *bool    `json:"is_auto,omitempty"`
	AutoRules  []any    `json:"auto_rules,omitempty"`
}

// ResolvedAlias bundles an alias with the provider it points at. The
// gateway hot path uses this to skip an extra DB roundtrip.
type ResolvedAlias struct {
	Alias    Alias
	Provider Provider
	ModelID  string
}

// CreateProvider inserts a provider row, encrypting the API key when
// supplied. Returns ErrBadInput when the unique-name constraint fires
// (wrapping is enough — sql.ErrNoRows is the empty case).
func (s *Store) CreateProvider(in ProviderInput) (*Provider, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("%w: name required", ErrBadInput)
	}
	if in.Type == "" {
		return nil, fmt.Errorf("%w: type required", ErrBadInput)
	}
	if in.BaseURL == "" {
		return nil, fmt.Errorf("%w: base_url required", ErrBadInput)
	}

	var enc []byte
	var preview string
	if in.APIKey != "" {
		var err error
		enc, err = greyproxy.Encrypt(s.key, []byte(in.APIKey))
		if err != nil {
			return nil, fmt.Errorf("encrypt api_key: %w", err)
		}
		preview = greyproxy.MaskCredentialValue(in.APIKey)
	}

	metaJSON, err := encodeMetadata(in.Metadata)
	if err != nil {
		return nil, err
	}

	enabled := 1
	if in.Enabled != nil && !*in.Enabled {
		enabled = 0
	}

	s.db.Lock()
	defer s.db.Unlock()

	res, err := s.db.WriteDB().Exec(
		`INSERT INTO llm_providers
		   (name, type, base_url, api_key_enc, key_preview, enabled, metadata_json, user_defined)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
		in.Name, in.Type, in.BaseURL, enc, preview, enabled, metaJSON,
	)
	if err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: provider name %q already exists", ErrBadInput, in.Name)
		}
		return nil, fmt.Errorf("insert provider: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.GetProvider(id)
}

// GetProvider fetches a provider by ID. Returns ErrNotFound if absent.
func (s *Store) GetProvider(id int64) (*Provider, error) {
	row := s.db.ReadDB().QueryRow(
		`SELECT id, name, type, base_url, api_key_enc IS NOT NULL, COALESCE(key_preview, ''),
		        enabled, COALESCE(metadata_json, ''), user_defined, created_at, updated_at
		 FROM llm_providers WHERE id = ?`,
		id)
	return scanProvider(row)
}

// GetProviderByName fetches a provider by its unique name.
func (s *Store) GetProviderByName(name string) (*Provider, error) {
	row := s.db.ReadDB().QueryRow(
		`SELECT id, name, type, base_url, api_key_enc IS NOT NULL, COALESCE(key_preview, ''),
		        enabled, COALESCE(metadata_json, ''), user_defined, created_at, updated_at
		 FROM llm_providers WHERE name = ?`,
		name)
	return scanProvider(row)
}

// GetProviderSecret decrypts and returns the API key for a provider.
// Empty string + nil error when the provider has no key.
func (s *Store) GetProviderSecret(id int64) (string, error) {
	var enc []byte
	err := s.db.ReadDB().QueryRow(
		`SELECT api_key_enc FROM llm_providers WHERE id = ?`,
		id).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if len(enc) == 0 {
		return "", nil
	}
	plain, err := greyproxy.Decrypt(s.key, enc)
	if err != nil {
		return "", fmt.Errorf("decrypt api_key: %w", err)
	}
	return string(plain), nil
}

// ListProviders returns every provider in name order. UI consumes the
// full list — there's no pagination yet because the expected size is
// small (single-digit to low-dozens).
func (s *Store) ListProviders() ([]Provider, error) {
	rows, err := s.db.ReadDB().Query(
		`SELECT id, name, type, base_url, api_key_enc IS NOT NULL, COALESCE(key_preview, ''),
		        enabled, COALESCE(metadata_json, ''), user_defined, created_at, updated_at
		 FROM llm_providers ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Provider
	for rows.Next() {
		p, err := scanProviderRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpdateProvider applies a partial input. APIKey="" leaves the existing
// key untouched; any non-empty APIKey rotates the stored value. Enabled
// is *bool so the caller can distinguish "not provided" from "false".
func (s *Store) UpdateProvider(id int64, in ProviderInput) (*Provider, error) {
	existing, err := s.GetProvider(id)
	if err != nil {
		return nil, err
	}

	sets := []string{"updated_at = datetime('now')"}
	var args []any

	if in.Name != "" {
		sets = append(sets, "name = ?")
		args = append(args, in.Name)
	}
	if in.Type != "" {
		sets = append(sets, "type = ?")
		args = append(args, in.Type)
	}
	if in.BaseURL != "" {
		sets = append(sets, "base_url = ?")
		args = append(args, in.BaseURL)
	}
	if in.APIKey != "" {
		enc, err := greyproxy.Encrypt(s.key, []byte(in.APIKey))
		if err != nil {
			return nil, fmt.Errorf("encrypt api_key: %w", err)
		}
		sets = append(sets, "api_key_enc = ?", "key_preview = ?")
		args = append(args, enc, greyproxy.MaskCredentialValue(in.APIKey))
	}
	if in.Enabled != nil {
		val := 0
		if *in.Enabled {
			val = 1
		}
		sets = append(sets, "enabled = ?")
		args = append(args, val)
	}
	if in.Metadata != nil {
		meta, err := encodeMetadata(in.Metadata)
		if err != nil {
			return nil, err
		}
		sets = append(sets, "metadata_json = ?")
		args = append(args, meta)
	}

	if len(sets) == 1 {
		// Only updated_at was queued — nothing to do.
		return existing, nil
	}

	args = append(args, id)
	s.db.Lock()
	defer s.db.Unlock()
	_, err = s.db.WriteDB().Exec(
		`UPDATE llm_providers SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: provider name already exists", ErrBadInput)
		}
		return nil, fmt.Errorf("update provider: %w", err)
	}
	return s.GetProvider(id)
}

// DeleteProvider removes a provider row. Refuses with ErrInUse if any
// alias still references it; the operator must delete those first (or
// repoint them at a different provider).
func (s *Store) DeleteProvider(id int64) error {
	var ref int
	if err := s.db.ReadDB().QueryRow(
		`SELECT COUNT(*) FROM llm_aliases WHERE provider_id = ?`, id).Scan(&ref); err != nil {
		return err
	}
	if ref > 0 {
		return fmt.Errorf("%w: %d alias(es) reference this provider", ErrInUse, ref)
	}

	s.db.Lock()
	defer s.db.Unlock()
	res, err := s.db.WriteDB().Exec(`DELETE FROM llm_providers WHERE id = ?`, id)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Alias CRUD ----------------------------------------------------------------

// CreateAlias inserts an alias row.
func (s *Store) CreateAlias(in AliasInput) (*Alias, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("%w: name required", ErrBadInput)
	}
	if in.ProviderID == 0 && (in.IsAuto == nil || !*in.IsAuto) {
		return nil, fmt.Errorf("%w: provider_id required (non-auto alias)", ErrBadInput)
	}

	enabled := 1
	if in.Enabled != nil && !*in.Enabled {
		enabled = 0
	}
	isAuto := 0
	if in.IsAuto != nil && *in.IsAuto {
		isAuto = 1
	}

	fbJSON, err := encodeFallbacks(in.Fallbacks)
	if err != nil {
		return nil, err
	}
	autoJSON, err := encodeAuto(in.AutoRules)
	if err != nil {
		return nil, err
	}

	s.db.Lock()
	defer s.db.Unlock()
	res, err := s.db.WriteDB().Exec(
		`INSERT INTO llm_aliases (name, provider_id, model_id, fallbacks_json, enabled, is_auto, auto_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		in.Name, in.ProviderID, in.ModelID, fbJSON, enabled, isAuto, autoJSON,
	)
	if err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: alias name %q already exists", ErrBadInput, in.Name)
		}
		return nil, fmt.Errorf("insert alias: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.GetAlias(id)
}

// GetAlias fetches one alias by id.
func (s *Store) GetAlias(id int64) (*Alias, error) {
	row := s.db.ReadDB().QueryRow(
		`SELECT id, name, provider_id, model_id, COALESCE(fallbacks_json, ''),
		        enabled, is_auto, COALESCE(auto_json, ''), created_at, updated_at
		 FROM llm_aliases WHERE id = ?`,
		id)
	return scanAlias(row)
}

// GetAliasByName fetches one alias by its unique name.
func (s *Store) GetAliasByName(name string) (*Alias, error) {
	row := s.db.ReadDB().QueryRow(
		`SELECT id, name, provider_id, model_id, COALESCE(fallbacks_json, ''),
		        enabled, is_auto, COALESCE(auto_json, ''), created_at, updated_at
		 FROM llm_aliases WHERE name = ?`,
		name)
	return scanAlias(row)
}

// ListAliases returns every alias in name order.
func (s *Store) ListAliases() ([]Alias, error) {
	rows, err := s.db.ReadDB().Query(
		`SELECT id, name, provider_id, model_id, COALESCE(fallbacks_json, ''),
		        enabled, is_auto, COALESCE(auto_json, ''), created_at, updated_at
		 FROM llm_aliases ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Alias
	for rows.Next() {
		a, err := scanAliasRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// UpdateAlias applies a partial input.
func (s *Store) UpdateAlias(id int64, in AliasInput) (*Alias, error) {
	existing, err := s.GetAlias(id)
	if err != nil {
		return nil, err
	}

	sets := []string{"updated_at = datetime('now')"}
	var args []any

	if in.Name != "" {
		sets = append(sets, "name = ?")
		args = append(args, in.Name)
	}
	if in.ProviderID != 0 {
		sets = append(sets, "provider_id = ?")
		args = append(args, in.ProviderID)
	}
	if in.ModelID != "" {
		sets = append(sets, "model_id = ?")
		args = append(args, in.ModelID)
	}
	if in.Fallbacks != nil {
		fb, err := encodeFallbacks(in.Fallbacks)
		if err != nil {
			return nil, err
		}
		sets = append(sets, "fallbacks_json = ?")
		args = append(args, fb)
	}
	if in.Enabled != nil {
		v := 0
		if *in.Enabled {
			v = 1
		}
		sets = append(sets, "enabled = ?")
		args = append(args, v)
	}
	if in.IsAuto != nil {
		v := 0
		if *in.IsAuto {
			v = 1
		}
		sets = append(sets, "is_auto = ?")
		args = append(args, v)
	}
	if in.AutoRules != nil {
		auto, err := encodeAuto(in.AutoRules)
		if err != nil {
			return nil, err
		}
		sets = append(sets, "auto_json = ?")
		args = append(args, auto)
	}

	if len(sets) == 1 {
		return existing, nil
	}

	args = append(args, id)
	s.db.Lock()
	defer s.db.Unlock()
	_, err = s.db.WriteDB().Exec(
		`UPDATE llm_aliases SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: alias name already exists", ErrBadInput)
		}
		return nil, fmt.Errorf("update alias: %w", err)
	}
	return s.GetAlias(id)
}

// DeleteAlias removes an alias row.
func (s *Store) DeleteAlias(id int64) error {
	s.db.Lock()
	defer s.db.Unlock()
	res, err := s.db.WriteDB().Exec(`DELETE FROM llm_aliases WHERE id = ?`, id)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolveAlias looks up an alias by its public name and returns the
// alias + its backing provider in one shot. Returns ErrNotFound when the
// alias doesn't exist, ErrDisabled when either the alias or its
// provider is disabled.
func (s *Store) ResolveAlias(name string) (*ResolvedAlias, error) {
	a, err := s.GetAliasByName(name)
	if err != nil {
		return nil, err
	}
	if !a.Enabled {
		return nil, fmt.Errorf("%w: alias %q is disabled", ErrDisabled, name)
	}
	p, err := s.GetProvider(a.ProviderID)
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, fmt.Errorf("%w: provider %q is disabled", ErrDisabled, p.Name)
	}
	return &ResolvedAlias{Alias: *a, Provider: *p, ModelID: a.ModelID}, nil
}

// scan helpers ---------------------------------------------------------------

type scannable interface {
	Scan(dest ...any) error
}

func scanProvider(row scannable) (*Provider, error) {
	return scanProviderRow(row)
}

func scanProviderRow(row scannable) (*Provider, error) {
	var p Provider
	var keySet int
	var metaJSON string
	var userDefined int
	var created, updated string
	err := row.Scan(&p.ID, &p.Name, &p.Type, &p.BaseURL, &keySet, &p.KeyPreview,
		&p.Enabled, &metaJSON, &userDefined, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.KeySet = keySet != 0
	p.UserDefined = userDefined != 0
	if metaJSON != "" {
		_ = json.Unmarshal([]byte(metaJSON), &p.Metadata)
	}
	p.CreatedAt, _ = time.Parse(time.DateTime, created)
	p.UpdatedAt, _ = time.Parse(time.DateTime, updated)
	// scanProvider returns Enabled as int (SQLite); coerce.
	if p.Enabled {
		// no-op — `Enabled bool` already scanned correctly thanks to driver
	}
	return &p, nil
}

func scanAlias(row scannable) (*Alias, error) {
	return scanAliasRow(row)
}

func scanAliasRow(row scannable) (*Alias, error) {
	var a Alias
	var fbJSON, autoJSON string
	var enabled, isAuto int
	var created, updated string
	err := row.Scan(&a.ID, &a.Name, &a.ProviderID, &a.ModelID, &fbJSON,
		&enabled, &isAuto, &autoJSON, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Enabled = enabled != 0
	a.IsAuto = isAuto != 0
	if fbJSON != "" {
		_ = json.Unmarshal([]byte(fbJSON), &a.Fallbacks)
	}
	if autoJSON != "" {
		_ = json.Unmarshal([]byte(autoJSON), &a.AutoRules)
	}
	a.CreatedAt, _ = time.Parse(time.DateTime, created)
	a.UpdatedAt, _ = time.Parse(time.DateTime, updated)
	return &a, nil
}

// encoding helpers -----------------------------------------------------------

func encodeMetadata(m map[string]string) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("encode metadata: %w", err)
	}
	return string(b), nil
}

func encodeFallbacks(fb []string) (string, error) {
	if len(fb) == 0 {
		return "", nil
	}
	b, err := json.Marshal(fb)
	if err != nil {
		return "", fmt.Errorf("encode fallbacks: %w", err)
	}
	return string(b), nil
}

func encodeAuto(r []any) (string, error) {
	if len(r) == 0 {
		return "", nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encode auto: %w", err)
	}
	return string(b), nil
}

func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint failed")
}
