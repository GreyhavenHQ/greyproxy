package greyproxy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
)

// EndpointRule maps a URL pattern to a wire decoder name.
type EndpointRule struct {
	ID          int64  `json:"id"`
	HostPattern string `json:"host_pattern"`
	PathPattern string `json:"path_pattern"`
	Method      string `json:"method"`
	DecoderName string `json:"decoder_name"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
	UserDefined bool   `json:"user_defined"`
}

// EndpointRegistry maps URL patterns to wire decoder names.
// Built-in rules are seeded on startup; user-defined rules are stored in SQLite.
type EndpointRegistry struct {
	db *DB
	mu sync.RWMutex
	// cached rules (rebuilt on mutation)
	rules []EndpointRule
}

// NewEndpointRegistry creates a registry and seeds built-in rules.
func NewEndpointRegistry(db *DB) *EndpointRegistry {
	r := &EndpointRegistry{db: db}
	r.seedBuiltinRules()
	r.reload()
	return r
}

// builtinRules are shipped with greyproxy and not user-editable.
var builtinRules = []EndpointRule{
	{HostPattern: "api.anthropic.com", PathPattern: "/v1/messages", Method: "POST", DecoderName: "anthropic", Priority: 0},
	{HostPattern: "api.openai.com", PathPattern: "/v1/responses", Method: "POST", DecoderName: "openai", Priority: 0},
	{HostPattern: "api.openai.com", PathPattern: "/v1/responses", Method: "WS_REQ", DecoderName: "openai-ws", Priority: 0},
	{HostPattern: "api.openai.com", PathPattern: "/v1/responses", Method: "WS_RESP", DecoderName: "openai-ws", Priority: 0},
	{HostPattern: "api.openai.com", PathPattern: "/v1/chat/completions", Method: "POST", DecoderName: "openai-chat", Priority: 0},
	{HostPattern: "openrouter.ai", PathPattern: "/api/v1/chat/completions", Method: "POST", DecoderName: "openai-chat", Priority: 0},
	{HostPattern: "generativelanguage.googleapis.com", PathPattern: "/v1beta/models/*", Method: "POST", DecoderName: "google-ai", Priority: 0},
}

func (r *EndpointRegistry) seedBuiltinRules() {
	r.db.Lock()
	defer r.db.Unlock()
	for _, rule := range builtinRules {
		_, err := r.db.WriteDB().Exec(
			`INSERT INTO endpoint_rules
			 (host_pattern, path_pattern, method, decoder_name, priority, enabled, user_defined)
			 VALUES (?, ?, ?, ?, ?, 1, 0)
			 ON CONFLICT(host_pattern, path_pattern, method, user_defined)
			 DO UPDATE SET decoder_name = excluded.decoder_name, priority = excluded.priority, enabled = 1`,
			rule.HostPattern, rule.PathPattern, rule.Method, rule.DecoderName, rule.Priority,
		)
		if err != nil {
			slog.Warn("endpoint_registry: failed to seed rule", "host", rule.HostPattern, "path", rule.PathPattern, "error", err)
		}
	}
}

func (r *EndpointRegistry) reload() {
	rows, err := r.db.ReadDB().Query(
		`SELECT id, host_pattern, path_pattern, method, decoder_name, priority, enabled, user_defined
		 FROM endpoint_rules
		 WHERE enabled = 1
		 ORDER BY priority DESC, id ASC`)
	if err != nil {
		slog.Warn("endpoint_registry: failed to load rules", "error", err)
		return
	}
	defer rows.Close()

	var rules []EndpointRule
	for rows.Next() {
		var rule EndpointRule
		var enabled, userDefined int
		if err := rows.Scan(&rule.ID, &rule.HostPattern, &rule.PathPattern, &rule.Method,
			&rule.DecoderName, &rule.Priority, &enabled, &userDefined); err != nil {
			slog.Warn("endpoint_registry: failed to scan rule", "error", err)
			continue
		}
		rule.Enabled = enabled == 1
		rule.UserDefined = userDefined == 1
		rules = append(rules, rule)
	}

	r.mu.Lock()
	r.rules = rules
	r.mu.Unlock()
}

// FindDissector resolves the dissector for a given URL, method, and host.
// First checks the registry rules; falls back to dissector.FindDissector().
// This is the authoritative routing function; the assembler should use this
// instead of calling dissector.FindDissector() directly.
func (r *EndpointRegistry) FindDissector(url, method, host string) dissector.Dissector {
	if name := r.Match(url, method, host); name != "" {
		if d := dissector.FindDissectorByName(name); d != nil {
			return d
		}
	}
	// Fallback: ask each dissector's CanHandle()
	return dissector.FindDissector(url, method, host)
}

// Match returns the decoder name for a given URL, method, and host.
// Returns empty string if no rule matches.
func (r *EndpointRegistry) Match(url, method, host string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Extract path from URL
	path := extractPath(url)

	for _, rule := range r.rules {
		if rule.Method != "*" && rule.Method != method {
			continue
		}
		if !matchGlob(rule.HostPattern, host) {
			continue
		}
		if !matchGlob(rule.PathPattern, path) {
			continue
		}
		return rule.DecoderName
	}
	return ""
}

// AllURLPatterns returns SQL LIKE patterns for all enabled rules.
// Used by the assembler to build WHERE clauses for loading transactions.
func (r *EndpointRegistry) AllURLPatterns() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var patterns []string
	seen := map[string]bool{}
	for _, rule := range r.rules {
		// Convert glob to LIKE pattern.
		// Use % between host and path to tolerate optional port (e.g. :80, :443)
		// in URLs like wss://api.openai.com:80/v1/responses.
		hostLike := strings.ReplaceAll(rule.HostPattern, "*", "%")
		pathLike := strings.ReplaceAll(rule.PathPattern, "*", "%")
		pattern := "%" + hostLike + "%" + pathLike + "%"
		if !seen[pattern] {
			patterns = append(patterns, pattern)
			seen[pattern] = true
		}
	}
	return patterns
}

// ListRules returns all rules (built-in and user-defined).
func (r *EndpointRegistry) ListRules() []EndpointRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]EndpointRule, len(r.rules))
	copy(out, r.rules)
	return out
}

// CreateRule adds a user-defined rule and reloads the cache.
func (r *EndpointRegistry) CreateRule(rule EndpointRule) (int64, error) {
	r.db.Lock()
	defer r.db.Unlock()
	res, err := r.db.WriteDB().Exec(
		`INSERT INTO endpoint_rules
		 (host_pattern, path_pattern, method, decoder_name, priority, enabled, user_defined)
		 VALUES (?, ?, ?, ?, ?, ?, 1)`,
		rule.HostPattern, rule.PathPattern, rule.Method, rule.DecoderName,
		rule.Priority, boolToInt(rule.Enabled),
	)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	r.reload()
	return id, nil
}

// UpdateRule updates a user-defined rule.
func (r *EndpointRegistry) UpdateRule(id int64, rule EndpointRule) error {
	r.db.Lock()
	defer r.db.Unlock()

	// Only allow updating user-defined rules
	var userDefined int
	if err := r.db.WriteDB().QueryRow("SELECT user_defined FROM endpoint_rules WHERE id = ?", id).Scan(&userDefined); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("rule not found")
		}
		return err
	}
	if userDefined == 0 {
		return fmt.Errorf("cannot modify built-in rule")
	}

	_, err := r.db.WriteDB().Exec(
		`UPDATE endpoint_rules SET
		 host_pattern = ?, path_pattern = ?, method = ?, decoder_name = ?,
		 priority = ?, enabled = ?
		 WHERE id = ? AND user_defined = 1`,
		rule.HostPattern, rule.PathPattern, rule.Method, rule.DecoderName,
		rule.Priority, boolToInt(rule.Enabled), id,
	)
	if err != nil {
		return err
	}
	r.reload()
	return nil
}

// DeleteRule removes a user-defined rule.
func (r *EndpointRegistry) DeleteRule(id int64) error {
	r.db.Lock()
	defer r.db.Unlock()

	res, err := r.db.WriteDB().Exec("DELETE FROM endpoint_rules WHERE id = ? AND user_defined = 1", id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("rule not found or is built-in")
	}
	r.reload()
	return nil
}

// AutoDetectAndCreate probes a request body to guess the decoder for an unknown host.
// If the body looks like an OpenAI-compatible chat completions request (has "model"
// and "messages" fields), it creates a user-defined endpoint rule and returns the
// matching dissector. Returns nil if detection fails.
func (r *EndpointRegistry) AutoDetectAndCreate(url, method, host string, body []byte) dissector.Dissector {
	if method != "POST" || host == "" || len(body) == 0 {
		return nil
	}
	path := extractPath(url)

	// Quick JSON probe: check for OpenAI chat completions shape
	var probe struct {
		Model    string            `json:"model"`
		Messages []json.RawMessage `json:"messages"`
	}
	if json.Unmarshal(body, &probe) != nil || probe.Model == "" || len(probe.Messages) == 0 {
		return nil
	}

	// Looks like OpenAI chat completions format
	decoderName := "openai-chat"
	d := dissector.FindDissectorByName(decoderName)
	if d == nil {
		return nil
	}

	// Create the rule
	id, err := r.CreateRule(EndpointRule{
		HostPattern: host,
		PathPattern: path,
		Method:      "POST",
		DecoderName: decoderName,
		Priority:    5,
		Enabled:     true,
	})
	if err != nil {
		slog.Warn("endpoint_registry: auto-detect failed to create rule", "host", host, "path", path, "error", err)
		return nil
	}
	slog.Info("endpoint_registry: auto-detected OpenAI-compatible endpoint, created rule",
		"host", host, "path", path, "decoder", decoderName, "rule_id", id)
	return d
}

// extractPath returns the path portion of a URL (before query string).
func extractPath(url string) string {
	// Strip scheme + host
	if i := strings.Index(url, "://"); i >= 0 {
		url = url[i+3:]
	}
	if i := strings.IndexByte(url, '/'); i >= 0 {
		url = url[i:]
	} else {
		return "/"
	}
	// Strip query string
	if i := strings.IndexByte(url, '?'); i >= 0 {
		url = url[:i]
	}
	return url
}

// matchGlob matches a pattern against a string using simple glob rules:
// * matches any sequence of characters.
func matchGlob(pattern, s string) bool {
	// Fast path: no wildcard
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 0 {
		return true
	}

	// Check prefix
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	// Check middle parts
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}

	// Check suffix
	return strings.HasSuffix(s, parts[len(parts)-1])
}
