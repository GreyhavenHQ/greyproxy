package greyproxy

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// --- Rules ---

type RuleCreateInput struct {
	ContainerPattern   string  `json:"container_pattern"`
	DestinationPattern string  `json:"destination_pattern"`
	PortPattern        string  `json:"port_pattern"`
	RuleType           string  `json:"rule_type"`
	Action             string  `json:"action"`
	ExpiresInSeconds   *int64  `json:"expires_in_seconds"`
	Notes              *string `json:"notes"`
	CreatedBy          string  `json:"created_by"`
}

type RuleUpdateInput struct {
	ContainerPattern   *string `json:"container_pattern"`
	DestinationPattern *string `json:"destination_pattern"`
	PortPattern        *string `json:"port_pattern"`
	Action             *string `json:"action"`
	Notes              *string `json:"notes"`
	ExpiresAt          *string `json:"expires_at"`
}

func CreateRule(db *DB, input RuleCreateInput) (*Rule, error) {
	db.Lock()
	defer db.Unlock()

	if input.PortPattern == "" {
		input.PortPattern = "*"
	}
	if input.RuleType == "" {
		input.RuleType = "permanent"
	}
	if input.Action == "" {
		input.Action = "allow"
	}
	if input.CreatedBy == "" {
		input.CreatedBy = "admin"
	}

	var expiresAt sql.NullTime
	if input.ExpiresInSeconds != nil && *input.ExpiresInSeconds > 0 {
		expiresAt = sql.NullTime{Time: time.Now().Add(time.Duration(*input.ExpiresInSeconds) * time.Second), Valid: true}
	}

	var notes sql.NullString
	if input.Notes != nil {
		notes = sql.NullString{String: *input.Notes, Valid: true}
	}

	result, err := db.WriteDB().Exec(
		`INSERT INTO rules (container_pattern, destination_pattern, port_pattern, rule_type, action, expires_at, created_by, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		input.ContainerPattern, input.DestinationPattern, input.PortPattern,
		input.RuleType, input.Action, expiresAt, input.CreatedBy, notes,
	)
	if err != nil {
		// Check if this is a unique constraint violation — return existing rule
		if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "unique") {
			existing := findExistingRule(db, input.ContainerPattern, input.DestinationPattern, input.PortPattern, input.Action)
			if existing != nil {
				return existing, nil
			}
		}
		return nil, fmt.Errorf("insert rule: %w", err)
	}

	id, _ := result.LastInsertId()
	return GetRule(db, id)
}

func GetRule(db *DB, id int64) (*Rule, error) {
	row := db.ReadDB().QueryRow(
		`SELECT id, container_pattern, destination_pattern, port_pattern, rule_type, action,
		        created_at, expires_at, last_used_at, created_by, notes
		 FROM rules WHERE id = ?`, id,
	)
	return scanRule(row)
}

func scanRule(row interface{ Scan(...any) error }) (*Rule, error) {
	var r Rule
	err := row.Scan(&r.ID, &r.ContainerPattern, &r.DestinationPattern, &r.PortPattern,
		&r.RuleType, &r.Action, &r.CreatedAt, &r.ExpiresAt, &r.LastUsedAt, &r.CreatedBy, &r.Notes)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

type RuleFilter struct {
	Container      string
	Destination    string
	Action         string
	IncludeExpired bool
	Limit          int
	Offset         int
}

func GetRules(db *DB, f RuleFilter) ([]Rule, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}

	where := []string{"1=1"}
	args := []any{}

	if !f.IncludeExpired {
		where = append(where, "(expires_at IS NULL OR expires_at > datetime('now'))")
	}
	if f.Container != "" {
		where = append(where, "container_pattern LIKE ?")
		args = append(args, "%"+f.Container+"%")
	}
	if f.Destination != "" {
		where = append(where, "destination_pattern LIKE ?")
		args = append(args, "%"+f.Destination+"%")
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	err := db.ReadDB().QueryRow("SELECT COUNT(*) FROM rules WHERE "+whereClause, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := db.ReadDB().Query(
		"SELECT id, container_pattern, destination_pattern, port_pattern, rule_type, action, created_at, expires_at, last_used_at, created_by, notes FROM rules WHERE "+whereClause+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		append(args, f.Limit, f.Offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.ContainerPattern, &r.DestinationPattern, &r.PortPattern,
			&r.RuleType, &r.Action, &r.CreatedAt, &r.ExpiresAt, &r.LastUsedAt, &r.CreatedBy, &r.Notes); err != nil {
			return nil, 0, err
		}
		rules = append(rules, r)
	}
	return rules, total, nil
}

func UpdateRule(db *DB, id int64, input RuleUpdateInput) (*Rule, error) {
	db.Lock()
	defer db.Unlock()

	sets := []string{}
	args := []any{}

	if input.ContainerPattern != nil {
		sets = append(sets, "container_pattern = ?")
		args = append(args, *input.ContainerPattern)
	}
	if input.DestinationPattern != nil {
		sets = append(sets, "destination_pattern = ?")
		args = append(args, *input.DestinationPattern)
	}
	if input.PortPattern != nil {
		sets = append(sets, "port_pattern = ?")
		args = append(args, *input.PortPattern)
	}
	if input.Action != nil {
		sets = append(sets, "action = ?")
		args = append(args, *input.Action)
	}
	if input.Notes != nil {
		sets = append(sets, "notes = ?")
		args = append(args, *input.Notes)
	}
	if input.ExpiresAt != nil {
		if *input.ExpiresAt == "" {
			sets = append(sets, "expires_at = NULL")
		} else {
			sets = append(sets, "expires_at = ?")
			args = append(args, *input.ExpiresAt)
		}
	}

	if len(sets) == 0 {
		return GetRule(db, id)
	}

	args = append(args, id)
	_, err := db.WriteDB().Exec(
		"UPDATE rules SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...,
	)
	if err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	return GetRule(db, id)
}

func DeleteRule(db *DB, id int64) (bool, error) {
	db.Lock()
	defer db.Unlock()

	result, err := db.WriteDB().Exec("DELETE FROM rules WHERE id = ?", id)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// IngestRuleInput is the input format for the bulk rule import endpoint.
type IngestRuleInput struct {
	ContainerPattern   string  `json:"container_pattern"`
	DestinationPattern string  `json:"destination_pattern"`
	PortPattern        string  `json:"port_pattern"`
	Action             string  `json:"action"`
	Notes              *string `json:"notes"`
}

// IngestResult contains statistics from a bulk rule import.
type IngestResult struct {
	Imported       int `json:"imported"`
	Skipped        int `json:"skipped"`
	PendingCleaned int `json:"pending_cleaned"`
}

// IngestRules imports a batch of rules, deduplicating against existing rules,
// and cleans up pending requests that now match an allow rule.
func IngestRules(db *DB, rules []IngestRuleInput) (*IngestResult, error) {
	result := &IngestResult{}

	for _, r := range rules {
		if r.PortPattern == "" {
			r.PortPattern = "*"
		}
		if r.Action == "" {
			r.Action = "allow"
		}

		// Check for existing identical rule
		existing := findExistingRule(db, r.ContainerPattern, r.DestinationPattern, r.PortPattern, r.Action)
		if existing != nil {
			result.Skipped++
			continue
		}

		_, err := CreateRule(db, RuleCreateInput{
			ContainerPattern:   r.ContainerPattern,
			DestinationPattern: r.DestinationPattern,
			PortPattern:        r.PortPattern,
			RuleType:           "permanent",
			Action:             r.Action,
			Notes:              r.Notes,
		})
		if err != nil {
			return nil, fmt.Errorf("ingest rule %q -> %q: %w", r.ContainerPattern, r.DestinationPattern, err)
		}
		result.Imported++
	}

	// Clean up pending requests that now match an allow rule
	if result.Imported > 0 {
		pendingItems, _, err := GetPendingRequests(db, PendingFilter{Limit: 10000})
		if err == nil {
			for _, p := range pendingItems {
				rule := FindMatchingRule(db, p.ContainerName, p.DestinationHost, p.DestinationPort,
					p.ResolvedHostname.String)
				if rule != nil && rule.Action == "allow" {
					db.Lock()
					deletePendingSiblings(db, &p)
					db.Unlock()
					result.PendingCleaned++
				}
			}
		}
	}

	return result, nil
}

// FindMatchingRule finds the most specific matching rule for the given request.
// Returns nil if no rule matches (default-deny).
func FindMatchingRule(db *DB, containerName, destHost string, destPort int, resolvedHostname string) *Rule {
	// Get all non-expired rules
	rows, err := db.ReadDB().Query(
		`SELECT id, container_pattern, destination_pattern, port_pattern, rule_type, action,
		        created_at, expires_at, last_used_at, created_by, notes
		 FROM rules
		 WHERE expires_at IS NULL OR expires_at > datetime('now')`,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type scored struct {
		rule        Rule
		specificity int
	}

	var matches []scored
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.ContainerPattern, &r.DestinationPattern, &r.PortPattern,
			&r.RuleType, &r.Action, &r.CreatedAt, &r.ExpiresAt, &r.LastUsedAt, &r.CreatedBy, &r.Notes); err != nil {
			continue
		}

		// Try matching against raw destination host
		matched := MatchesRule(containerName, destHost, destPort, r.ContainerPattern, r.DestinationPattern, r.PortPattern)

		// Also try matching against resolved hostname
		if !matched && resolvedHostname != "" {
			matched = MatchesRule(containerName, resolvedHostname, destPort, r.ContainerPattern, r.DestinationPattern, r.PortPattern)
		}

		if matched {
			matches = append(matches, scored{
				rule:        r,
				specificity: CalculateSpecificity(r.ContainerPattern, r.DestinationPattern, r.PortPattern),
			})
		}
	}

	if len(matches) == 0 {
		return nil
	}

	// Sort: highest specificity first, deny before allow at same specificity
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].specificity != matches[j].specificity {
			return matches[i].specificity > matches[j].specificity
		}
		// Deny rules take priority at same specificity
		if matches[i].rule.Action != matches[j].rule.Action {
			return matches[i].rule.Action == "deny"
		}
		return false
	})

	winner := &matches[0].rule

	// Update last_used_at in background (don't block the caller)
	go func() {
		db.Lock()
		defer db.Unlock()
		db.WriteDB().Exec("UPDATE rules SET last_used_at = datetime('now') WHERE id = ?", winner.ID)
	}()

	return winner
}

// --- Pending Requests ---

// CreateOrUpdatePending creates a new pending request or updates an existing one.
// Returns (pending, isNew).
func CreateOrUpdatePending(db *DB, containerName, containerID, destHost string, destPort int, resolvedHostname string) (*PendingRequest, bool, error) {
	db.Lock()
	defer db.Unlock()

	var rh sql.NullString
	if resolvedHostname != "" {
		rh = sql.NullString{String: resolvedHostname, Valid: true}
	}

	// Check for existing: same container, destination_host, port
	var existing PendingRequest
	err := db.WriteDB().QueryRow(
		`SELECT id, container_name, container_id, destination_host, destination_port,
		        resolved_hostname, first_seen, last_seen, attempt_count
		 FROM pending_requests
		 WHERE container_name = ? AND destination_host = ? AND destination_port = ?`,
		containerName, destHost, destPort,
	).Scan(&existing.ID, &existing.ContainerName, &existing.ContainerID, &existing.DestinationHost,
		&existing.DestinationPort, &existing.ResolvedHostname, &existing.FirstSeen, &existing.LastSeen, &existing.AttemptCount)

	if err == nil {
		// Update existing
		_, err = db.WriteDB().Exec(
			`UPDATE pending_requests SET last_seen = datetime('now'), attempt_count = attempt_count + 1,
			 resolved_hostname = COALESCE(?, resolved_hostname)
			 WHERE id = ?`, rh, existing.ID,
		)
		if err != nil {
			return nil, false, err
		}
		// Re-read
		p, err := getPendingByIDLocked(db.WriteDB(), existing.ID)
		return p, false, err
	}

	// Also check siblings: same container + resolved_hostname + port (different IP)
	if resolvedHostname != "" {
		err = db.WriteDB().QueryRow(
			`SELECT id FROM pending_requests
			 WHERE container_name = ? AND resolved_hostname = ? AND destination_port = ?`,
			containerName, resolvedHostname, destPort,
		).Scan(&existing.ID)
		if err == nil {
			_, err = db.WriteDB().Exec(
				`UPDATE pending_requests SET last_seen = datetime('now'), attempt_count = attempt_count + 1
				 WHERE id = ?`, existing.ID,
			)
			if err != nil {
				return nil, false, err
			}
			p, err := getPendingByIDLocked(db.WriteDB(), existing.ID)
			return p, false, err
		}
	}

	// Insert new
	result, err := db.WriteDB().Exec(
		`INSERT INTO pending_requests (container_name, container_id, destination_host, destination_port, resolved_hostname)
		 VALUES (?, ?, ?, ?, ?)`,
		containerName, containerID, destHost, destPort, rh,
	)
	if err != nil {
		return nil, false, fmt.Errorf("insert pending: %w", err)
	}

	id, _ := result.LastInsertId()
	p, err := getPendingByIDLocked(db.WriteDB(), id)
	return p, true, err
}

func getPendingByIDLocked(conn *sql.DB, id int64) (*PendingRequest, error) {
	var p PendingRequest
	err := conn.QueryRow(
		`SELECT id, container_name, container_id, destination_host, destination_port,
		        resolved_hostname, first_seen, last_seen, attempt_count
		 FROM pending_requests WHERE id = ?`, id,
	).Scan(&p.ID, &p.ContainerName, &p.ContainerID, &p.DestinationHost,
		&p.DestinationPort, &p.ResolvedHostname, &p.FirstSeen, &p.LastSeen, &p.AttemptCount)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func GetPending(db *DB, id int64) (*PendingRequest, error) {
	return getPendingByIDLocked(db.ReadDB(), id)
}

type PendingFilter struct {
	Container   string
	Destination string
	Limit       int
	Offset      int
}

func GetPendingRequests(db *DB, f PendingFilter) ([]PendingRequest, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}

	where := []string{"1=1"}
	args := []any{}

	if f.Container != "" {
		where = append(where, "container_name LIKE ?")
		args = append(args, "%"+f.Container+"%")
	}
	if f.Destination != "" {
		where = append(where, "(destination_host LIKE ? OR resolved_hostname LIKE ?)")
		args = append(args, "%"+f.Destination+"%", "%"+f.Destination+"%")
	}

	whereClause := strings.Join(where, " AND ")

	// Fetch all matching rows (before LIMIT) for in-memory consolidation
	rows, err := db.ReadDB().Query(
		`SELECT id, container_name, container_id, destination_host, destination_port,
		        resolved_hostname, first_seen, last_seen, attempt_count
		 FROM pending_requests WHERE `+whereClause+` ORDER BY last_seen DESC`,
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var allPending []PendingRequest
	for rows.Next() {
		var p PendingRequest
		if err := rows.Scan(&p.ID, &p.ContainerName, &p.ContainerID, &p.DestinationHost,
			&p.DestinationPort, &p.ResolvedHostname, &p.FirstSeen, &p.LastSeen, &p.AttemptCount); err != nil {
			return nil, 0, err
		}
		allPending = append(allPending, p)
	}

	// Consolidate by (container_name, resolved_hostname, destination_port)
	// When resolved_hostname is set, group by it; otherwise keep as-is.
	type groupKey struct {
		ContainerName    string
		ResolvedHostname string
		DestinationPort  int
	}
	grouped := make(map[groupKey]*PendingRequest)
	var order []groupKey

	for i := range allPending {
		p := &allPending[i]
		var key groupKey
		if p.ResolvedHostname.Valid && p.ResolvedHostname.String != "" {
			key = groupKey{p.ContainerName, p.ResolvedHostname.String, p.DestinationPort}
		} else {
			// No resolved hostname — use destination_host as key (no consolidation possible)
			key = groupKey{p.ContainerName, p.DestinationHost, p.DestinationPort}
		}

		if existing, ok := grouped[key]; ok {
			// Merge: sum attempts, take min first_seen, max last_seen
			existing.AttemptCount += p.AttemptCount
			if p.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = p.FirstSeen
			}
			if p.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = p.LastSeen
			}
		} else {
			clone := *p
			grouped[key] = &clone
			order = append(order, key)
		}
	}

	// Build consolidated list in order
	var consolidated []PendingRequest
	for _, key := range order {
		consolidated = append(consolidated, *grouped[key])
	}

	total := len(consolidated)

	// Apply offset/limit
	start := f.Offset
	if start > len(consolidated) {
		start = len(consolidated)
	}
	end := start + f.Limit
	if end > len(consolidated) {
		end = len(consolidated)
	}

	return consolidated[start:end], total, nil
}

func GetPendingCount(db *DB) (int, error) {
	var count int
	err := db.ReadDB().QueryRow(
		`SELECT COUNT(DISTINCT COALESCE(resolved_hostname, destination_host) || ':' || destination_port || ':' || container_name)
		 FROM pending_requests`,
	).Scan(&count)
	return count, err
}

func DeletePending(db *DB, id int64) (bool, error) {
	db.Lock()
	defer db.Unlock()

	result, err := db.WriteDB().Exec("DELETE FROM pending_requests WHERE id = ?", id)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// deletePendingSiblings removes the pending request and any siblings sharing the same
// container_name, resolved_hostname, and destination_port.
func deletePendingSiblings(db *DB, p *PendingRequest) (int64, error) {
	// Must be called with db.Lock() already held
	var total int64

	// Delete exact match
	result, err := db.WriteDB().Exec("DELETE FROM pending_requests WHERE id = ?", p.ID)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	total += n

	// Delete siblings with same resolved_hostname
	if p.ResolvedHostname.Valid && p.ResolvedHostname.String != "" {
		result, err = db.WriteDB().Exec(
			`DELETE FROM pending_requests
			 WHERE container_name = ? AND resolved_hostname = ? AND destination_port = ? AND id != ?`,
			p.ContainerName, p.ResolvedHostname.String, p.DestinationPort, p.ID,
		)
		if err != nil {
			return total, err
		}
		n, _ = result.RowsAffected()
		total += n
	}

	return total, nil
}

// AllowPending allows a pending request by creating a rule. Returns (rule, error).
func AllowPending(db *DB, id int64, scope, duration string, notes *string) (*Rule, error) {
	p, err := GetPending(db, id)
	if err != nil || p == nil {
		return nil, fmt.Errorf("pending request %d not found", id)
	}

	containerPattern, destPattern, portPattern := buildPatterns(p, scope)
	ruleType, expiresIn := parseDuration(duration)

	// Check for existing identical allow rule
	existingRule := findExistingRule(db, containerPattern, destPattern, portPattern, "allow")
	if existingRule != nil {
		db.Lock()
		deletePendingSiblings(db, p)
		db.Unlock()
		return existingRule, nil
	}

	// Create the rule
	rule, err := CreateRule(db, RuleCreateInput{
		ContainerPattern:   containerPattern,
		DestinationPattern: destPattern,
		PortPattern:        portPattern,
		RuleType:           ruleType,
		Action:             "allow",
		ExpiresInSeconds:   expiresIn,
		Notes:              notes,
	})
	if err != nil {
		return nil, err
	}

	// Delete pending and siblings
	db.Lock()
	deletePendingSiblings(db, p)
	db.Unlock()

	return rule, nil
}

// DenyPending creates a deny rule for a pending request. Returns (rule, error).
func DenyPending(db *DB, id int64, scope, duration string, notes *string) (*Rule, error) {
	p, err := GetPending(db, id)
	if err != nil || p == nil {
		return nil, fmt.Errorf("pending request %d not found", id)
	}

	containerPattern, destPattern, portPattern := buildPatterns(p, scope)
	ruleType, expiresIn := parseDuration(duration)

	// Check for existing identical deny rule
	existingRule := findExistingRule(db, containerPattern, destPattern, portPattern, "deny")
	if existingRule != nil {
		db.Lock()
		deletePendingSiblings(db, p)
		db.Unlock()
		return existingRule, nil
	}

	rule, err := CreateRule(db, RuleCreateInput{
		ContainerPattern:   containerPattern,
		DestinationPattern: destPattern,
		PortPattern:        portPattern,
		RuleType:           ruleType,
		Action:             "deny",
		ExpiresInSeconds:   expiresIn,
		Notes:              notes,
	})
	if err != nil {
		return nil, err
	}

	db.Lock()
	deletePendingSiblings(db, p)
	db.Unlock()

	return rule, nil
}

func buildPatterns(p *PendingRequest, scope string) (container, dest, port string) {
	host := p.DisplayHost()
	portStr := fmt.Sprintf("%d", p.DestinationPort)

	switch scope {
	case "any_port":
		return p.ContainerName, host, "*"
	case "subdomain_wildcard":
		baseDomain := extractBaseDomain(host)
		return p.ContainerName, "*." + baseDomain, "*"
	case "all_containers":
		return "*", host, portStr
	default: // "exact"
		return p.ContainerName, host, portStr
	}
}

func extractBaseDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func parseDuration(duration string) (ruleType string, expiresIn *int64) {
	switch duration {
	case "once":
		v := int64(30)
		return "temporary", &v
	case "1h":
		v := int64(3600)
		return "temporary", &v
	case "12h":
		v := int64(43200)
		return "temporary", &v
	case "24h":
		v := int64(86400)
		return "temporary", &v
	case "7d":
		v := int64(604800)
		return "temporary", &v
	case "30d":
		v := int64(2592000)
		return "temporary", &v
	default: // "permanent"
		return "permanent", nil
	}
}

func findExistingRule(db *DB, containerPattern, destPattern, portPattern, action string) *Rule {
	var r Rule
	err := db.ReadDB().QueryRow(
		`SELECT id, container_pattern, destination_pattern, port_pattern, rule_type, action,
		        created_at, expires_at, last_used_at, created_by, notes
		 FROM rules
		 WHERE container_pattern = ? AND destination_pattern = ? AND port_pattern = ? AND action = ?
		   AND (expires_at IS NULL OR expires_at > datetime('now'))`,
		containerPattern, destPattern, portPattern, action,
	).Scan(&r.ID, &r.ContainerPattern, &r.DestinationPattern, &r.PortPattern,
		&r.RuleType, &r.Action, &r.CreatedAt, &r.ExpiresAt, &r.LastUsedAt, &r.CreatedBy, &r.Notes)
	if err != nil {
		return nil
	}
	return &r
}

// --- Request Logs ---

type LogCreateInput struct {
	ContainerName    string
	ContainerID      string
	DestinationHost  string
	DestinationPort  int
	ResolvedHostname string
	Method           string
	Result           string
	RuleID           *int64
	ResponseTimeMs   *int64
}

func CreateLogEntry(db *DB, input LogCreateInput) (*RequestLog, error) {
	db.Lock()
	defer db.Unlock()

	result, err := db.WriteDB().Exec(
		`INSERT INTO request_logs (container_name, container_id, destination_host, destination_port,
		 resolved_hostname, method, result, rule_id, response_time_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.ContainerName,
		sql.NullString{String: input.ContainerID, Valid: input.ContainerID != ""},
		input.DestinationHost,
		sql.NullInt64{Int64: int64(input.DestinationPort), Valid: input.DestinationPort > 0},
		sql.NullString{String: input.ResolvedHostname, Valid: input.ResolvedHostname != ""},
		sql.NullString{String: input.Method, Valid: input.Method != ""},
		input.Result,
		sql.NullInt64{Int64: ptrInt64OrZero(input.RuleID), Valid: input.RuleID != nil},
		sql.NullInt64{Int64: ptrInt64OrZero(input.ResponseTimeMs), Valid: input.ResponseTimeMs != nil},
	)
	if err != nil {
		return nil, fmt.Errorf("insert log: %w", err)
	}

	id, _ := result.LastInsertId()
	return getLogByID(db.WriteDB(), id)
}

func ptrInt64OrZero(p *int64) int64 {
	if p != nil {
		return *p
	}
	return 0
}

func getLogByID(conn *sql.DB, id int64) (*RequestLog, error) {
	var l RequestLog
	err := conn.QueryRow(
		`SELECT id, timestamp, container_name, container_id, destination_host, destination_port,
		        resolved_hostname, method, result, rule_id, response_time_ms
		 FROM request_logs WHERE id = ?`, id,
	).Scan(&l.ID, &l.Timestamp, &l.ContainerName, &l.ContainerID, &l.DestinationHost,
		&l.DestinationPort, &l.ResolvedHostname, &l.Method, &l.Result, &l.RuleID, &l.ResponseTimeMs)
	if err != nil {
		return nil, err
	}
	return &l, nil
}

type LogFilter struct {
	Container   string
	Destination string
	Result      string
	FromDate    *time.Time
	ToDate      *time.Time
	Limit       int
	Offset      int
}

func QueryLogs(db *DB, f LogFilter) ([]RequestLog, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}

	where := []string{"1=1"}
	args := []any{}

	if f.Container != "" {
		where = append(where, "rl.container_name LIKE ?")
		args = append(args, "%"+f.Container+"%")
	}
	if f.Destination != "" {
		where = append(where, "(rl.destination_host LIKE ? OR rl.resolved_hostname LIKE ?)")
		args = append(args, "%"+f.Destination+"%", "%"+f.Destination+"%")
	}
	if f.Result != "" {
		where = append(where, "rl.result = ?")
		args = append(args, f.Result)
	}
	if f.FromDate != nil {
		where = append(where, "rl.timestamp >= ?")
		args = append(args, f.FromDate.UTC().Format("2006-01-02 15:04:05"))
	}
	if f.ToDate != nil {
		where = append(where, "rl.timestamp <= ?")
		args = append(args, f.ToDate.UTC().Format("2006-01-02 15:04:05"))
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	err := db.ReadDB().QueryRow("SELECT COUNT(*) FROM request_logs rl WHERE "+whereClause, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := db.ReadDB().Query(
		`SELECT rl.id, rl.timestamp, rl.container_name, rl.container_id, rl.destination_host, rl.destination_port,
		        rl.resolved_hostname, rl.method, rl.result, rl.rule_id, rl.response_time_ms,
		        CASE WHEN r.id IS NOT NULL THEN r.container_pattern || ' → ' || r.destination_pattern || ':' || r.port_pattern ELSE NULL END AS rule_summary
		 FROM request_logs rl
		 LEFT JOIN rules r ON rl.rule_id = r.id
		 WHERE `+whereClause+` ORDER BY rl.timestamp DESC LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []RequestLog
	for rows.Next() {
		var l RequestLog
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.ContainerName, &l.ContainerID, &l.DestinationHost,
			&l.DestinationPort, &l.ResolvedHostname, &l.Method, &l.Result, &l.RuleID, &l.ResponseTimeMs,
			&l.RuleSummary); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

// GetDashboardStats returns aggregated dashboard statistics.
func GetDashboardStats(db *DB, fromDate, toDate time.Time, groupBy string, recentLimit int) (*DashboardStats, error) {
	if recentLimit <= 0 {
		recentLimit = 10
	}

	stats := &DashboardStats{
		Period: Period{
			From: fromDate.UTC().Format(time.RFC3339),
			To:   toDate.UTC().Format(time.RFC3339),
		},
	}

	from := fromDate.UTC().Format("2006-01-02 15:04:05")
	to := toDate.UTC().Format("2006-01-02 15:04:05")

	// Totals
	err := db.ReadDB().QueryRow(
		`SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN result = 'allowed' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN result = 'blocked' THEN 1 ELSE 0 END), 0)
		 FROM request_logs WHERE timestamp >= ? AND timestamp <= ?`, from, to,
	).Scan(&stats.TotalRequests, &stats.Allowed, &stats.Blocked)
	if err != nil {
		return nil, err
	}
	if stats.TotalRequests > 0 {
		stats.AllowRate = float64(stats.Allowed) / float64(stats.TotalRequests) * 100
	}

	// By container
	rows, err := db.ReadDB().Query(
		`SELECT container_name,
		        COUNT(*) as total,
		        COALESCE(SUM(CASE WHEN result = 'allowed' THEN 1 ELSE 0 END), 0) as allowed,
		        COALESCE(SUM(CASE WHEN result = 'blocked' THEN 1 ELSE 0 END), 0) as blocked
		 FROM request_logs WHERE timestamp >= ? AND timestamp <= ?
		 GROUP BY container_name ORDER BY total DESC LIMIT 20`, from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var c ContainerStatsItem
		if err := rows.Scan(&c.Name, &c.Total, &c.Allowed, &c.Blocked); err != nil {
			continue
		}
		if stats.TotalRequests > 0 {
			c.Percentage = float64(c.Total) / float64(stats.TotalRequests) * 100
		}
		stats.ByContainer = append(stats.ByContainer, c)
	}
	rows.Close()

	// Top blocked destinations
	rows, err = db.ReadDB().Query(
		`SELECT destination_host, destination_port, COALESCE(resolved_hostname, ''),
		        COUNT(*) as cnt, GROUP_CONCAT(DISTINCT container_name) as containers
		 FROM request_logs
		 WHERE timestamp >= ? AND timestamp <= ? AND result = 'blocked'
		 GROUP BY destination_host, destination_port
		 ORDER BY cnt DESC LIMIT 10`, from, to,
	)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var b BlockedDestinationItem
		var containersStr sql.NullString
		if err := rows.Scan(&b.Host, &b.Port, &b.ResolvedHostname, &b.Count, &containersStr); err != nil {
			continue
		}
		if containersStr.Valid && containersStr.String != "" {
			b.Containers = strings.Split(containersStr.String, ",")
		}
		stats.TopBlocked = append(stats.TopBlocked, b)
	}
	rows.Close()

	// Timeline
	var timeFormat string
	switch groupBy {
	case "day":
		timeFormat = "%Y-%m-%d"
	case "week":
		timeFormat = "%Y-W%W"
	default: // hour
		timeFormat = "%Y-%m-%d %H:00"
	}

	rows, err = db.ReadDB().Query(
		`SELECT strftime('`+timeFormat+`', timestamp) as period,
		        COALESCE(SUM(CASE WHEN result = 'allowed' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN result = 'blocked' THEN 1 ELSE 0 END), 0)
		 FROM request_logs WHERE timestamp >= ? AND timestamp <= ?
		 GROUP BY period ORDER BY period`, from, to,
	)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var t TimelinePoint
		if err := rows.Scan(&t.Timestamp, &t.Allowed, &t.Blocked); err != nil {
			continue
		}
		stats.Timeline = append(stats.Timeline, t)
	}
	rows.Close()

	// Recent logs
	recentLogs, _, err := QueryLogs(db, LogFilter{
		FromDate: &fromDate,
		ToDate:   &toDate,
		Limit:    recentLimit,
	})
	if err != nil {
		return nil, err
	}
	for _, l := range recentLogs {
		stats.Recent = append(stats.Recent, l.ToJSON())
	}

	return stats, nil
}
