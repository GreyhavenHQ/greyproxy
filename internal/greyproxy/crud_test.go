package greyproxy

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *DB {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "greyproxy_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	db, err := OpenDB(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	return db
}

func TestCreateAndGetRule(t *testing.T) {
	db := setupTestDB(t)

	rule, err := CreateRule(db, RuleCreateInput{
		ContainerPattern:   "myapp",
		DestinationPattern: "**.example.com",
		PortPattern:        "443",
		RuleType:           "permanent",
		Action:             "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID == 0 {
		t.Error("expected non-zero ID")
	}
	if rule.ContainerPattern != "myapp" {
		t.Errorf("got container_pattern %q, want %q", rule.ContainerPattern, "myapp")
	}
	if rule.Action != "allow" {
		t.Errorf("got action %q, want %q", rule.Action, "allow")
	}

	// Get by ID
	got, err := GetRule(db, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected rule, got nil")
	}
	if got.DestinationPattern != "**.example.com" {
		t.Errorf("got destination_pattern %q, want %q", got.DestinationPattern, "**.example.com")
	}
}

func TestCreateRuleDefaults(t *testing.T) {
	db := setupTestDB(t)

	rule, err := CreateRule(db, RuleCreateInput{
		ContainerPattern:   "myapp",
		DestinationPattern: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule.PortPattern != "*" {
		t.Errorf("expected default port_pattern '*', got %q", rule.PortPattern)
	}
	if rule.RuleType != "permanent" {
		t.Errorf("expected default rule_type 'permanent', got %q", rule.RuleType)
	}
	if rule.Action != "allow" {
		t.Errorf("expected default action 'allow', got %q", rule.Action)
	}
	if rule.CreatedBy != "admin" {
		t.Errorf("expected default created_by 'admin', got %q", rule.CreatedBy)
	}
}

func TestCreateRuleWithExpiration(t *testing.T) {
	db := setupTestDB(t)

	expires := int64(3600)
	rule, err := CreateRule(db, RuleCreateInput{
		ContainerPattern:   "myapp",
		DestinationPattern: "example.com",
		ExpiresInSeconds:   &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rule.ExpiresAt.Valid {
		t.Error("expected expires_at to be set")
	}
	if rule.ExpiresAt.Time.Before(time.Now()) {
		t.Error("expected expires_at to be in the future")
	}
}

func TestGetRules(t *testing.T) {
	db := setupTestDB(t)

	// Create some rules
	for _, dest := range []string{"a.com", "b.com", "c.com"} {
		_, err := CreateRule(db, RuleCreateInput{
			ContainerPattern:   "*",
			DestinationPattern: dest,
			Action:             "allow",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	rules, total, err := GetRules(db, RuleFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
	if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}
}

func TestGetRulesFilter(t *testing.T) {
	db := setupTestDB(t)

	_, _ = CreateRule(db, RuleCreateInput{ContainerPattern: "myapp", DestinationPattern: "a.com", Action: "allow"})
	_, _ = CreateRule(db, RuleCreateInput{ContainerPattern: "other", DestinationPattern: "b.com", Action: "deny"})

	// Filter by action
	rules, total, err := GetRules(db, RuleFilter{Action: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("expected 1 allow rule, got %d", total)
	}
	if rules[0].DestinationPattern != "a.com" {
		t.Errorf("expected a.com, got %s", rules[0].DestinationPattern)
	}

	// Filter by container
	rules, total, err = GetRules(db, RuleFilter{Container: "myapp"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("expected 1 rule for myapp, got %d", total)
	}
}

func TestUpdateRule(t *testing.T) {
	db := setupTestDB(t)

	rule, _ := CreateRule(db, RuleCreateInput{
		ContainerPattern:   "myapp",
		DestinationPattern: "example.com",
		Action:             "allow",
	})

	newAction := "deny"
	updated, err := UpdateRule(db, rule.ID, RuleUpdateInput{Action: &newAction})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", updated.Action)
	}
}

func TestDeleteRule(t *testing.T) {
	db := setupTestDB(t)

	rule, _ := CreateRule(db, RuleCreateInput{
		ContainerPattern:   "myapp",
		DestinationPattern: "example.com",
	})

	deleted, err := DeleteRule(db, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("expected deletion to succeed")
	}

	got, err := GetRule(db, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected rule to be deleted")
	}

	// Delete non-existent
	deleted, err = DeleteRule(db, 9999)
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Error("expected deletion of non-existent to return false")
	}
}

func TestFindMatchingRule(t *testing.T) {
	db := setupTestDB(t)

	// Create rules with different specificity
	_, _ = CreateRule(db, RuleCreateInput{
		ContainerPattern:   "*",
		DestinationPattern: "*.example.com",
		PortPattern:        "*",
		Action:             "allow",
	})
	_, _ = CreateRule(db, RuleCreateInput{
		ContainerPattern:   "myapp",
		DestinationPattern: "api.example.com",
		PortPattern:        "443",
		Action:             "deny",
	})

	// Specific rule should win
	rule := FindMatchingRule(db, "myapp", "api.example.com", 443, "")
	if rule == nil {
		t.Fatal("expected matching rule")
	}
	if rule.Action != "deny" {
		t.Errorf("expected deny (more specific), got %q", rule.Action)
	}

	// Wildcard rule should match
	rule = FindMatchingRule(db, "other", "foo.example.com", 80, "")
	if rule == nil {
		t.Fatal("expected matching rule")
	}
	if rule.Action != "allow" {
		t.Errorf("expected allow, got %q", rule.Action)
	}

	// No match
	rule = FindMatchingRule(db, "myapp", "other.com", 80, "")
	if rule != nil {
		t.Error("expected no matching rule")
	}
}

func TestFindMatchingRuleWithResolvedHostname(t *testing.T) {
	db := setupTestDB(t)

	_, _ = CreateRule(db, RuleCreateInput{
		ContainerPattern:   "*",
		DestinationPattern: "**.example.com",
		Action:             "allow",
	})

	// Should match via resolved hostname when raw IP doesn't match
	rule := FindMatchingRule(db, "myapp", "1.2.3.4", 443, "api.example.com")
	if rule == nil {
		t.Fatal("expected match via resolved hostname")
	}
	if rule.Action != "allow" {
		t.Errorf("expected allow, got %q", rule.Action)
	}
}

func TestFindMatchingRuleDenyPriority(t *testing.T) {
	db := setupTestDB(t)

	// Create allow and deny with same specificity
	_, _ = CreateRule(db, RuleCreateInput{
		ContainerPattern:   "*",
		DestinationPattern: "example.com",
		PortPattern:        "*",
		Action:             "allow",
	})
	_, _ = CreateRule(db, RuleCreateInput{
		ContainerPattern:   "*",
		DestinationPattern: "example.com",
		PortPattern:        "*",
		Action:             "deny",
	})

	rule := FindMatchingRule(db, "myapp", "example.com", 443, "")
	if rule == nil {
		t.Fatal("expected matching rule")
	}
	if rule.Action != "deny" {
		t.Errorf("deny should take priority at same specificity, got %q", rule.Action)
	}
}

func TestPendingCreateAndUpdate(t *testing.T) {
	db := setupTestDB(t)

	// Create new
	p, isNew, err := CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("expected new pending request")
	}
	if p.ContainerName != "myapp" {
		t.Errorf("got container %q, want %q", p.ContainerName, "myapp")
	}
	if p.AttemptCount != 1 {
		t.Errorf("got attempt_count %d, want 1", p.AttemptCount)
	}

	// Update existing (same container, host, port)
	p2, isNew2, err := CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if isNew2 {
		t.Error("expected update, not new")
	}
	if p2.ID != p.ID {
		t.Errorf("expected same ID %d, got %d", p.ID, p2.ID)
	}
	if p2.AttemptCount != 2 {
		t.Errorf("got attempt_count %d, want 2", p2.AttemptCount)
	}
}

func TestPendingSiblingConsolidation(t *testing.T) {
	db := setupTestDB(t)

	// Create pending for one IP with resolved hostname
	p1, _, _ := CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "example.com")

	// Same container, different IP, same resolved hostname + port → should consolidate
	p2, isNew, _ := CreateOrUpdatePending(db, "myapp", "", "5.6.7.8", 443, "example.com")
	if isNew {
		t.Error("expected sibling consolidation, not new")
	}
	if p2.ID != p1.ID {
		t.Errorf("expected same ID (sibling), got %d vs %d", p2.ID, p1.ID)
	}
}

func TestGetPendingCount(t *testing.T) {
	db := setupTestDB(t)

	count, err := GetPendingCount(db)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "")
	CreateOrUpdatePending(db, "myapp", "", "5.6.7.8", 80, "")

	count, err = GetPendingCount(db)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestDeletePending(t *testing.T) {
	db := setupTestDB(t)

	p, _, _ := CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "")

	deleted, err := DeletePending(db, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("expected deletion")
	}

	got, err := GetPending(db, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil after deletion")
	}
}

func TestAllowPending(t *testing.T) {
	db := setupTestDB(t)

	p, _, _ := CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "example.com")

	rule, err := AllowPending(db, p.ID, "exact", "permanent", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Action != "allow" {
		t.Errorf("expected allow rule, got %q", rule.Action)
	}
	if rule.ContainerPattern != "myapp" {
		t.Errorf("expected container 'myapp', got %q", rule.ContainerPattern)
	}
	if rule.DestinationPattern != "example.com" {
		t.Errorf("expected destination 'example.com', got %q", rule.DestinationPattern)
	}
	if rule.PortPattern != "443" {
		t.Errorf("expected port '443', got %q", rule.PortPattern)
	}

	// Pending should be deleted
	got, _ := GetPending(db, p.ID)
	if got != nil {
		t.Error("expected pending to be deleted after allow")
	}
}

func TestDenyPending(t *testing.T) {
	db := setupTestDB(t)

	p, _, _ := CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "example.com")

	rule, err := DenyPending(db, p.ID, "exact", "24h", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Action != "deny" {
		t.Errorf("expected deny rule, got %q", rule.Action)
	}
	if rule.RuleType != "temporary" {
		t.Errorf("expected temporary, got %q", rule.RuleType)
	}
	if !rule.ExpiresAt.Valid {
		t.Error("expected expires_at to be set for 24h duration")
	}
}

func TestAllowPendingScopes(t *testing.T) {
	tests := []struct {
		scope       string
		wantDest    string
		wantPort    string
		wantContain string
	}{
		{"exact", "example.com", "443", "myapp"},
		{"any_port", "example.com", "*", "myapp"},
		{"subdomain_wildcard", "*.example.com", "*", "myapp"},
		{"all_containers", "example.com", "443", "*"},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			db := setupTestDB(t)
			p, _, _ := CreateOrUpdatePending(db, "myapp", "", "1.2.3.4", 443, "example.com")

			rule, err := AllowPending(db, p.ID, tt.scope, "permanent", nil)
			if err != nil {
				t.Fatal(err)
			}
			if rule.ContainerPattern != tt.wantContain {
				t.Errorf("container: got %q, want %q", rule.ContainerPattern, tt.wantContain)
			}
			if rule.DestinationPattern != tt.wantDest {
				t.Errorf("destination: got %q, want %q", rule.DestinationPattern, tt.wantDest)
			}
			if rule.PortPattern != tt.wantPort {
				t.Errorf("port: got %q, want %q", rule.PortPattern, tt.wantPort)
			}
		})
	}
}

func TestCreateLogEntry(t *testing.T) {
	db := setupTestDB(t)

	entry, err := CreateLogEntry(db, LogCreateInput{
		ContainerName:    "myapp",
		ContainerID:      "abc123",
		DestinationHost:  "example.com",
		DestinationPort:  443,
		ResolvedHostname: "example.com",
		Method:           "SOCKS5",
		Result:           "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID == 0 {
		t.Error("expected non-zero ID")
	}
	if entry.ContainerName != "myapp" {
		t.Errorf("got container %q, want %q", entry.ContainerName, "myapp")
	}
	if entry.Result != "allowed" {
		t.Errorf("got result %q, want %q", entry.Result, "allowed")
	}
}

func TestQueryLogs(t *testing.T) {
	db := setupTestDB(t)

	// Create logs
	CreateLogEntry(db, LogCreateInput{ContainerName: "myapp", DestinationHost: "a.com", Result: "allowed"})
	CreateLogEntry(db, LogCreateInput{ContainerName: "myapp", DestinationHost: "b.com", Result: "blocked"})
	CreateLogEntry(db, LogCreateInput{ContainerName: "other", DestinationHost: "c.com", Result: "allowed"})

	// All logs
	logs, total, err := QueryLogs(db, LogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("expected 3 total, got %d", total)
	}
	if len(logs) != 3 {
		t.Errorf("expected 3 logs, got %d", len(logs))
	}

	// Filter by result
	logs, total, err = QueryLogs(db, LogFilter{Result: "blocked"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("expected 1 blocked, got %d", total)
	}

	// Filter by container
	logs, total, err = QueryLogs(db, LogFilter{Container: "myapp"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("expected 2 for myapp, got %d", total)
	}
}

func TestGetDashboardStats(t *testing.T) {
	db := setupTestDB(t)

	// Create some log data
	CreateLogEntry(db, LogCreateInput{ContainerName: "myapp", DestinationHost: "a.com", Result: "allowed"})
	CreateLogEntry(db, LogCreateInput{ContainerName: "myapp", DestinationHost: "b.com", Result: "blocked"})
	CreateLogEntry(db, LogCreateInput{ContainerName: "other", DestinationHost: "c.com", Result: "allowed"})

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)

	stats, err := GetDashboardStats(db, from, to, "hour", 10)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalRequests != 3 {
		t.Errorf("expected 3 total, got %d", stats.TotalRequests)
	}
	if stats.Allowed != 2 {
		t.Errorf("expected 2 allowed, got %d", stats.Allowed)
	}
	if stats.Blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.Blocked)
	}
}

func TestMigrations(t *testing.T) {
	db := setupTestDB(t)

	// Verify tables exist
	tables := []string{"rules", "pending_requests", "request_logs", "schema_migrations"}
	for _, table := range tables {
		var name string
		err := db.ReadDB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}

	// Verify migrations are idempotent
	if err := db.Migrate(); err != nil {
		t.Errorf("re-running migrations should be idempotent: %v", err)
	}

	// Verify migration versions were recorded
	var count int
	db.ReadDB().QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 migration versions, got %d", count)
	}
}

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"api.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := extractBaseDomain(tt.host)
			if got != tt.want {
				t.Errorf("extractBaseDomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		duration string
		wantType string
		hasExpir bool
	}{
		{"permanent", "permanent", false},
		{"once", "temporary", true},
		{"1h", "temporary", true},
		{"12h", "temporary", true},
		{"24h", "temporary", true},
		{"7d", "temporary", true},
		{"30d", "temporary", true},
	}

	for _, tt := range tests {
		t.Run(tt.duration, func(t *testing.T) {
			ruleType, expires := parseDuration(tt.duration)
			if ruleType != tt.wantType {
				t.Errorf("got type %q, want %q", ruleType, tt.wantType)
			}
			if tt.hasExpir && expires == nil {
				t.Error("expected expires to be set")
			}
			if !tt.hasExpir && expires != nil {
				t.Error("expected expires to be nil")
			}
		})
	}
}

func TestRuleToJSON(t *testing.T) {
	r := Rule{
		ID:                 1,
		ContainerPattern:   "myapp",
		DestinationPattern: "example.com",
		PortPattern:        "443",
		RuleType:           "permanent",
		Action:             "allow",
		CreatedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:          sql.NullTime{},
		LastUsedAt:         sql.NullTime{},
		CreatedBy:          "admin",
		Notes:              sql.NullString{String: "test note", Valid: true},
	}

	j := r.ToJSON()
	if j.ID != 1 {
		t.Errorf("got ID %d, want 1", j.ID)
	}
	if j.ExpiresAt != nil {
		t.Error("expected nil expires_at")
	}
	if j.Notes == nil || *j.Notes != "test note" {
		t.Errorf("got notes %v, want 'test note'", j.Notes)
	}
	if !j.IsActive {
		t.Error("expected IsActive to be true for rule with no expiration")
	}

	// Test IsActive with expired rule
	expired := Rule{
		ID:        2,
		ExpiresAt: sql.NullTime{Time: time.Now().Add(-1 * time.Hour), Valid: true},
	}
	ej := expired.ToJSON()
	if ej.IsActive {
		t.Error("expected IsActive to be false for expired rule")
	}

	// Test IsActive with future expiration
	future := Rule{
		ID:        3,
		ExpiresAt: sql.NullTime{Time: time.Now().Add(1 * time.Hour), Valid: true},
	}
	fj := future.ToJSON()
	if !fj.IsActive {
		t.Error("expected IsActive to be true for rule with future expiration")
	}
}
