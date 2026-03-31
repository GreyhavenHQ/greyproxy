package greyproxy

import (
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// helper to insert a minimal Anthropic-like transaction for assembler tests.
func insertAssemblerTransaction(t *testing.T, db *DB, containerName, url string, requestBody []byte) int64 {
	t.Helper()
	txn, err := CreateHttpTransaction(db, HttpTransactionCreateInput{
		ContainerName:       containerName,
		DestinationHost:     "api.anthropic.com",
		DestinationPort:     443,
		Method:              "POST",
		URL:                 url,
		RequestBody:         requestBody,
		RequestContentType:  "application/json",
		ResponseBody:        nil,
		ResponseContentType: "text/event-stream",
		Result:              "auto",
	})
	if err != nil {
		t.Fatal(err)
	}
	return txn.ID
}

func TestTruncateUTF8(t *testing.T) {
	tests := []struct {
		input    string
		max      int
		expected string
	}{
		{"hello", 10, "hello"},       // shorter than max
		{"hello", 5, "hello"},        // exact length
		{"hello", 3, "hel"},          // simple ASCII truncation
		{"héllo", 2, "h"},            // don't split 2-byte é (0xC3 0xA9)
		{"héllo", 3, "hé"},           // include the full é
		{"日本語", 3, "日"},           // 3-byte CJK char fits exactly
		{"日本語", 4, "日"},           // 4 bytes, but 本 needs 3 more, so still just 日
		{"日本語", 6, "日本"},         // two 3-byte chars
		{"a🎉b", 2, "a"},            // don't split 4-byte emoji
		{"a🎉b", 5, "a🎉"},         // include full emoji
		{"", 5, ""},                  // empty string
	}
	for _, tt := range tests {
		got := truncateUTF8(tt.input, tt.max)
		if got != tt.expected {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.expected)
		}
	}
}

// TestEscapeLikePattern verifies that SQL LIKE special characters are properly escaped.
func TestEscapeLikePattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{"has%percent", `has\%percent`},
		{"has_underscore", `has\_underscore`},
		{`has\backslash`, `has\\backslash`},
		{"%_%", `\%\_\%`},
	}
	for _, tt := range tests {
		got := escapeLikePattern(tt.input)
		if got != tt.want {
			t.Errorf("escapeLikePattern(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestLoadTransactionsForSessions_LikeInjection tests that SQL LIKE wildcards
// in session IDs are escaped and don't match unrelated rows.
func TestLoadTransactionsForSessions_LikeInjection(t *testing.T) {
	db := setupTestDB(t)
	apiURL := "https://api.anthropic.com/v1/messages"

	// Insert transactions with different session IDs embedded in the body
	body1 := []byte(`{"metadata":{"user_id":"user_abc_session_aaaa-bbbb-cccc"},"messages":[]}`)
	body2 := []byte(`{"metadata":{"user_id":"user_abc_session_xxxx-yyyy-zzzz"},"messages":[]}`)

	id1 := insertAssemblerTransaction(t, db, "test", apiURL, body1)
	id2 := insertAssemblerTransaction(t, db, "test", apiURL, body2)

	// Test: searching for session "%" should NOT match any rows (literal percent)
	t.Run("percent_wildcard", func(t *testing.T) {
		count := countMatchingTransactions(t, db, "%")
		if count != 0 {
			t.Errorf("session ID '%%' matched %d rows, want 0 (LIKE injection!)", count)
		}
	})

	// Test: searching for "aaaa_bbbb_cccc" should NOT match "aaaa-bbbb-cccc"
	// because _ should be literal, not a single-char wildcard
	t.Run("underscore_wildcard", func(t *testing.T) {
		body3 := []byte(`{"metadata":{"user_id":"user_abc_session_aaaa_bbbb_cccc"},"messages":[]}`)
		insertAssemblerTransaction(t, db, "test", apiURL, body3)

		count := countMatchingTransactions(t, db, "aaaa_bbbb_cccc")
		// Should match exactly 1 (the one with literal underscores), not 2
		if count != 1 {
			t.Errorf("session ID 'aaaa_bbbb_cccc' matched %d rows, want 1", count)
		}
	})

	// Sanity check: normal session IDs still work
	t.Run("normal_match", func(t *testing.T) {
		count := countMatchingTransactions(t, db, "aaaa-bbbb-cccc")
		if count != 1 {
			t.Errorf("session ID 'aaaa-bbbb-cccc' matched %d rows, want 1", count)
		}
	})

	_ = id1
	_ = id2
}

// countMatchingTransactions runs the same LIKE query used by loadTransactionsForSessions
// and returns the number of matching rows, using proper LIKE escaping.
func countMatchingTransactions(t *testing.T, db *DB, sessionID string) int {
	t.Helper()
	escaped := escapeLikePattern(sessionID)
	query := `SELECT COUNT(*) FROM http_transactions
		WHERE url LIKE '%api.anthropic.com/v1/messages%'
		  AND CAST(request_body AS TEXT) LIKE ? ESCAPE '\'`
	var count int
	err := db.ReadDB().QueryRow(query, "%session_"+escaped+"%").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

// countMatchingTransactionsUnescaped shows the bug: without escaping, LIKE
// wildcards in session IDs match unintended rows.
func countMatchingTransactionsUnescaped(t *testing.T, db *DB, sessionID string) int {
	t.Helper()
	query := `SELECT COUNT(*) FROM http_transactions
		WHERE url LIKE '%api.anthropic.com/v1/messages%'
		  AND CAST(request_body AS TEXT) LIKE ?`
	var count int
	err := db.ReadDB().QueryRow(query, "%session_"+sessionID+"%").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

// TestLikeInjection_Unescaped demonstrates the vulnerability: without escaping,
// a "%" session ID matches all rows.
func TestLikeInjection_Unescaped(t *testing.T) {
	db := setupTestDB(t)
	apiURL := "https://api.anthropic.com/v1/messages"

	body1 := []byte(`{"metadata":{"user_id":"user_abc_session_aaaa-bbbb-cccc"},"messages":[]}`)
	body2 := []byte(`{"metadata":{"user_id":"user_abc_session_xxxx-yyyy-zzzz"},"messages":[]}`)
	insertAssemblerTransaction(t, db, "test", apiURL, body1)
	insertAssemblerTransaction(t, db, "test", apiURL, body2)

	// Without escaping, "%" matches everything
	unescapedCount := countMatchingTransactionsUnescaped(t, db, "%")
	if unescapedCount != 2 {
		t.Fatalf("expected unescaped '%%' to match 2 rows (demonstrating bug), got %d", unescapedCount)
	}

	// With escaping, "%" matches nothing
	escapedCount := countMatchingTransactions(t, db, "%")
	if escapedCount != 0 {
		t.Errorf("expected escaped '%%' to match 0 rows, got %d", escapedCount)
	}
}

func TestConversationAssembler_RaceCondition(t *testing.T) {
	db := setupTestDB(t)
	bus := NewEventBus()
	assembler := NewConversationAssembler(db, bus)

	// Run RebuildAllConversations concurrently to verify no panics or races
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assembler.RebuildAllConversations()
		}()
	}
	wg.Wait()
}
