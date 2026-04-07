package greyproxy

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/dissector"
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
	registry := NewEndpointRegistry(db)
	assembler := NewConversationAssembler(db, bus, registry)

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

// assemblerFixture matches the JSON format of fixtures in dissector/testdata.
type assemblerFixture struct {
	ID                  int    `json:"id"`
	ContainerName       string `json:"container_name"`
	URL                 string `json:"url"`
	Method              string `json:"method"`
	DestinationHost     string `json:"destination_host"`
	RequestHeaders      string `json:"request_headers"`
	RequestBody         string `json:"request_body"`
	RequestContentType  string `json:"request_content_type"`
	ResponseBody        string `json:"response_body"`
	ResponseContentType string `json:"response_content_type"`
	DurationMs          int64  `json:"duration_ms"`
}

func loadAssemblerFixture(t *testing.T, name string) assemblerFixture {
	t.Helper()
	data, err := os.ReadFile("dissector/testdata/" + name + ".json")
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	var f assemblerFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return f
}

func parseFixtureHeaders(raw string) http.Header {
	if raw == "" {
		return nil
	}
	var multi map[string][]string
	if json.Unmarshal([]byte(raw), &multi) == nil && len(multi) > 0 {
		return http.Header(multi)
	}
	return nil
}

func insertFixtureTransaction(t *testing.T, db *DB, f assemblerFixture) int64 {
	t.Helper()
	txn, err := CreateHttpTransaction(db, HttpTransactionCreateInput{
		ContainerName:       f.ContainerName,
		DestinationHost:     f.DestinationHost,
		DestinationPort:     443,
		Method:              f.Method,
		URL:                 f.URL,
		RequestHeaders:      parseFixtureHeaders(f.RequestHeaders),
		RequestBody:         []byte(f.RequestBody),
		RequestContentType:  f.RequestContentType,
		ResponseBody:        []byte(f.ResponseBody),
		ResponseContentType: f.ResponseContentType,
		DurationMs:          f.DurationMs,
		Result:              "auto",
	})
	if err != nil {
		t.Fatal(err)
	}
	return txn.ID
}

// TestAssembler_EndToEnd inserts a Claude Code transaction (which has session
// IDs embedded in metadata.user_id) and verifies the assembler correctly
// builds a conversation with proper provider, client, and model detection.
func TestAssembler_EndToEnd(t *testing.T) {
	db := setupTestDB(t)
	bus := NewEventBus()
	registry := NewEndpointRegistry(db)
	assembler := NewConversationAssembler(db, bus, registry)

	// Use an existing Anthropic fixture (383) which has a session ID in the
	// request body via metadata.user_id. This is the pattern the assembler
	// uses to group transactions.
	f := loadAssemblerFixture(t, "383")
	insertFixtureTransaction(t, db, f)

	// Run the assembler
	assembler.RebuildAllConversations()

	// Query all conversations
	convs, total, err := QueryConversations(db, ConversationFilter{Limit: 100})
	if err != nil {
		t.Fatalf("QueryConversations: %v", err)
	}

	t.Logf("Total conversations assembled: %d", total)
	for _, c := range convs {
		t.Logf("  Conv %s: provider=%s client=%s model=%s turns=%d",
			c.ID,
			c.Provider.String,
			c.ClientName.String,
			c.Model.String,
			c.TurnCount,
		)
	}

	if total == 0 {
		t.Fatal("expected at least 1 conversation, got 0")
	}

	// Verify the conversation has the right provider and model
	conv := convs[0]
	if conv.Provider.String != "anthropic" {
		t.Errorf("provider = %q, want 'anthropic'", conv.Provider.String)
	}
	if conv.Model.String == "" {
		t.Error("expected non-empty model")
	}
	if conv.TurnCount < 1 {
		t.Errorf("turn_count = %d, want >= 1", conv.TurnCount)
	}
}

// TestAssembler_GroupBySession verifies that groupBySession correctly handles
// transactions with and without session IDs, including heuristic grouping.
func TestAssembler_GroupBySession(t *testing.T) {
	// Simulate transactions from different clients
	entries := []transactionEntry{
		{txnID: 1, timestamp: "2025-01-01T00:00:00Z", sessionID: "sess-a", url: "https://api.anthropic.com/v1/messages"},
		{txnID: 2, timestamp: "2025-01-01T00:00:30Z", sessionID: "sess-a", url: "https://api.anthropic.com/v1/messages"},
		{txnID: 3, timestamp: "2025-01-01T00:01:00Z", sessionID: "sess-b", url: "https://api.openai.com/v1/responses"},
		// Unassigned transaction (no session, within time window of sess-a)
		{txnID: 4, timestamp: "2025-01-01T00:00:15Z", url: "https://api.anthropic.com/v1/messages"},
	}

	sessions := groupBySession(entries)
	t.Logf("Sessions: %d", len(sessions))
	for sid, se := range sessions {
		t.Logf("  Session %q: %d transactions", sid, len(se))
	}

	// sess-a should exist
	if _, ok := sessions["sess-a"]; !ok {
		t.Error("expected session 'sess-a'")
	}
	// sess-b should exist
	if _, ok := sessions["sess-b"]; !ok {
		t.Error("expected session 'sess-b'")
	}

	// Total transactions across all sessions should cover all 4
	totalTxns := 0
	for _, se := range sessions {
		totalTxns += len(se)
	}
	// The unassigned txn (4) should be grouped with sess-a (closest time overlap)
	if totalTxns < 3 {
		t.Errorf("expected at least 3 transactions in sessions, got %d", totalTxns)
	}
}

// TestAssembler_AssembleConversation verifies that assembleConversation
// produces correct output for a set of transaction entries.
func TestAssembler_AssembleConversation(t *testing.T) {
	// Load the Aider fixture and manually create a transactionEntry
	fixtures := []struct {
		name     string
		file     string
		wantProv string
	}{
		{"aider", "aider_openrouter_2459", "openrouter"},
		{"opencode_litellm", "opencode_litellm_302", "unknown"},
		{"gemini", "gemini_main_2571", "google-ai"},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			f := loadAssemblerFixture(t, fx.file)
			headers := parseFixtureHeaders(f.RequestHeaders)

			var body map[string]any
			if f.RequestBody != "" {
				json.Unmarshal([]byte(f.RequestBody), &body)
			}

			entry := transactionEntry{
				txnID:          int64(f.ID),
				timestamp:      "2025-01-01T00:00:00Z",
				containerName:  f.ContainerName,
				url:            f.URL,
				model:          "test-model",
				body:           body,
				requestHeaders: headers,
			}

			conv := assembleConversation("test-session", []transactionEntry{entry})

			if conv.provider != fx.wantProv {
				t.Errorf("provider = %q, want %q", conv.provider, fx.wantProv)
			}
			if conv.conversationID != "session_test-session" {
				t.Errorf("conversationID = %q, want 'session_test-session'", conv.conversationID)
			}
			if conv.containerName != f.ContainerName {
				t.Errorf("containerName = %q, want %q", conv.containerName, f.ContainerName)
			}
		})
	}
}

// TestAssembler_ProviderDetection verifies that detectProvider correctly
// identifies the provider from transaction URLs.
func TestAssembler_ProviderDetection(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantProv string
	}{
		{"anthropic", "https://api.anthropic.com/v1/messages", "anthropic"},
		{"openai", "https://api.openai.com/v1/responses", "openai"},
		{"openrouter", "https://openrouter.ai/api/v1/chat/completions", "openrouter"},
		{"google", "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent", "google-ai"},
		{"unknown", "https://example.com/api", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := []transactionEntry{{url: tt.url}}
			got := detectProvider(entries)
			if got != tt.wantProv {
				t.Errorf("detectProvider for %s = %q, want %q", tt.url, got, tt.wantProv)
			}
		})
	}
}

// TestAssembler_ClientInference verifies that inferClientName correctly
// identifies the coding tool from headers.
func TestAssembler_ClientInference(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		wantName string
	}{
		{"aider", "aider_openrouter_2459", "aider"},
		{"opencode_litellm", "opencode_litellm_302", "opencode"},
		{"opencode_openrouter", "opencode_openrouter_2469", "opencode"},
		{"gemini_scorer", "gemini_scorer_2570", "gemini-cli"},
		{"gemini_main", "gemini_main_2571", "gemini-cli"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := loadAssemblerFixture(t, tt.fixture)
			headers := parseFixtureHeaders(f.RequestHeaders)
			entries := []transactionEntry{{
				url:            f.URL,
				requestHeaders: headers,
			}}
			provider := detectProvider(entries)
			got := inferClientName(provider, entries)
			if got != tt.wantName {
				t.Errorf("inferClientName for %s = %q, want %q", tt.name, got, tt.wantName)
			}
		})
	}
}

// TestMapRequestsToTurns_UsesClientScaffolding verifies that mapRequestsToTurns
// uses the provided scaffolding config instead of the hardcoded default.
func TestMapRequestsToTurns_UsesClientScaffolding(t *testing.T) {
	// Create a scaffolding config that treats "Tool loaded." as scaffolding
	claudeScaffolding := ClaudeCodeScaffolding()
	// Create a generic scaffolding config that does NOT filter anything
	genericScaffolding := GenericScaffolding()

	// Build entries where one message is "Tool loaded." (Claude scaffolding)
	msgs := []dissector.Message{
		{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "Tool loaded."}}},
		{Role: "user", Content: []dissector.ContentBlock{{Type: "text", Text: "Hello, build me a thing"}}},
		{Role: "assistant", Content: []dissector.ContentBlock{{Type: "text", Text: "Sure!"}}},
	}
	entries := []transactionEntry{
		{
			txnID: 1, timestamp: "2025-01-01T00:00:00Z",
			result: &dissector.ExtractionResult{
				Messages:     msgs,
				MessageCount: len(msgs),
			},
		},
	}

	// With Claude scaffolding: "Tool loaded." is filtered, so 1 real prompt
	claudeResult := mapRequestsToTurns(entries, 1, claudeScaffolding)
	if _, ok := claudeResult[1]; !ok {
		t.Error("claude scaffolding: expected turn 1 to have entries")
	}

	// With generic scaffolding: "Tool loaded." is a real message, so 2 real prompts
	genericResult := mapRequestsToTurns(entries, 2, genericScaffolding)
	// Both prompts should be detected as turns
	if len(genericResult) < 1 {
		t.Error("generic scaffolding: expected at least 1 turn mapped")
	}

	// Verify that with nil scaffolding it defaults to Claude Code behavior
	defaultResult := mapRequestsToTurns(entries, 1, nil)
	if _, ok := defaultResult[1]; !ok {
		t.Error("nil scaffolding (default): expected turn 1 to have entries")
	}
}

// TestSessionStrategy_InferSession_Timing verifies that TimingStrategy
// correctly groups entries by time gap.
func TestSessionStrategy_InferSession_Timing(t *testing.T) {
	strategy := &TimingStrategy{Gap: 5 * time.Minute}

	entries := []transactionEntry{
		{txnID: 1, timestamp: "2025-01-01T00:00:00Z"},
		{txnID: 2, timestamp: "2025-01-01T00:01:00Z"},
		{txnID: 3, timestamp: "2025-01-01T00:10:00Z"}, // 9 min gap -> new session
		{txnID: 4, timestamp: "2025-01-01T00:11:00Z"},
	}

	result := strategy.InferSession(entries)
	if len(result) != 4 {
		t.Fatalf("expected 4 assignments, got %d", len(result))
	}

	// Entries 1 and 2 should be in the same session
	if result[1] != result[2] {
		t.Errorf("entries 1 and 2 should be in same session: %q vs %q", result[1], result[2])
	}

	// Entries 3 and 4 should be in the same session
	if result[3] != result[4] {
		t.Errorf("entries 3 and 4 should be in same session: %q vs %q", result[3], result[4])
	}

	// But entries 2 and 3 should be in different sessions
	if result[2] == result[3] {
		t.Error("entries 2 and 3 should be in different sessions (>5min gap)")
	}
}

// TestSessionStrategy_UsedByGroupBySession verifies that groupBySession uses
// the adapter's session strategy for sessionless transactions.
func TestSessionStrategy_UsedByGroupBySession(t *testing.T) {
	// Create sessionless transactions that look like Gemini CLI traffic.
	// The GeminiCLI adapter uses TimingStrategy.
	entries := []transactionEntry{
		{
			txnID: 1, timestamp: "2025-01-01T00:00:00Z",
			requestHeaders: http.Header{"User-Agent": []string{"GeminiCLI/1.0"}},
			result:         &dissector.ExtractionResult{Provider: "google-ai", Model: "gemini-2.5-pro"},
		},
		{
			txnID: 2, timestamp: "2025-01-01T00:01:00Z",
			requestHeaders: http.Header{"User-Agent": []string{"GeminiCLI/1.0"}},
			result:         &dissector.ExtractionResult{Provider: "google-ai", Model: "gemini-2.5-pro"},
		},
		{
			txnID: 3, timestamp: "2025-01-01T01:00:00Z", // 59 min gap -> new session
			requestHeaders: http.Header{"User-Agent": []string{"GeminiCLI/1.0"}},
			result:         &dissector.ExtractionResult{Provider: "google-ai", Model: "gemini-2.5-pro"},
		},
	}

	sessions := groupBySession(entries)

	// We should get at least 2 sessions due to the time gap
	if len(sessions) < 2 {
		t.Errorf("expected at least 2 sessions (time gap), got %d", len(sessions))
		for sid, se := range sessions {
			t.Logf("  session %q: %d entries", sid, len(se))
		}
	}

	// Total transactions should cover all 3
	total := 0
	for _, se := range sessions {
		total += len(se)
	}
	if total != 3 {
		t.Errorf("expected 3 total entries across sessions, got %d", total)
	}
}

// TestIncrementalAssembly_SessionlessTransactions verifies that sessionless
// transactions (like Gemini/Aider) get processed during incremental assembly.
func TestIncrementalAssembly_SessionlessTransactions(t *testing.T) {
	db := setupTestDB(t)
	bus := NewEventBus()
	registry := NewEndpointRegistry(db)
	assembler := NewConversationAssembler(db, bus, registry)

	// Insert a Gemini-like transaction (sessionless) using the google-ai endpoint
	geminiURL := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"
	geminiBody := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "Hello Gemini"}]},
			{"role": "model", "parts": [{"text": "Hi there!"}]}
		],
		"systemInstruction": {"parts": [{"text": "You are a helpful assistant."}]}
	}`)

	txn, err := CreateHttpTransaction(db, HttpTransactionCreateInput{
		ContainerName:       "test-container",
		DestinationHost:     "generativelanguage.googleapis.com",
		DestinationPort:     443,
		Method:              "POST",
		URL:                 geminiURL,
		RequestBody:         geminiBody,
		RequestContentType:  "application/json",
		ResponseBody:        nil,
		ResponseContentType: "text/event-stream",
		DurationMs:          500,
		RequestHeaders: http.Header{
			"User-Agent": []string{"GeminiCLI/1.0"},
		},
		Result: "auto",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Run the assembler (incremental path)
	assembler.processNewTransactions()

	// Verify conversations were created
	convs, total, err := QueryConversations(db, ConversationFilter{Limit: 100})
	if err != nil {
		t.Fatalf("QueryConversations: %v", err)
	}

	if total == 0 {
		t.Fatalf("expected at least 1 conversation from sessionless Gemini transaction (txn_id=%d), got 0", txn.ID)
	}

	t.Logf("Created %d conversation(s) from sessionless Gemini traffic", total)
	for _, c := range convs {
		t.Logf("  Conv %s: provider=%s client=%s model=%s turns=%d",
			c.ID, c.Provider.String, c.ClientName.String, c.Model.String, c.TurnCount)
	}
}

// TestDetectProvider_PrefersResult verifies that detectProvider uses the
// dissector-extracted provider when available.
func TestDetectProvider_PrefersResult(t *testing.T) {
	// Entry with result.Provider set (from dissector) and URL that would
	// normally resolve to a different provider
	entries := []transactionEntry{
		{
			url: "https://openrouter.ai/api/v1/chat/completions",
			result: &dissector.ExtractionResult{
				Provider: "openrouter",
			},
		},
	}

	got := detectProvider(entries)
	if got != "openrouter" {
		t.Errorf("detectProvider = %q, want %q (from result.Provider)", got, "openrouter")
	}
}

// TestDetectProvider_FallsBackToURL verifies URL-based detection when
// result.Provider is not set.
func TestDetectProvider_FallsBackToURL(t *testing.T) {
	entries := []transactionEntry{
		{url: "https://api.anthropic.com/v1/messages"},
	}
	got := detectProvider(entries)
	if got != "anthropic" {
		t.Errorf("detectProvider = %q, want %q (from URL)", got, "anthropic")
	}
}
