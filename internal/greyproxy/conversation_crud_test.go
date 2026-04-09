package greyproxy

import (
	"testing"

	_ "modernc.org/sqlite"
)

func TestUpsertAndGetConversation(t *testing.T) {
	db := setupTestDB(t)

	sp := "You are a helpful assistant."
	sps := "You are a helpful..."
	meta := `{"total_requests":5}`
	reqIDs := `[1,2,3,4,5]`

	err := UpsertConversation(db, ConversationUpsertInput{
		ID:                  "session_abc123",
		Model:               "claude-opus-4-6",
		ContainerName:       "claude",
		Provider:            "anthropic",
		StartedAt:           "2026-03-13T10:00:00Z",
		EndedAt:             "2026-03-13T10:05:00Z",
		TurnCount:           3,
		SystemPrompt:        &sp,
		SystemPromptSummary: &sps,
		LastTurnHasResponse: true,
		MetadataJSON:        &meta,
		RequestIDsJSON:      &reqIDs,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Upsert turns
	prompt1 := "Hello, how are you?"
	prompt2 := "Thanks!"
	steps1 := `[{"type":"assistant","text":"I'm doing well!"}]`
	ts1 := "2026-03-13T10:00:00Z"
	ts2 := "2026-03-13T10:02:00Z"
	dur1 := int64(1000)
	dur2 := int64(500)
	model := "claude-opus-4-6"

	err = UpsertTurns(db, "session_abc123", []TurnInput{
		{TurnNumber: 1, UserPrompt: &prompt1, StepsJSON: &steps1, APICallsInTurn: 1, Timestamp: &ts1, DurationMs: &dur1, Model: &model},
		{TurnNumber: 2, UserPrompt: &prompt2, APICallsInTurn: 1, Timestamp: &ts2, DurationMs: &dur2, Model: &model},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get conversation
	conv, err := GetConversation(db, "session_abc123")
	if err != nil {
		t.Fatal(err)
	}
	if conv == nil {
		t.Fatal("expected conversation, got nil")
	}
	if conv.ID != "session_abc123" {
		t.Errorf("expected ID 'session_abc123', got %q", conv.ID)
	}
	if !conv.Model.Valid || conv.Model.String != "claude-opus-4-6" {
		t.Errorf("expected model 'claude-opus-4-6', got %v", conv.Model)
	}
	if conv.TurnCount != 3 {
		t.Errorf("expected turn_count 3, got %d", conv.TurnCount)
	}
	if len(conv.Turns) != 2 {
		t.Errorf("expected 2 turns, got %d", len(conv.Turns))
	}
	if conv.Turns[0].TurnNumber != 1 {
		t.Errorf("expected turn 1, got %d", conv.Turns[0].TurnNumber)
	}
	if !conv.LastTurnHasResponse {
		t.Error("expected LastTurnHasResponse to be true")
	}

	// Test ToJSON
	j := conv.ToJSON(true)
	if j.ID != "session_abc123" {
		t.Errorf("JSON ID mismatch")
	}
	if len(j.Turns) != 2 {
		t.Errorf("expected 2 JSON turns, got %d", len(j.Turns))
	}
}

func TestQueryConversations(t *testing.T) {
	db := setupTestDB(t)

	// Create a parent and a subagent
	parentID := "session_parent"
	_ = UpsertConversation(db, ConversationUpsertInput{
		ID: "session_parent", Model: "claude-opus-4-6", ContainerName: "claude",
		Provider: "anthropic", StartedAt: "2026-03-13T10:00:00Z", EndedAt: "2026-03-13T10:05:00Z",
		TurnCount: 2,
	})
	_ = UpsertConversation(db, ConversationUpsertInput{
		ID: "session_parent/subagent_1", Model: "claude-opus-4-6", ContainerName: "claude",
		Provider: "anthropic", StartedAt: "2026-03-13T10:01:00Z", EndedAt: "2026-03-13T10:02:00Z",
		TurnCount: 1, ParentConversationID: &parentID,
	})

	// Query top-level
	convs, total, err := QueryConversations(db, ConversationFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("expected 1 top-level conversation, got %d", total)
	}
	if len(convs) != 1 {
		t.Fatalf("expected 1 result, got %d", len(convs))
	}
	if convs[0].ID != "session_parent" {
		t.Errorf("expected session_parent, got %q", convs[0].ID)
	}

	// Query subagents
	subs, err := GetSubagents(db, "session_parent")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subagent, got %d", len(subs))
	}
	if subs[0].ID != "session_parent/subagent_1" {
		t.Errorf("expected subagent ID, got %q", subs[0].ID)
	}
}

func TestUpsertConversationReplace(t *testing.T) {
	db := setupTestDB(t)

	_ = UpsertConversation(db, ConversationUpsertInput{
		ID: "session_test", Model: "claude-3", TurnCount: 1,
	})
	_ = UpsertConversation(db, ConversationUpsertInput{
		ID: "session_test", Model: "claude-4", TurnCount: 5,
	})

	conv, err := GetConversation(db, "session_test")
	if err != nil {
		t.Fatal(err)
	}
	if conv.Model.String != "claude-4" {
		t.Errorf("expected model updated to claude-4, got %q", conv.Model.String)
	}
	if conv.TurnCount != 5 {
		t.Errorf("expected turn_count updated to 5, got %d", conv.TurnCount)
	}
}

func TestConversationProcessingState(t *testing.T) {
	db := setupTestDB(t)

	val, err := GetConversationProcessingState(db, "last_processed_id")
	if err != nil {
		t.Fatal(err)
	}
	if val != "" {
		t.Errorf("expected empty value, got %q", val)
	}

	err = SetConversationProcessingState(db, "last_processed_id", "42")
	if err != nil {
		t.Fatal(err)
	}

	val, err = GetConversationProcessingState(db, "last_processed_id")
	if err != nil {
		t.Fatal(err)
	}
	if val != "42" {
		t.Errorf("expected '42', got %q", val)
	}

	// Update
	_ = SetConversationProcessingState(db, "last_processed_id", "100")
	val, _ = GetConversationProcessingState(db, "last_processed_id")
	if val != "100" {
		t.Errorf("expected '100', got %q", val)
	}
}

func TestUpdateTransactionConversationID(t *testing.T) {
	db := setupTestDB(t)

	// Create a transaction
	txn, err := CreateHttpTransaction(db, HttpTransactionCreateInput{
		ContainerName:   "claude",
		DestinationHost: "api.anthropic.com",
		DestinationPort: 443,
		Method:          "POST",
		URL:             "https://api.anthropic.com/v1/messages",
		StatusCode:      200,
		Result:          "auto",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a conversation
	_ = UpsertConversation(db, ConversationUpsertInput{
		ID: "session_linked", Model: "claude-4", TurnCount: 1,
	})

	// Link them
	err = UpdateTransactionConversationID(db, txn.ID, "session_linked")
	if err != nil {
		t.Fatal(err)
	}

	// Verify reverse lookup
	ids, err := GetTransactionsByConversationID(db, "session_linked")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != txn.ID {
		t.Errorf("expected transaction %d linked, got %v", txn.ID, ids)
	}
}

func TestQueryConversationsWithFilters(t *testing.T) {
	db := setupTestDB(t)

	_ = UpsertConversation(db, ConversationUpsertInput{
		ID: "session_1", Model: "claude-opus-4-6", ContainerName: "app1",
		Provider: "anthropic", StartedAt: "2026-03-13T10:00:00Z", EndedAt: "2026-03-13T10:05:00Z",
		TurnCount: 3,
	})
	_ = UpsertConversation(db, ConversationUpsertInput{
		ID: "session_2", Model: "claude-haiku-4-5-20251001", ContainerName: "app2",
		Provider: "anthropic", StartedAt: "2026-03-13T11:00:00Z", EndedAt: "2026-03-13T11:05:00Z",
		TurnCount: 1,
	})

	// Filter by container
	convs, total, _ := QueryConversations(db, ConversationFilter{Container: "app1", Limit: 50})
	if total != 1 || convs[0].ID != "session_1" {
		t.Errorf("container filter failed: total=%d", total)
	}

	// Filter by model
	convs, total, _ = QueryConversations(db, ConversationFilter{Model: "claude-haiku-4-5-20251001", Limit: 50})
	if total != 1 || convs[0].ID != "session_2" {
		t.Errorf("model filter failed: total=%d", total)
	}
}
