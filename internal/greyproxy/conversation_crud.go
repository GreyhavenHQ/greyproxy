package greyproxy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// ConversationUpsertInput holds data for inserting or updating a conversation.
type ConversationUpsertInput struct {
	ID                   string
	Model                string
	ContainerName        string
	Provider             string
	StartedAt            string
	EndedAt              string
	TurnCount            int
	SystemPrompt         *string
	SystemPromptSummary  *string
	ParentConversationID *string
	LastTurnHasResponse  bool
	MetadataJSON         *string
	LinkedSubagentsJSON  *string
	RequestIDsJSON       *string
	Incomplete           bool
	IncompleteReason     *string
	ClientName           string
}

// TurnInput holds data for inserting a turn.
type TurnInput struct {
	TurnNumber     int
	UserPrompt     *string
	StepsJSON      *string
	APICallsInTurn int
	RequestIDsJSON *string
	Timestamp      *string
	TimestampEnd   *string
	DurationMs     *int64
	Model          *string
}

// UpsertConversation inserts or replaces a conversation record.
func UpsertConversation(db *DB, input ConversationUpsertInput) error {
	db.Lock()
	defer db.Unlock()

	_, err := db.WriteDB().Exec(
		`INSERT OR REPLACE INTO conversations
		 (id, model, container_name, provider, started_at, ended_at, turn_count,
		  system_prompt, system_prompt_summary, parent_conversation_id,
		  last_turn_has_response, metadata_json, linked_subagents_json,
		  request_ids_json, incomplete, incomplete_reason, client_name, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		input.ID, nullStr(input.Model), nullStr(input.ContainerName), nullStr(input.Provider),
		nullStr(input.StartedAt), nullStr(input.EndedAt), input.TurnCount,
		nullStrPtr(input.SystemPrompt), nullStrPtr(input.SystemPromptSummary),
		nullStrPtr(input.ParentConversationID),
		boolToInt(input.LastTurnHasResponse),
		nullStrPtr(input.MetadataJSON), nullStrPtr(input.LinkedSubagentsJSON),
		nullStrPtr(input.RequestIDsJSON),
		boolToInt(input.Incomplete), nullStrPtr(input.IncompleteReason),
		nullStr(input.ClientName),
	)
	return err
}

// UpsertTurns replaces all turns for a conversation.
func UpsertTurns(db *DB, conversationID string, turns []TurnInput) error {
	db.Lock()
	defer db.Unlock()

	if _, err := db.WriteDB().Exec("DELETE FROM turns WHERE conversation_id = ?", conversationID); err != nil {
		return fmt.Errorf("delete old turns: %w", err)
	}

	for _, t := range turns {
		if _, err := db.WriteDB().Exec(
			`INSERT INTO turns
			 (conversation_id, turn_number, user_prompt, steps_json,
			  api_calls_in_turn, request_ids_json, timestamp, timestamp_end,
			  duration_ms, model)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			conversationID, t.TurnNumber,
			nullStrPtr(t.UserPrompt), nullStrPtr(t.StepsJSON),
			t.APICallsInTurn, nullStrPtr(t.RequestIDsJSON),
			nullStrPtr(t.Timestamp), nullStrPtr(t.TimestampEnd),
			nullInt64Ptr(t.DurationMs), nullStrPtr(t.Model),
		); err != nil {
			return fmt.Errorf("insert turn %d: %w", t.TurnNumber, err)
		}
	}
	return nil
}

// ConversationFilter holds query filters for listing conversations.
type ConversationFilter struct {
	Container string
	Model     string
	Provider  string
	ParentID  *string // nil = top-level only (parent IS NULL), non-nil = filter by parent
	Limit     int
	Offset    int
}

// QueryConversations lists conversations with optional filters.
func QueryConversations(db *DB, f ConversationFilter) ([]Conversation, int, error) {
	var where []string
	var args []any

	if f.ParentID != nil {
		where = append(where, "c.parent_conversation_id = ?")
		args = append(args, *f.ParentID)
	} else {
		where = append(where, "c.parent_conversation_id IS NULL")
	}
	if f.Container != "" {
		where = append(where, "c.container_name = ?")
		args = append(args, f.Container)
	}
	if f.Model != "" {
		where = append(where, "c.model = ?")
		args = append(args, f.Model)
	}
	if f.Provider != "" {
		where = append(where, "c.provider = ?")
		args = append(args, f.Provider)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	var total int
	countQ := fmt.Sprintf("SELECT COUNT(*) FROM conversations c %s", whereClause)
	if err := db.ReadDB().QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count conversations: %w", err)
	}

	if f.Limit <= 0 {
		f.Limit = 50
	}

	// Query with first turn's user_prompt for sidebar preview
	q := fmt.Sprintf(`
		SELECT c.id, c.model, c.container_name, c.provider, c.started_at, c.ended_at,
		       c.turn_count, c.system_prompt_summary, c.parent_conversation_id,
		       c.last_turn_has_response, c.linked_subagents_json, c.request_ids_json,
		       c.incomplete, c.metadata_json,
		       (SELECT user_prompt FROM turns WHERE conversation_id = c.id AND turn_number = 1) as first_prompt
		FROM conversations c
		%s
		ORDER BY c.ended_at DESC
		LIMIT ? OFFSET ?`, whereClause)
	args = append(args, f.Limit, f.Offset)

	rows, err := db.ReadDB().Query(q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query conversations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []Conversation
	for rows.Next() {
		var c Conversation
		var firstPrompt sql.NullString
		if err := rows.Scan(
			&c.ID, &c.Model, &c.ContainerName, &c.Provider, &c.StartedAt, &c.EndedAt,
			&c.TurnCount, &c.SystemPromptSummary, &c.ParentConversationID,
			&c.LastTurnHasResponse, &c.LinkedSubagentsJSON, &c.RequestIDsJSON,
			&c.Incomplete, &c.MetadataJSON, &firstPrompt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan conversation: %w", err)
		}
		if firstPrompt.Valid {
			c.FirstPrompt = firstPrompt.String
		}
		results = append(results, c)
	}
	return results, total, nil
}

// GetConversation returns a single conversation with its turns.
func GetConversation(db *DB, id string) (*Conversation, error) {
	var c Conversation
	err := db.ReadDB().QueryRow(`
		SELECT id, model, container_name, provider, started_at, ended_at,
		       turn_count, system_prompt, system_prompt_summary, parent_conversation_id,
		       last_turn_has_response, metadata_json, linked_subagents_json,
		       request_ids_json, incomplete, incomplete_reason, client_name, updated_at
		FROM conversations WHERE id = ?`, id,
	).Scan(
		&c.ID, &c.Model, &c.ContainerName, &c.Provider, &c.StartedAt, &c.EndedAt,
		&c.TurnCount, &c.SystemPrompt, &c.SystemPromptSummary, &c.ParentConversationID,
		&c.LastTurnHasResponse, &c.MetadataJSON, &c.LinkedSubagentsJSON,
		&c.RequestIDsJSON, &c.Incomplete, &c.IncompleteReason, &c.ClientName, &c.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get conversation: %w", err)
	}

	// Load turns
	rows, err := db.ReadDB().Query(`
		SELECT id, conversation_id, turn_number, user_prompt, steps_json,
		       api_calls_in_turn, request_ids_json, timestamp, timestamp_end,
		       duration_ms, model
		FROM turns WHERE conversation_id = ? ORDER BY turn_number`, id)
	if err != nil {
		return nil, fmt.Errorf("query turns: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var t Turn
		if err := rows.Scan(
			&t.ID, &t.ConversationID, &t.TurnNumber, &t.UserPrompt, &t.StepsJSON,
			&t.APICallsInTurn, &t.RequestIDsJSON, &t.Timestamp, &t.TimestampEnd,
			&t.DurationMs, &t.Model,
		); err != nil {
			return nil, fmt.Errorf("scan turn: %w", err)
		}
		c.Turns = append(c.Turns, t)
	}

	return &c, nil
}

// GetSubagents returns conversations that have the given parent ID.
func GetSubagents(db *DB, parentID string) ([]Conversation, error) {
	convs, _, err := QueryConversations(db, ConversationFilter{
		ParentID: &parentID,
		Limit:    100,
	})
	return convs, err
}

// UpdateTransactionConversationID sets the conversation_id FK on an http_transaction.
func UpdateTransactionConversationID(db *DB, txnID int64, convID string) error {
	db.Lock()
	defer db.Unlock()
	_, err := db.WriteDB().Exec(
		"UPDATE http_transactions SET conversation_id = ? WHERE id = ?",
		convID, txnID,
	)
	return err
}

// GetTransactionsByConversationID returns transaction IDs linked to a conversation.
func GetTransactionsByConversationID(db *DB, convID string) ([]int64, error) {
	rows, err := db.ReadDB().Query(
		"SELECT id FROM http_transactions WHERE conversation_id = ? ORDER BY id",
		convID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// GetConversationProcessingState reads a key from the processing_state table.
func GetConversationProcessingState(db *DB, key string) (string, error) {
	var value string
	err := db.ReadDB().QueryRow(
		"SELECT value FROM conversation_processing_state WHERE key = ?", key,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetConversationProcessingState writes a key-value pair to the processing_state table.
func SetConversationProcessingState(db *DB, key, value string) error {
	db.Lock()
	defer db.Unlock()
	_, err := db.WriteDB().Exec(
		"INSERT OR REPLACE INTO conversation_processing_state (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}

// DeleteAllConversations removes all conversations, turns, and conversation_id
// links from http_transactions. Used during full rebuild to avoid stale orphans.
func DeleteAllConversations(db *DB) error {
	db.Lock()
	defer db.Unlock()
	tx, err := db.WriteDB().Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.Exec("DELETE FROM turns")
	_, _ = tx.Exec("DELETE FROM conversations")
	_, _ = tx.Exec("UPDATE http_transactions SET conversation_id = NULL WHERE conversation_id IS NOT NULL")
	return tx.Commit()
}

// --- helpers ---

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullStrPtr(s *string) sql.NullString {
	if s == nil || *s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullInt64Ptr(i *int64) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *i, Valid: true}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// jsonMarshalOrNil marshals v to a JSON string pointer, or returns nil if v is nil/empty.
func jsonMarshalOrNil(v any) *string {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	s := string(b)
	if s == "null" || s == "[]" || s == "{}" {
		return nil
	}
	return &s
}
