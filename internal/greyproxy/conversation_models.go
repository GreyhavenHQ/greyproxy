package greyproxy

import (
	"database/sql"
	"encoding/json"
)

// Conversation represents a reconstructed LLM conversation.
type Conversation struct {
	ID                   string         `json:"id"`
	Model                sql.NullString `json:"-"`
	ContainerName        sql.NullString `json:"-"`
	Provider             sql.NullString `json:"-"`
	StartedAt            sql.NullString `json:"-"`
	EndedAt              sql.NullString `json:"-"`
	TurnCount            int            `json:"turn_count"`
	SystemPrompt         sql.NullString `json:"-"`
	SystemPromptSummary  sql.NullString `json:"-"`
	ParentConversationID sql.NullString `json:"-"`
	LastTurnHasResponse  bool           `json:"-"`
	MetadataJSON         sql.NullString `json:"-"`
	LinkedSubagentsJSON  sql.NullString `json:"-"`
	RequestIDsJSON       sql.NullString `json:"-"`
	Incomplete           bool           `json:"-"`
	IncompleteReason     sql.NullString `json:"-"`
	ClientName           sql.NullString `json:"-"`
	UpdatedAt            sql.NullString `json:"-"`

	// Populated by queries, not stored directly
	Turns      []Turn `json:"-"`
	FirstPrompt string `json:"-"`
}

// ConversationJSON is the API response format for a conversation.
type ConversationJSON struct {
	ID                   string   `json:"id"`
	Model                *string  `json:"model"`
	ContainerName        *string  `json:"container_name"`
	Provider             *string  `json:"provider,omitempty"`
	StartedAt            *string  `json:"started_at"`
	EndedAt              *string  `json:"ended_at"`
	TurnCount            int      `json:"turn_count"`
	SystemPrompt         *string  `json:"system_prompt,omitempty"`
	SystemPromptSummary  *string  `json:"system_prompt_summary,omitempty"`
	ParentConversationID *string  `json:"parent_conversation_id,omitempty"`
	LastTurnHasResponse  bool     `json:"last_turn_has_response"`
	Metadata             any      `json:"metadata,omitempty"`
	LinkedSubagents      any      `json:"linked_subagents,omitempty"`
	RequestIDs           any      `json:"request_ids,omitempty"`
	Incomplete           bool     `json:"incomplete"`
	IncompleteReason     *string  `json:"incomplete_reason,omitempty"`
	ClientName           *string  `json:"client_name,omitempty"`
	FirstPrompt          *string  `json:"first_prompt,omitempty"`
	Turns                []TurnJSON `json:"turns,omitempty"`
}

func (c *Conversation) ToJSON(includeTurns bool) ConversationJSON {
	j := ConversationJSON{
		ID:                  c.ID,
		TurnCount:           c.TurnCount,
		LastTurnHasResponse: c.LastTurnHasResponse,
		Incomplete:          c.Incomplete,
	}
	if c.Model.Valid {
		j.Model = &c.Model.String
	}
	if c.ContainerName.Valid {
		j.ContainerName = &c.ContainerName.String
	}
	if c.Provider.Valid {
		j.Provider = &c.Provider.String
	}
	if c.StartedAt.Valid {
		j.StartedAt = &c.StartedAt.String
	}
	if c.EndedAt.Valid {
		j.EndedAt = &c.EndedAt.String
	}
	if c.SystemPrompt.Valid {
		j.SystemPrompt = &c.SystemPrompt.String
	}
	if c.SystemPromptSummary.Valid {
		j.SystemPromptSummary = &c.SystemPromptSummary.String
	}
	if c.ParentConversationID.Valid {
		j.ParentConversationID = &c.ParentConversationID.String
	}
	if c.IncompleteReason.Valid {
		j.IncompleteReason = &c.IncompleteReason.String
	}
	if c.ClientName.Valid {
		j.ClientName = &c.ClientName.String
	}
	if c.MetadataJSON.Valid {
		var v any
		if json.Unmarshal([]byte(c.MetadataJSON.String), &v) == nil {
			j.Metadata = v
		}
	}
	if c.LinkedSubagentsJSON.Valid {
		var v any
		if json.Unmarshal([]byte(c.LinkedSubagentsJSON.String), &v) == nil {
			j.LinkedSubagents = v
		}
	}
	if c.RequestIDsJSON.Valid {
		var v any
		if json.Unmarshal([]byte(c.RequestIDsJSON.String), &v) == nil {
			j.RequestIDs = v
		}
	}
	if c.FirstPrompt != "" {
		j.FirstPrompt = &c.FirstPrompt
	}
	if includeTurns {
		for _, t := range c.Turns {
			j.Turns = append(j.Turns, t.ToJSON())
		}
	}
	return j
}

// Turn represents a single turn in a conversation.
type Turn struct {
	ID              int64          `json:"id"`
	ConversationID  string         `json:"conversation_id"`
	TurnNumber      int            `json:"turn_number"`
	UserPrompt      sql.NullString `json:"-"`
	StepsJSON       sql.NullString `json:"-"`
	APICallsInTurn  int            `json:"api_calls_in_turn"`
	RequestIDsJSON  sql.NullString `json:"-"`
	Timestamp       sql.NullString `json:"-"`
	TimestampEnd    sql.NullString `json:"-"`
	DurationMs      sql.NullInt64  `json:"-"`
	Model           sql.NullString `json:"-"`
}

// TurnJSON is the API response format for a turn.
type TurnJSON struct {
	TurnNumber     int     `json:"turn_number"`
	UserPrompt     *string `json:"user_prompt"`
	Steps          any     `json:"steps,omitempty"`
	APICallsInTurn int     `json:"api_calls_in_turn"`
	RequestIDs     any     `json:"request_ids,omitempty"`
	Timestamp      *string `json:"timestamp,omitempty"`
	TimestampEnd   *string `json:"timestamp_end,omitempty"`
	DurationMs     *int64  `json:"duration_ms,omitempty"`
	Model          *string `json:"model,omitempty"`
}

func (t *Turn) ToJSON() TurnJSON {
	j := TurnJSON{
		TurnNumber:     t.TurnNumber,
		APICallsInTurn: t.APICallsInTurn,
	}
	if t.UserPrompt.Valid {
		j.UserPrompt = &t.UserPrompt.String
	}
	if t.StepsJSON.Valid {
		var v any
		if json.Unmarshal([]byte(t.StepsJSON.String), &v) == nil {
			j.Steps = v
		}
	}
	if t.RequestIDsJSON.Valid {
		var v any
		if json.Unmarshal([]byte(t.RequestIDsJSON.String), &v) == nil {
			j.RequestIDs = v
		}
	}
	if t.Timestamp.Valid {
		j.Timestamp = &t.Timestamp.String
	}
	if t.TimestampEnd.Valid {
		j.TimestampEnd = &t.TimestampEnd.String
	}
	if t.DurationMs.Valid {
		j.DurationMs = &t.DurationMs.Int64
	}
	if t.Model.Valid {
		j.Model = &t.Model.String
	}
	return j
}
