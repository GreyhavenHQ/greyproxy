package greyproxy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MiddlewareEventSummary is one middleware decision attached to an
// ActivityItem. Ordered by `Sequence` within the cascade.
type MiddlewareEventSummary struct {
	Sequence       int            `json:"sequence"`
	MiddlewareName string         `json:"middleware_name,omitempty"`
	MiddlewareURL  string         `json:"middleware_url"`
	Hook           string         `json:"hook"`
	Action         string         `json:"action"`
	StatusCode     int            `json:"status_code,omitempty"`
	HeadersChanged []string       `json:"headers_changed,omitempty"`
	BodyRewritten  bool           `json:"body_rewritten,omitempty"`
	Tags           map[string]any `json:"tags,omitempty"`
	DurationMs     int64          `json:"duration_ms,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

// DisplayLabel returns the preferred human identifier for this event's
// middleware: the friendly name if the middleware declared one, otherwise
// the URL. Used by the Activity UI template.
func (m MiddlewareEventSummary) DisplayLabel() string {
	if m.MiddlewareName != "" {
		return m.MiddlewareName
	}
	return m.MiddlewareURL
}

// MiddlewareEventInsert is the input shape for WriteMiddlewareEvent. All
// fields are treated as-given: the caller is responsible for applying the
// "row-worthy" rule (mutating action OR tags).
type MiddlewareEventInsert struct {
	TransactionID   int64
	TransactionKind string // "http" | "connection"
	Sequence        int
	MiddlewareName  string
	MiddlewareURL   string
	Hook            string
	Action          string
	StatusCode      int
	HeadersChanged  []string
	BodyRewritten   bool
	Tags            map[string]any
	DurationMs      int64
}

// WriteMiddlewareEvent inserts one middleware_events row.
func WriteMiddlewareEvent(db *DB, ev MiddlewareEventInsert) error {
	var headersJSON, tagsJSON, nameNS sql.NullString
	if len(ev.HeadersChanged) > 0 {
		if b, err := json.Marshal(ev.HeadersChanged); err == nil {
			headersJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	if len(ev.Tags) > 0 {
		if b, err := json.Marshal(ev.Tags); err == nil {
			tagsJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	if ev.MiddlewareName != "" {
		nameNS = sql.NullString{String: ev.MiddlewareName, Valid: true}
	}
	body := 0
	if ev.BodyRewritten {
		body = 1
	}
	_, err := db.WriteDB().Exec(`INSERT INTO middleware_events
		(transaction_id, transaction_kind, sequence, middleware_url, middleware_name, hook,
		 action, status_code, headers_changed, body_rewritten, tags, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.TransactionID, ev.TransactionKind, ev.Sequence,
		ev.MiddlewareURL, nameNS, ev.Hook, ev.Action, ev.StatusCode,
		headersJSON, body, tagsJSON, ev.DurationMs,
	)
	if err != nil {
		return fmt.Errorf("insert middleware_event: %w", err)
	}
	return nil
}

// LoadMiddlewareEventsForActivity fetches all middleware_events rows whose
// (transaction_kind, transaction_id) matches one of the given activity
// rows. Returns a map keyed by "kind:id" for easy attachment.
func LoadMiddlewareEventsForActivity(db *DB, items []ActivityItem) (map[string][]MiddlewareEventSummary, error) {
	if len(items) == 0 {
		return nil, nil
	}
	// Build one IN clause per kind so we can reuse the composite index.
	httpIDs := make([]any, 0, len(items))
	connIDs := make([]any, 0, len(items))
	for _, it := range items {
		switch it.Kind {
		case "http":
			httpIDs = append(httpIDs, it.ID)
		case "connection":
			connIDs = append(connIDs, it.ID)
		}
	}

	out := make(map[string][]MiddlewareEventSummary)
	query := func(kind string, ids []any) error {
		if len(ids) == 0 {
			return nil
		}
		placeholders := strings.Repeat("?,", len(ids))
		placeholders = placeholders[:len(placeholders)-1]
		q := fmt.Sprintf(`SELECT transaction_id, sequence, middleware_url, middleware_name, hook,
			action, COALESCE(status_code, 0), headers_changed, body_rewritten,
			tags, COALESCE(duration_ms, 0), created_at
			FROM middleware_events
			WHERE transaction_kind = ? AND transaction_id IN (%s)
			ORDER BY transaction_id, sequence`, placeholders)
		args := append([]any{kind}, ids...)
		rows, err := db.ReadDB().Query(q, args...)
		if err != nil {
			return fmt.Errorf("query middleware_events: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				txID                          int64
				sum                           MiddlewareEventSummary
				nameNS, headersJSON, tagsJSON sql.NullString
				bodyRewritten                 int
				createdAt                     string
			)
			if err := rows.Scan(&txID, &sum.Sequence, &sum.MiddlewareURL, &nameNS,
				&sum.Hook, &sum.Action, &sum.StatusCode,
				&headersJSON, &bodyRewritten, &tagsJSON, &sum.DurationMs, &createdAt); err != nil {
				return fmt.Errorf("scan middleware_event: %w", err)
			}
			if nameNS.Valid {
				sum.MiddlewareName = nameNS.String
			}
			sum.BodyRewritten = bodyRewritten != 0
			if headersJSON.Valid {
				_ = json.Unmarshal([]byte(headersJSON.String), &sum.HeadersChanged)
			}
			if tagsJSON.Valid {
				_ = json.Unmarshal([]byte(tagsJSON.String), &sum.Tags)
			}
			sum.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
			if sum.CreatedAt.IsZero() {
				sum.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
			}
			key := fmt.Sprintf("%s:%d", kind, txID)
			out[key] = append(out[key], sum)
		}
		return nil
	}
	if err := query("http", httpIDs); err != nil {
		return nil, err
	}
	if err := query("connection", connIDs); err != nil {
		return nil, err
	}
	return out, nil
}
