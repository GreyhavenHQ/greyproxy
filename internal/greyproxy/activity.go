package greyproxy

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ActivityItem represents a unified row from either request_logs or http_transactions.
type ActivityItem struct {
	Kind             string
	ID               int64
	Timestamp        time.Time
	ContainerName    string
	DestinationHost  string
	DestinationPort  int
	Result           string
	ResolvedHostname sql.NullString
	RuleID           sql.NullInt64
	RuleSummary      sql.NullString
	MitmSkipReason sql.NullString
	// HTTP-specific fields
	Method         sql.NullString
	URL            sql.NullString
	StatusCode     sql.NullInt64
	DurationMs     sql.NullInt64
	ConversationID sql.NullString
}

// ActivityFilter specifies filters for the unified activity query.
type ActivityFilter struct {
	Container   string
	Destination string
	Kind        string // "", "connection", "http"
	Result      string // "", "allowed", "blocked"
	FromDate    *time.Time
	ToDate      *time.Time
	Limit  int
	Offset int
}

// QueryActivity returns a unified, time-ordered list from request_logs and http_transactions.
func QueryActivity(db *DB, f ActivityFilter) ([]ActivityItem, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}

	includeConn := f.Kind == "" || f.Kind == "connection"
	includeHTTP := f.Kind == "" || f.Kind == "http"

	// When filtering by result, exclude HTTP transactions (they always use "auto")
	if f.Result != "" && f.Kind == "" {
		includeHTTP = false
	}

	var unionParts []string
	var queryArgs []any
	var countParts []string
	var countArgs []any

	if includeConn {
		where, args := buildActivityConnWhere(f)
		q := fmt.Sprintf(`SELECT 'connection' as kind, l.id, l.timestamp, l.container_name,
			l.destination_host, COALESCE(l.destination_port, 0) as destination_port, l.result,
			l.resolved_hostname, l.rule_id, r.destination_pattern as rule_summary,
			l.mitm_skip_reason,
			NULL as method, NULL as url, NULL as status_code, NULL as duration_ms,
			NULL as conversation_id
			FROM request_logs l LEFT JOIN rules r ON l.rule_id = r.id
			WHERE %s`, where)
		unionParts = append(unionParts, q)
		queryArgs = append(queryArgs, args...)

		cq := fmt.Sprintf(`(SELECT COUNT(*) FROM request_logs l WHERE %s)`, where)
		countParts = append(countParts, cq)
		countArgs = append(countArgs, args...)
	}

	if includeHTTP {
		where, args := buildActivityHTTPWhere(f)
		// Left-join to request_logs to recover the rule that allowed this
		// connection (HTTP transactions don't store rule_id themselves).
		// Use a subquery to find the rule_id from the connection log that
		// allowed this HTTP traffic, avoiding ambiguous column issues.
		q := fmt.Sprintf(`SELECT 'http' as kind, t.id, t.timestamp, t.container_name,
			t.destination_host, t.destination_port, t.result,
			NULL as resolved_hostname,
			COALESCE(t.rule_id, (
				SELECT cl.rule_id FROM request_logs cl
				WHERE cl.container_name = t.container_name
				AND (cl.destination_host = t.destination_host OR cl.resolved_hostname = t.destination_host)
				AND COALESCE(cl.destination_port, 0) = t.destination_port
				AND cl.result = 'allowed' AND cl.rule_id IS NOT NULL
				ORDER BY cl.timestamp DESC LIMIT 1
			)) as rule_id,
			(SELECT r.destination_pattern FROM rules r WHERE r.id = COALESCE(t.rule_id, (
				SELECT cl2.rule_id FROM request_logs cl2
				WHERE cl2.container_name = t.container_name
				AND (cl2.destination_host = t.destination_host OR cl2.resolved_hostname = t.destination_host)
				AND COALESCE(cl2.destination_port, 0) = t.destination_port
				AND cl2.result = 'allowed' AND cl2.rule_id IS NOT NULL
				ORDER BY cl2.timestamp DESC LIMIT 1
			))) as rule_summary,
			NULL as mitm_skip_reason,
			t.method, t.url, t.status_code, t.duration_ms, t.conversation_id
			FROM http_transactions t
			WHERE %s`, where)
		unionParts = append(unionParts, q)
		queryArgs = append(queryArgs, args...)

		cq := fmt.Sprintf(`(SELECT COUNT(*) FROM http_transactions t WHERE %s)`, where)
		countParts = append(countParts, cq)
		countArgs = append(countArgs, args...)
	}

	if len(unionParts) == 0 {
		return nil, 0, nil
	}

	// Count
	countQuery := "SELECT " + strings.Join(countParts, " + ")
	var total int
	if err := db.ReadDB().QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count activity: %w", err)
	}

	// Main query
	query := strings.Join(unionParts, " UNION ALL ") + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	queryArgs = append(queryArgs, f.Limit, f.Offset)

	rows, err := db.ReadDB().Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query activity: %w", err)
	}
	defer rows.Close()

	var items []ActivityItem
	for rows.Next() {
		var item ActivityItem
		var ts string
		err := rows.Scan(
			&item.Kind, &item.ID, &ts, &item.ContainerName,
			&item.DestinationHost, &item.DestinationPort, &item.Result,
			&item.ResolvedHostname, &item.RuleID, &item.RuleSummary,
			&item.MitmSkipReason,
			&item.Method, &item.URL, &item.StatusCode, &item.DurationMs,
			&item.ConversationID,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan activity: %w", err)
		}
		item.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		if item.Timestamp.IsZero() {
			item.Timestamp, _ = time.Parse(time.RFC3339, ts)
		}
		items = append(items, item)
	}

	return items, total, nil
}

func buildActivityConnWhere(f ActivityFilter) (string, []any) {
	var conds []string
	var args []any

	if f.Container != "" {
		conds = append(conds, "l.container_name = ?")
		args = append(args, f.Container)
	}
	if f.Destination != "" {
		conds = append(conds, "(l.destination_host LIKE ? OR l.resolved_hostname LIKE ?)")
		args = append(args, "%"+f.Destination+"%", "%"+f.Destination+"%")
	}
	if f.Result != "" {
		conds = append(conds, "l.result = ?")
		args = append(args, f.Result)
	}
	if f.FromDate != nil {
		conds = append(conds, "l.timestamp >= ?")
		args = append(args, f.FromDate.UTC().Format("2006-01-02 15:04:05"))
	}
	if f.ToDate != nil {
		conds = append(conds, "l.timestamp <= ?")
		args = append(args, f.ToDate.UTC().Format("2006-01-02 15:04:05"))
	}

	if len(conds) == 0 {
		return "1=1", nil
	}
	return strings.Join(conds, " AND "), args
}

func buildActivityHTTPWhere(f ActivityFilter) (string, []any) {
	var conds []string
	var args []any

	if f.Container != "" {
		conds = append(conds, "t.container_name = ?")
		args = append(args, f.Container)
	}
	if f.Destination != "" {
		conds = append(conds, "(t.destination_host LIKE ? OR t.url LIKE ?)")
		args = append(args, "%"+f.Destination+"%", "%"+f.Destination+"%")
	}
	// Result filter doesn't apply to HTTP transactions (they use "auto" result)
	if f.FromDate != nil {
		conds = append(conds, "t.timestamp >= ?")
		args = append(args, f.FromDate.UTC().Format("2006-01-02 15:04:05"))
	}
	if f.ToDate != nil {
		conds = append(conds, "t.timestamp <= ?")
		args = append(args, f.ToDate.UTC().Format("2006-01-02 15:04:05"))
	}

	if len(conds) == 0 {
		return "1=1", nil
	}
	return strings.Join(conds, " AND "), args
}
