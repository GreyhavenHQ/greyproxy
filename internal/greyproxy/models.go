package greyproxy

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

type Rule struct {
	ID                 int64          `json:"id"`
	ContainerPattern   string         `json:"container_pattern"`
	DestinationPattern string         `json:"destination_pattern"`
	PortPattern        string         `json:"port_pattern"`
	RuleType           string         `json:"rule_type"`
	Action             string         `json:"action"`
	CreatedAt          time.Time      `json:"created_at"`
	ExpiresAt          sql.NullTime   `json:"expires_at"`
	LastUsedAt         sql.NullTime   `json:"last_used_at"`
	CreatedBy          string         `json:"created_by"`
	Notes              sql.NullString `json:"notes"`
}

type RuleJSON struct {
	ID                 int64   `json:"id"`
	ContainerPattern   string  `json:"container_pattern"`
	DestinationPattern string  `json:"destination_pattern"`
	PortPattern        string  `json:"port_pattern"`
	RuleType           string  `json:"rule_type"`
	Action             string  `json:"action"`
	CreatedAt          string  `json:"created_at"`
	ExpiresAt          *string `json:"expires_at"`
	LastUsedAt         *string `json:"last_used_at"`
	CreatedBy          string  `json:"created_by"`
	Notes              *string `json:"notes"`
	IsActive           bool    `json:"is_active"`
}

func (r *Rule) ToJSON() RuleJSON {
	j := RuleJSON{
		ID:                 r.ID,
		ContainerPattern:   r.ContainerPattern,
		DestinationPattern: r.DestinationPattern,
		PortPattern:        r.PortPattern,
		RuleType:           r.RuleType,
		Action:             r.Action,
		CreatedAt:          r.CreatedAt.UTC().Format(time.RFC3339),
		CreatedBy:          r.CreatedBy,
		IsActive:           !r.ExpiresAt.Valid || r.ExpiresAt.Time.After(time.Now()),
	}
	if r.ExpiresAt.Valid {
		s := r.ExpiresAt.Time.UTC().Format(time.RFC3339)
		j.ExpiresAt = &s
	}
	if r.LastUsedAt.Valid {
		s := r.LastUsedAt.Time.UTC().Format(time.RFC3339)
		j.LastUsedAt = &s
	}
	if r.Notes.Valid {
		j.Notes = &r.Notes.String
	}
	return j
}

type PendingRequest struct {
	ID               int64          `json:"id"`
	ContainerName    string         `json:"container_name"`
	ContainerID      string         `json:"container_id"`
	DestinationHost  string         `json:"destination_host"`
	DestinationPort  int            `json:"destination_port"`
	ResolvedHostname sql.NullString `json:"resolved_hostname"`
	FirstSeen        time.Time      `json:"first_seen"`
	LastSeen         time.Time      `json:"last_seen"`
	AttemptCount     int            `json:"attempt_count"`
	WaitingCount     int            `json:"-"` // In-memory only: connections currently held open
}

type PendingRequestJSON struct {
	ID               int64   `json:"id"`
	ContainerName    string  `json:"container_name"`
	ContainerID      string  `json:"container_id"`
	DestinationHost  string  `json:"destination_host"`
	DestinationPort  int     `json:"destination_port"`
	ResolvedHostname *string `json:"resolved_hostname"`
	FirstSeen        string  `json:"first_seen"`
	LastSeen         string  `json:"last_seen"`
	AttemptCount     int     `json:"attempt_count"`
}

func (p *PendingRequest) ToJSON() PendingRequestJSON {
	j := PendingRequestJSON{
		ID:              p.ID,
		ContainerName:   p.ContainerName,
		ContainerID:     p.ContainerID,
		DestinationHost: p.DestinationHost,
		DestinationPort: p.DestinationPort,
		FirstSeen:       p.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:        p.LastSeen.UTC().Format(time.RFC3339),
		AttemptCount:    p.AttemptCount,
	}
	if p.ResolvedHostname.Valid {
		j.ResolvedHostname = &p.ResolvedHostname.String
	}
	return j
}

// DisplayHost returns the best hostname to show (resolved hostname or raw IP).
func (p *PendingRequest) DisplayHost() string {
	if p.ResolvedHostname.Valid && p.ResolvedHostname.String != "" {
		return p.ResolvedHostname.String
	}
	return p.DestinationHost
}

type RequestLog struct {
	ID               int64          `json:"id"`
	Timestamp        time.Time      `json:"timestamp"`
	ContainerName    string         `json:"container_name"`
	ContainerID      sql.NullString `json:"container_id"`
	DestinationHost  string         `json:"destination_host"`
	DestinationPort  sql.NullInt64  `json:"destination_port"`
	ResolvedHostname sql.NullString `json:"resolved_hostname"`
	Method           sql.NullString `json:"method"`
	Result           string         `json:"result"`
	RuleID           sql.NullInt64  `json:"rule_id"`
	ResponseTimeMs   sql.NullInt64  `json:"response_time_ms"`
	MitmSkipReason   sql.NullString `json:"mitm_skip_reason"`
	RuleSummary      sql.NullString `json:"-"` // Computed at query time via JOIN
}

type RequestLogJSON struct {
	ID               int64   `json:"id"`
	Timestamp        string  `json:"timestamp"`
	ContainerName    string  `json:"container_name"`
	ContainerID      *string `json:"container_id"`
	DestinationHost  string  `json:"destination_host"`
	DestinationPort  *int64  `json:"destination_port"`
	ResolvedHostname *string `json:"resolved_hostname"`
	Method           *string `json:"method"`
	Result           string  `json:"result"`
	RuleID           *int64  `json:"rule_id"`
	ResponseTimeMs   *int64  `json:"response_time_ms"`
	RuleSummary      *string `json:"rule_summary,omitempty"`
}

func (l *RequestLog) ToJSON() RequestLogJSON {
	j := RequestLogJSON{
		ID:              l.ID,
		Timestamp:       l.Timestamp.UTC().Format(time.RFC3339),
		ContainerName:   l.ContainerName,
		DestinationHost: l.DestinationHost,
		Result:          l.Result,
	}
	if l.ContainerID.Valid {
		j.ContainerID = &l.ContainerID.String
	}
	if l.DestinationPort.Valid {
		j.DestinationPort = &l.DestinationPort.Int64
	}
	if l.ResolvedHostname.Valid {
		j.ResolvedHostname = &l.ResolvedHostname.String
	}
	if l.Method.Valid {
		j.Method = &l.Method.String
	}
	if l.RuleID.Valid {
		j.RuleID = &l.RuleID.Int64
	}
	if l.ResponseTimeMs.Valid {
		j.ResponseTimeMs = &l.ResponseTimeMs.Int64
	}
	if l.RuleSummary.Valid {
		j.RuleSummary = &l.RuleSummary.String
	}
	return j
}

// DisplayHost returns the best hostname to show.
func (l *RequestLog) DisplayHost() string {
	if l.ResolvedHostname.Valid && l.ResolvedHostname.String != "" {
		return l.ResolvedHostname.String
	}
	return l.DestinationHost
}

// HttpTransaction represents a MITM-captured HTTP request/response pair.
type HttpTransaction struct {
	ID                  int64          `json:"id"`
	Timestamp           time.Time      `json:"timestamp"`
	ContainerName       string         `json:"container_name"`
	DestinationHost     string         `json:"destination_host"`
	DestinationPort     int            `json:"destination_port"`
	Method              string         `json:"method"`
	URL                 string         `json:"url"`
	RequestHeaders      sql.NullString `json:"-"`
	RequestBody         []byte         `json:"-"`
	RequestBodySize     sql.NullInt64  `json:"-"`
	RequestContentType  sql.NullString `json:"-"`
	StatusCode          sql.NullInt64  `json:"status_code"`
	ResponseHeaders     sql.NullString `json:"-"`
	ResponseBody        []byte         `json:"-"`
	ResponseBodySize    sql.NullInt64  `json:"-"`
	ResponseContentType sql.NullString `json:"-"`
	DurationMs          sql.NullInt64  `json:"duration_ms"`
	RuleID              sql.NullInt64  `json:"rule_id"`
	Result              string         `json:"result"`
}

type HttpTransactionJSON struct {
	ID                  int64   `json:"id"`
	Timestamp           string  `json:"timestamp"`
	ContainerName       string  `json:"container_name"`
	DestinationHost     string  `json:"destination_host"`
	DestinationPort     int     `json:"destination_port"`
	Method              string  `json:"method"`
	URL                 string  `json:"url"`
	RequestHeaders      any     `json:"request_headers,omitempty"`
	RequestBody         *string `json:"request_body,omitempty"`
	RequestBodySize     *int64  `json:"request_body_size,omitempty"`
	RequestContentType  *string `json:"request_content_type,omitempty"`
	StatusCode          *int64  `json:"status_code,omitempty"`
	ResponseHeaders     any     `json:"response_headers,omitempty"`
	ResponseBody        *string `json:"response_body,omitempty"`
	ResponseBodySize    *int64  `json:"response_body_size,omitempty"`
	ResponseContentType *string `json:"response_content_type,omitempty"`
	DurationMs          *int64  `json:"duration_ms,omitempty"`
	RuleID              *int64  `json:"rule_id,omitempty"`
	Result              string  `json:"result"`
}

func (t *HttpTransaction) ToJSON(includeBody bool) HttpTransactionJSON {
	j := HttpTransactionJSON{
		ID:              t.ID,
		Timestamp:       t.Timestamp.UTC().Format(time.RFC3339),
		ContainerName:   t.ContainerName,
		DestinationHost: t.DestinationHost,
		DestinationPort: t.DestinationPort,
		Method:          t.Method,
		URL:             t.URL,
		Result:          t.Result,
	}
	if t.RequestHeaders.Valid {
		var h map[string]any
		if json.Unmarshal([]byte(t.RequestHeaders.String), &h) == nil {
			j.RequestHeaders = h
		}
	}
	if t.RequestBodySize.Valid {
		j.RequestBodySize = &t.RequestBodySize.Int64
	}
	if t.RequestContentType.Valid {
		j.RequestContentType = &t.RequestContentType.String
	}
	if t.StatusCode.Valid {
		j.StatusCode = &t.StatusCode.Int64
	}
	if t.ResponseHeaders.Valid {
		var h map[string]any
		if json.Unmarshal([]byte(t.ResponseHeaders.String), &h) == nil {
			j.ResponseHeaders = h
		}
	}
	if t.ResponseBodySize.Valid {
		j.ResponseBodySize = &t.ResponseBodySize.Int64
	}
	if t.ResponseContentType.Valid {
		j.ResponseContentType = &t.ResponseContentType.String
	}
	if t.DurationMs.Valid {
		j.DurationMs = &t.DurationMs.Int64
	}
	if t.RuleID.Valid {
		j.RuleID = &t.RuleID.Int64
	}
	if includeBody {
		if len(t.RequestBody) > 0 {
			s := string(t.RequestBody)
			j.RequestBody = &s
		}
		if len(t.ResponseBody) > 0 {
			s := string(t.ResponseBody)
			j.ResponseBody = &s
		}
	}
	return j
}

// HttpTransactionCreateInput holds the data needed to create a transaction record.
type HttpTransactionCreateInput struct {
	ContainerName   string
	DestinationHost string
	DestinationPort int
	Method          string
	URL             string
	RequestHeaders  http.Header
	RequestBody     []byte
	RequestContentType string
	StatusCode      int
	ResponseHeaders http.Header
	ResponseBody    []byte
	ResponseContentType string
	DurationMs      int64
	RuleID          *int64
	Result          string
}

// DashboardStats holds aggregated data for the dashboard.
type DashboardStats struct {
	Period        Period                   `json:"period"`
	TotalRequests int                      `json:"total_requests"`
	Allowed       int                      `json:"allowed"`
	Blocked       int                      `json:"blocked"`
	AllowRate     float64                  `json:"allow_rate"`
	ByContainer   []ContainerStatsItem     `json:"by_container"`
	TopBlocked    []BlockedDestinationItem `json:"top_blocked"`
	Timeline      []TimelinePoint          `json:"timeline"`
	Recent        []RequestLogJSON         `json:"recent"`
}

type Period struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type ContainerStatsItem struct {
	Name       string  `json:"name"`
	Total      int     `json:"total"`
	Allowed    int     `json:"allowed"`
	Blocked    int     `json:"blocked"`
	Percentage float64 `json:"percentage"`
}

type BlockedDestinationItem struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	ResolvedHostname string   `json:"resolved_hostname"`
	Count            int      `json:"count"`
	Containers       []string `json:"containers"`
}

type TimelinePoint struct {
	Timestamp string `json:"timestamp"`
	Allowed   int    `json:"allowed"`
	Blocked   int    `json:"blocked"`
}
