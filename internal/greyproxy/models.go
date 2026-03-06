package greyproxy

import (
	"database/sql"
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
