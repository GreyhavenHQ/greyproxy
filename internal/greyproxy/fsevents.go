package greyproxy

import (
	"sync"
)

// Event type for filesystem activity received from greywall.
const EventSessionFsEvents = "session.fs_events"

// EventSessionFsAlert fires when a heartbeat delivers at least one event
// classified warn or critical. Dashboards use this to raise toasts /
// notifications even when the user is not actively viewing the session.
const EventSessionFsAlert = "session.fs_alert"

// FsEvent mirrors the greywall sandbox.FsEvent wire format. It describes a
// single filesystem operation observed inside a sandboxed agent and is
// shipped to greyproxy in the heartbeat body. Severity, Tags, and
// TransactionID are added server-side on ingest; greywall does not send
// them. TransactionID links the event back to the last completed
// http_transactions row in the same session, so the dashboard can render
// fs activity grouped by API round trip.
type FsEvent struct {
	Ts            string   `json:"ts"`
	Op            string   `json:"op"`
	Path          string   `json:"path"`
	Path2         string   `json:"path2,omitempty"`
	PID           int      `json:"pid,omitempty"`
	Errno         int      `json:"errno,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	TransactionID int64    `json:"transaction_id,omitempty"`
}

// FsEventsPayload is the optional JSON body of a heartbeat request.
type FsEventsPayload struct {
	Events  []FsEvent `json:"events,omitempty"`
	Dropped uint64    `json:"dropped,omitempty"`
}

// FsEventsBatch is published on the event bus when a heartbeat delivers
// new filesystem events. WebSocket clients can subscribe to render live
// activity in the dashboard.
type FsEventsBatch struct {
	SessionID string    `json:"session_id"`
	Events    []FsEvent `json:"events"`
	Dropped   uint64    `json:"dropped,omitempty"`
}

// FsEventsAlert is the bus payload published when one or more events in a
// batch were classified warn or critical. It carries only the alarming
// subset so subscribers don't have to filter.
type FsEventsAlert struct {
	SessionID string    `json:"session_id"`
	Events    []FsEvent `json:"events"`
	MaxSeverity string  `json:"max_severity"`
}

// FsEventsSnapshot is the wire form returned by GET /api/sessions/:id/fsevents.
type FsEventsSnapshot struct {
	SessionID    string    `json:"session_id"`
	Events       []FsEvent `json:"events"`
	Dropped      uint64    `json:"dropped"`        // cumulative dropped events for this session
	Truncated    bool      `json:"truncated"`      // true when the per-session buffer has wrapped at least once
	TotalEvents  uint64    `json:"total_events"`   // cumulative events received for this session
	BufferLimit  int       `json:"buffer_limit"`   // ring capacity
	BufferLength int       `json:"buffer_length"`  // current count of live entries
	// Cumulative counts of severity-tagged events seen since session start.
	// "Critical" includes only events whose severity is critical; "warn"
	// covers warn only. Both reset on session delete.
	CriticalCount uint64 `json:"critical_count"`
	WarnCount     uint64 `json:"warn_count"`
}

// DefaultFsEventBufferCap is the per-session ring buffer capacity. Chosen
// large enough to span ~10 heartbeat ticks of high-frequency filesystem
// activity without forcing the dashboard to poll on a tight loop.
const DefaultFsEventBufferCap = 1024

// fsRing is a bounded ring buffer of FsEvents for a single session.
type fsRing struct {
	buf       []FsEvent
	head      int
	size      int
	cap       int
	dropped   uint64 // cumulative
	total     uint64 // cumulative
	critical  uint64 // cumulative count of severity=critical events
	warn      uint64 // cumulative count of severity=warn events
	truncated bool
}

func newFsRing(capacity int) *fsRing {
	if capacity <= 0 {
		capacity = 1
	}
	return &fsRing{
		buf: make([]FsEvent, capacity),
		cap: capacity,
	}
}

func (r *fsRing) push(e FsEvent) {
	r.total++
	if r.size < r.cap {
		r.buf[(r.head+r.size)%r.cap] = e
		r.size++
		return
	}
	r.buf[r.head] = e
	r.head = (r.head + 1) % r.cap
	r.truncated = true
}

func (r *fsRing) snapshot() []FsEvent {
	if r.size == 0 {
		return nil
	}
	out := make([]FsEvent, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.buf[(r.head+i)%r.cap]
	}
	return out
}

// FsCorrelator looks up the most recent http_transactions row that
// completed at or before the given event timestamp for the session.
// Returns 0 when no transaction has completed yet (event happened before
// the wrapped app's first API call).
type FsCorrelator func(sessionID, eventTs string) int64

// FsEventStore holds per-session ring buffers. Safe for concurrent use.
type FsEventStore struct {
	mu         sync.RWMutex
	rings      map[string]*fsRing
	cap        int
	classifier *FsEventClassifier // optional; nil disables classification
	correlator FsCorrelator       // optional; nil disables transaction linking
}

// NewFsEventStore creates a store with the given per-session ring capacity.
// Pass 0 to use DefaultFsEventBufferCap.
func NewFsEventStore(perSessionCap int) *FsEventStore {
	if perSessionCap <= 0 {
		perSessionCap = DefaultFsEventBufferCap
	}
	return &FsEventStore{
		rings: make(map[string]*fsRing),
		cap:   perSessionCap,
	}
}

// SetClassifier installs a classifier so every ingested event is tagged
// with severity + tags before being stored. Pass nil to disable.
func (s *FsEventStore) SetClassifier(c *FsEventClassifier) {
	s.mu.Lock()
	s.classifier = c
	s.mu.Unlock()
}

// SetCorrelator installs a function that maps each ingested event to
// the http_transactions row that immediately preceded it. The returned
// id is stamped onto the event's TransactionID field before it lands in
// the ring buffer, so dashboard and WebSocket subscribers see the link
// in the same place they read every other field. Pass nil to disable.
func (s *FsEventStore) SetCorrelator(fn FsCorrelator) {
	s.mu.Lock()
	s.correlator = fn
	s.mu.Unlock()
}

// FsEventIngestResult reports what happened on an ingest call so callers can
// decide whether to publish a session.fs_alert. Alerting only makes sense
// when at least one event was actually classified warn or critical.
type FsEventIngestResult struct {
	// Stored is the ingested events after classification — same slice
	// length as the input but with Severity/Tags filled in.
	Stored []FsEvent
	// AlertEvents is the subset of Stored whose severity is warn or
	// critical. Empty when nothing alarming was observed.
	AlertEvents []FsEvent
	// MaxSeverity is the highest severity in this batch, or "info" if
	// the batch was clean.
	MaxSeverity string
}

// Ingest appends events for sessionID, classifies them, and records the
// dropped delta reported by greywall (events the tracer threw away before
// they reached greyproxy). The returned FsEventIngestResult lets the caller
// decide whether to surface an alert.
func (s *FsEventStore) Ingest(sessionID string, events []FsEvent, dropped uint64) FsEventIngestResult {
	res := FsEventIngestResult{MaxSeverity: SeverityInfo}
	if sessionID == "" || (len(events) == 0 && dropped == 0) {
		return res
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.rings[sessionID]
	if !ok {
		r = newFsRing(s.cap)
		s.rings[sessionID] = r
	}

	classified := make([]FsEvent, 0, len(events))
	for _, e := range events {
		if s.classifier != nil {
			c := s.classifier.Classify(e)
			e.Severity = c.Severity
			e.Tags = c.Tags
		} else if e.Severity == "" {
			e.Severity = SeverityInfo
		}
		if s.correlator != nil && e.TransactionID == 0 {
			e.TransactionID = s.correlator(sessionID, e.Ts)
		}
		switch e.Severity {
		case SeverityCritical:
			r.critical++
			res.AlertEvents = append(res.AlertEvents, e)
		case SeverityWarn:
			r.warn++
			res.AlertEvents = append(res.AlertEvents, e)
		}
		res.MaxSeverity = maxSeverity(res.MaxSeverity, e.Severity)
		r.push(e)
		classified = append(classified, e)
	}
	r.dropped += dropped
	res.Stored = classified
	return res
}

// Snapshot returns a FIFO copy of the session's buffer plus cumulative
// counters. Returns a zero-value snapshot when the session is unknown so
// the API can respond uniformly.
func (s *FsEventStore) Snapshot(sessionID string) FsEventsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.rings[sessionID]
	if !ok {
		return FsEventsSnapshot{
			SessionID:   sessionID,
			BufferLimit: s.cap,
		}
	}
	return FsEventsSnapshot{
		SessionID:     sessionID,
		Events:        r.snapshot(),
		Dropped:       r.dropped,
		Truncated:     r.truncated,
		TotalEvents:   r.total,
		BufferLimit:   r.cap,
		BufferLength:  r.size,
		CriticalCount: r.critical,
		WarnCount:     r.warn,
	}
}

// Forget releases the ring buffer for a session (called on session delete /
// expiry so memory does not grow unbounded across long-lived proxy runs).
func (s *FsEventStore) Forget(sessionID string) {
	s.mu.Lock()
	delete(s.rings, sessionID)
	s.mu.Unlock()
}
