package greyproxy

import (
	"sync"
)

// Event type for filesystem activity received from greywall.
const EventSessionFsEvents = "session.fs_events"

// FsEvent mirrors the greywall sandbox.FsEvent wire format. It describes a
// single filesystem operation observed inside a sandboxed agent and is
// shipped to greyproxy in the heartbeat body.
type FsEvent struct {
	Ts    string `json:"ts"`
	Op    string `json:"op"`
	Path  string `json:"path"`
	Path2 string `json:"path2,omitempty"`
	PID   int    `json:"pid,omitempty"`
	Errno int    `json:"errno,omitempty"`
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

// FsEventsSnapshot is the wire form returned by GET /api/sessions/:id/fsevents.
type FsEventsSnapshot struct {
	SessionID    string    `json:"session_id"`
	Events       []FsEvent `json:"events"`
	Dropped      uint64    `json:"dropped"`        // cumulative dropped events for this session
	Truncated    bool      `json:"truncated"`      // true when the per-session buffer has wrapped at least once
	TotalEvents  uint64    `json:"total_events"`   // cumulative events received for this session
	BufferLimit  int       `json:"buffer_limit"`   // ring capacity
	BufferLength int       `json:"buffer_length"`  // current count of live entries
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

// FsEventStore holds per-session ring buffers. Safe for concurrent use.
type FsEventStore struct {
	mu      sync.RWMutex
	rings   map[string]*fsRing
	cap     int
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

// Ingest appends events for sessionID and records the dropped delta reported
// by greywall (events the tracer threw away before they reached greyproxy).
func (s *FsEventStore) Ingest(sessionID string, events []FsEvent, dropped uint64) {
	if sessionID == "" || (len(events) == 0 && dropped == 0) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.rings[sessionID]
	if !ok {
		r = newFsRing(s.cap)
		s.rings[sessionID] = r
	}
	for _, e := range events {
		r.push(e)
	}
	r.dropped += dropped
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
		SessionID:    sessionID,
		Events:       r.snapshot(),
		Dropped:      r.dropped,
		Truncated:    r.truncated,
		TotalEvents:  r.total,
		BufferLimit:  r.cap,
		BufferLength: r.size,
	}
}

// Forget releases the ring buffer for a session (called on session delete /
// expiry so memory does not grow unbounded across long-lived proxy runs).
func (s *FsEventStore) Forget(sessionID string) {
	s.mu.Lock()
	delete(s.rings, sessionID)
	s.mu.Unlock()
}
