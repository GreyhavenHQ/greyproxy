package middleware

import (
	"net/http"
	"sync"
	"time"
)

// PendingEvent is one row-worthy middleware decision captured during a
// cascade step, waiting for the http_transactions row to be created so it
// can be attached via transaction_id.
type PendingEvent struct {
	Sequence       int
	MiddlewareName string // friendly name from hello, may be empty
	MiddlewareURL  string
	Hook           string // "http-request" | "http-response" | "mitm-request" | "mitm-response"
	Action         string // "deny" | "block" | "rewrite" | "tagged-allow" | "tagged-passthrough"
	StatusCode     int
	HeadersChanged []string
	BodyRewritten  bool
	Tags           map[string]any
	DurationMs     int64
	CreatedAt      time.Time
}

// pendingBucket holds the accumulated events for one in-flight request plus
// a deadline after which a sweep reaps it if no drain ever happened.
type pendingBucket struct {
	events  []PendingEvent
	expires time.Time
}

var (
	pendingMu      sync.Mutex
	pending        = make(map[string]*pendingBucket)
	pendingTTL     = 60 * time.Second
	pendingSweepWg sync.Once
)

// StashEvent appends a pending event for a given request ID. Callers should
// produce a row only for decisions that are actually row-worthy per the
// write rule ("mutating action OR emitted tags").
func StashEvent(requestID string, ev PendingEvent) {
	if requestID == "" {
		return
	}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	b, ok := pending[requestID]
	if !ok {
		b = &pendingBucket{expires: time.Now().Add(pendingTTL)}
		pending[requestID] = b
	}
	b.events = append(b.events, ev)
	pendingSweepWg.Do(startPendingSweep)
}

// DrainEvents returns all pending events for the request ID and removes
// the bucket. Returns nil if no events were stashed.
func DrainEvents(requestID string) []PendingEvent {
	if requestID == "" {
		return nil
	}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	b, ok := pending[requestID]
	if !ok {
		return nil
	}
	delete(pending, requestID)
	return b.events
}

// DiffHeaderNames returns the set of header names that differ between before
// and after. Only names are returned (no values) to avoid storing PII.
func DiffHeaderNames(before, after http.Header) []string {
	if len(before) == 0 && len(after) == 0 {
		return nil
	}
	changed := map[string]struct{}{}
	for k, v := range after {
		old, ok := before[k]
		if !ok || !equalStringSlices(old, v) {
			changed[k] = struct{}{}
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			changed[k] = struct{}{}
		}
	}
	if len(changed) == 0 {
		return nil
	}
	out := make([]string, 0, len(changed))
	for k := range changed {
		out = append(out, k)
	}
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func startPendingSweep() {
	go func() {
		ticker := time.NewTicker(pendingTTL)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			pendingMu.Lock()
			for id, b := range pending {
				if now.After(b.expires) {
					delete(pending, id)
				}
			}
			pendingMu.Unlock()
		}
	}()
}
