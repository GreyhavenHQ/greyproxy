package greyproxy

import (
	"sync"
	"time"
)

const (
	SilentModeAllow = "allow"
	SilentModeDeny  = "deny"
)

// AllowAllStatus is the current state of silent mode.
type AllowAllStatus struct {
	Active           bool       `json:"active"`
	Mode             string     `json:"mode,omitempty"`              // "allow" or "deny"
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`        // nil means "until restart"
	RemainingSeconds *int64     `json:"remaining_seconds,omitempty"` // nil means "until restart"
}

// AllowAllManager implements Little Snitch-style silent mode: when active it
// short-circuits ACL evaluation for every connection.
//
// Two modes are supported:
//   - "allow": permit all connections without asking (no pending requests created)
//   - "deny":  block all connections without asking (no pending requests created)
//
// State is intentionally not persisted; a restart always reverts to normal mode.
type AllowAllManager struct {
	mu     sync.RWMutex
	active bool
	mode   string    // SilentModeAllow or SilentModeDeny
	expiry time.Time // zero value means "until restart"
	timer  *time.Timer
	bus    *EventBus
}

func NewAllowAllManager(bus *EventBus) *AllowAllManager {
	return &AllowAllManager{bus: bus}
}

// Enable activates silent mode. duration=0 means "until restart" (no timer set).
// Calling Enable while already active resets the timer and/or mode.
func (m *AllowAllManager) Enable(duration time.Duration, mode string) {
	m.mu.Lock()

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}

	m.active = true
	m.mode = mode

	var expPtr *time.Time
	var remPtr *int64

	if duration > 0 {
		exp := time.Now().Add(duration)
		m.expiry = exp
		expPtr = &exp
		rem := int64(duration.Seconds())
		remPtr = &rem

		m.timer = time.AfterFunc(duration, func() {
			m.mu.Lock()
			m.active = false
			m.timer = nil
			m.mu.Unlock()

			m.bus.Publish(Event{
				Type: EventAllowAllChanged,
				Data: AllowAllStatus{Active: false},
			})
		})
	} else {
		m.expiry = time.Time{} // zero = until restart
	}

	m.mu.Unlock()

	m.bus.Publish(Event{
		Type: EventAllowAllChanged,
		Data: AllowAllStatus{
			Active:           true,
			Mode:             mode,
			ExpiresAt:        expPtr,
			RemainingSeconds: remPtr,
		},
	})
}

// Disable cancels silent mode immediately.
func (m *AllowAllManager) Disable() {
	m.mu.Lock()

	if !m.active {
		m.mu.Unlock()
		return
	}

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.active = false

	m.mu.Unlock()

	m.bus.Publish(Event{
		Type: EventAllowAllChanged,
		Data: AllowAllStatus{Active: false},
	})
}

// IsActive returns true if silent mode is currently active.
// Called on every proxied connection; optimized for the common (inactive) case.
func (m *AllowAllManager) IsActive() bool {
	m.mu.RLock()
	active := m.active
	m.mu.RUnlock()
	return active
}

// Mode returns the current mode ("allow" or "deny").
func (m *AllowAllManager) Mode() string {
	m.mu.RLock()
	mode := m.mode
	m.mu.RUnlock()
	return mode
}

// Status returns the current state for API responses.
func (m *AllowAllManager) Status() AllowAllStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.active {
		return AllowAllStatus{Active: false}
	}

	s := AllowAllStatus{Active: true, Mode: m.mode}

	if !m.expiry.IsZero() {
		exp := m.expiry
		s.ExpiresAt = &exp
		rem := int64(time.Until(m.expiry).Seconds())
		if rem < 0 {
			rem = 0
		}
		s.RemainingSeconds = &rem
	}
	// nil ExpiresAt + nil RemainingSeconds = "until restart"

	return s
}
