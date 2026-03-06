package greyproxy

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

var nextConnID atomic.Uint64

// ConnTracker tracks active proxy connections by the rule ID that authorized
// them. When a rule is deleted or changed to deny, all connections that were
// allowed by that rule can be cancelled immediately.
type ConnTracker struct {
	mu    sync.Mutex
	conns map[int64]map[uint64]context.CancelFunc
}

func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		conns: make(map[int64]map[uint64]context.CancelFunc),
	}
}

// Register associates a cancel function with a rule ID and returns an ID
// that can be used to unregister later.
func (ct *ConnTracker) Register(ruleID int64, cancel context.CancelFunc) uint64 {
	id := nextConnID.Add(1)

	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.conns[ruleID] == nil {
		ct.conns[ruleID] = make(map[uint64]context.CancelFunc)
	}
	ct.conns[ruleID][id] = cancel

	slog.Info("conn_tracker: registered", "conn_id", id, "rule_id", ruleID, "total_for_rule", len(ct.conns[ruleID]))
	return id
}

// Unregister removes a previously registered connection.
// Called when a connection ends naturally.
func (ct *ConnTracker) Unregister(ruleID int64, id uint64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if m, ok := ct.conns[ruleID]; ok {
		delete(m, id)
		if len(m) == 0 {
			delete(ct.conns, ruleID)
		}
		slog.Info("conn_tracker: unregistered", "conn_id", id, "rule_id", ruleID)
	}
}

// CancelByRule cancels all active connections that were authorized by the
// given rule ID and removes them from tracking.
func (ct *ConnTracker) CancelByRule(ruleID int64) {
	ct.mu.Lock()
	cancels := ct.conns[ruleID]
	delete(ct.conns, ruleID)
	ct.mu.Unlock()

	if len(cancels) == 0 {
		slog.Info("conn_tracker: cancel by rule, no active connections", "rule_id", ruleID)
		return
	}

	slog.Info("conn_tracker: cancel by rule, killing connections", "rule_id", ruleID, "count", len(cancels))
	for id, cancel := range cancels {
		slog.Info("conn_tracker: cancelling conn", "conn_id", id, "rule_id", ruleID)
		cancel()
	}
}
