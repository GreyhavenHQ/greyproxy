package greyproxy

import (
	"encoding/json"
	"sync"
)

// Event types for pending request lifecycle.
const (
	EventPendingCreated   = "pending_request.created"
	EventPendingUpdated   = "pending_request.updated"
	EventPendingAllowed   = "pending_request.allowed"
	EventPendingDismissed = "pending_request.dismissed"
	EventWaitersChanged   = "waiters.changed"
	EventTransactionNew   = "transaction.new"

	// Conversation dissector events
	EventConversationUpdated = "conversation.updated"
)

// Event represents a broadcast event.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// WaiterChangedData is published with EventWaitersChanged when a
// pending request's waiter count changes.
type WaiterChangedData struct {
	ContainerName string `json:"container_name"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	PreviousCount int    `json:"previous_count"`
	CurrentCount  int    `json:"current_count"`
}

func (e Event) JSON() []byte {
	b, _ := json.Marshal(e)
	return b
}

// EventBus provides a channel-based pub/sub mechanism.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[chan Event]struct{}),
	}
}

// Subscribe returns a channel that will receive all published events.
// bufSize controls the channel buffer size.
func (eb *EventBus) Subscribe(bufSize int) chan Event {
	if bufSize < 1 {
		bufSize = 64
	}
	ch := make(chan Event, bufSize)
	eb.mu.Lock()
	eb.subscribers[ch] = struct{}{}
	eb.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel and closes it.
func (eb *EventBus) Unsubscribe(ch chan Event) {
	eb.mu.Lock()
	delete(eb.subscribers, ch)
	eb.mu.Unlock()
	close(ch)
}

// Publish sends an event to all subscribers (non-blocking).
func (eb *EventBus) Publish(evt Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for ch := range eb.subscribers {
		select {
		case ch <- evt:
		default:
			// Drop if subscriber is slow
		}
	}
}
