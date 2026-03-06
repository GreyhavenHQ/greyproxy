package greyproxy

import (
	"fmt"
	"sync"
)

// WaiterTracker tracks how many connections are currently waiting (held open)
// for each pending request destination. Counters are managed explicitly via
// Add (increment) and the returned cleanup function (decrement).
type WaiterTracker struct {
	mu      sync.Mutex
	counts  map[string]int
	bus     *EventBus
}

func NewWaiterTracker(bus *EventBus) *WaiterTracker {
	return &WaiterTracker{
		counts: make(map[string]int),
		bus:    bus,
	}
}

func waiterKey(containerName, host string, port int) string {
	return fmt.Sprintf("%s|%s|%d", containerName, host, port)
}

// Add increments the waiter count for the given destination and publishes
// an EventWaitersChanged event. Returns a function to call when the waiter
// is done (defer-friendly); calling it decrements the count and publishes
// another event.
func (w *WaiterTracker) Add(containerName, host string, port int) func() {
	key := waiterKey(containerName, host, port)

	w.mu.Lock()
	w.counts[key]++
	w.mu.Unlock()

	w.publishChanged()

	var once sync.Once
	return func() {
		once.Do(func() {
			w.mu.Lock()
			w.counts[key]--
			if w.counts[key] <= 0 {
				delete(w.counts, key)
			}
			w.mu.Unlock()

			w.publishChanged()
		})
	}
}

// Get returns the number of connections currently waiting for the given destination.
func (w *WaiterTracker) Get(containerName, host string, port int) int {
	key := waiterKey(containerName, host, port)

	w.mu.Lock()
	defer w.mu.Unlock()

	return w.counts[key]
}

func (w *WaiterTracker) publishChanged() {
	if w.bus != nil {
		w.bus.Publish(Event{Type: EventWaitersChanged})
	}
}
