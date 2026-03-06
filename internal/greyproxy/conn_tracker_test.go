package greyproxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnTrackerRegisterAndCancel(t *testing.T) {
	ct := NewConnTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ct.Register(42, cancel)

	// Context should still be active
	select {
	case <-ctx.Done():
		t.Fatal("context should not be cancelled yet")
	default:
	}

	// Cancel all connections for rule 42
	ct.CancelByRule(42)

	select {
	case <-ctx.Done():
		// OK
	case <-time.After(time.Second):
		t.Fatal("context should have been cancelled")
	}
}

func TestConnTrackerMultipleConnsPerRule(t *testing.T) {
	ct := NewConnTracker()

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	ct.Register(42, cancel1)
	ct.Register(42, cancel2)

	ct.CancelByRule(42)

	select {
	case <-ctx1.Done():
	case <-time.After(time.Second):
		t.Fatal("ctx1 should have been cancelled")
	}

	select {
	case <-ctx2.Done():
	case <-time.After(time.Second):
		t.Fatal("ctx2 should have been cancelled")
	}
}

func TestConnTrackerUnregister(t *testing.T) {
	ct := NewConnTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connID := ct.Register(42, cancel)
	ct.Unregister(42, connID)

	// After unregister, CancelByRule should have no effect
	ct.CancelByRule(42)

	select {
	case <-ctx.Done():
		t.Fatal("context should NOT have been cancelled after unregister")
	default:
		// OK
	}
}

func TestConnTrackerCancelOnlyAffectsTargetRule(t *testing.T) {
	ct := NewConnTracker()

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	ct.Register(1, cancel1)
	ct.Register(2, cancel2)

	// Cancel only rule 1
	ct.CancelByRule(1)

	select {
	case <-ctx1.Done():
	case <-time.After(time.Second):
		t.Fatal("ctx1 should have been cancelled")
	}

	select {
	case <-ctx2.Done():
		t.Fatal("ctx2 should NOT have been cancelled")
	default:
		// OK
	}
}

func TestConnTrackerCancelByRuleIdempotent(t *testing.T) {
	ct := NewConnTracker()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	ct.Register(42, cancel)

	// Calling CancelByRule twice should not panic
	ct.CancelByRule(42)
	ct.CancelByRule(42)
}

func TestConnTrackerUnregisterUnknown(t *testing.T) {
	ct := NewConnTracker()

	// Unregistering a non-existent rule/conn should not panic
	ct.Unregister(999, 12345)
}

func TestConnTrackerConcurrent(t *testing.T) {
	ct := NewConnTracker()

	var wg sync.WaitGroup
	var cancelled atomic.Int64

	// Register 100 connections across 10 rules
	for rule := int64(0); rule < 10; rule++ {
		for i := 0; i < 10; i++ {
			rule := rule
			ctx, cancel := context.WithCancel(context.Background())
			connID := ct.Register(rule, cancel)

			wg.Add(1)
			go func() {
				defer wg.Done()
				<-ctx.Done()
				cancelled.Add(1)
				ct.Unregister(rule, connID)
			}()
		}
	}

	// Cancel all rules concurrently
	var cancelWg sync.WaitGroup
	for rule := int64(0); rule < 10; rule++ {
		rule := rule
		cancelWg.Add(1)
		go func() {
			defer cancelWg.Done()
			ct.CancelByRule(rule)
		}()
	}
	cancelWg.Wait()
	wg.Wait()

	if got := cancelled.Load(); got != 100 {
		t.Errorf("expected 100 cancelled connections, got %d", got)
	}
}
