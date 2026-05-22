package greyproxy

import (
	"testing"
)

func TestFsEventStore_IngestAndSnapshot(t *testing.T) {
	s := NewFsEventStore(4)

	s.Ingest("sess-1", []FsEvent{
		{Ts: "t1", Op: "open_read", Path: "/a"},
		{Ts: "t2", Op: "create", Path: "/b"},
	}, 0)

	snap := s.Snapshot("sess-1")
	if len(snap.Events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(snap.Events))
	}
	if snap.Events[0].Path != "/a" || snap.Events[1].Path != "/b" {
		t.Errorf("events out of order: %+v", snap.Events)
	}
	if snap.TotalEvents != 2 {
		t.Errorf("total = %d, want 2", snap.TotalEvents)
	}
	if snap.Truncated {
		t.Error("truncated should be false at 2/4")
	}
	if snap.BufferLimit != 4 {
		t.Errorf("buffer_limit = %d, want 4", snap.BufferLimit)
	}
}

func TestFsEventStore_RingOverwrites(t *testing.T) {
	s := NewFsEventStore(3)

	for i, op := range []string{"a", "b", "c", "d", "e"} {
		s.Ingest("ring", []FsEvent{{Ts: "t", Op: op, Path: "/p"}}, 0)
		_ = i
	}

	snap := s.Snapshot("ring")
	if len(snap.Events) != 3 {
		t.Fatalf("len = %d, want 3", len(snap.Events))
	}
	// After overwrite, the oldest two ('a','b') should be gone; surviving
	// FIFO order is c, d, e.
	wantOps := []string{"c", "d", "e"}
	for i, e := range snap.Events {
		if e.Op != wantOps[i] {
			t.Errorf("events[%d].Op = %q, want %q", i, e.Op, wantOps[i])
		}
	}
	if !snap.Truncated {
		t.Error("expected truncated=true after wrap")
	}
	if snap.TotalEvents != 5 {
		t.Errorf("total = %d, want 5", snap.TotalEvents)
	}
}

func TestFsEventStore_DroppedAccumulates(t *testing.T) {
	s := NewFsEventStore(8)
	s.Ingest("d", nil, 3)
	s.Ingest("d", []FsEvent{{Op: "x", Path: "/p"}}, 5)
	snap := s.Snapshot("d")
	if snap.Dropped != 8 {
		t.Errorf("dropped = %d, want 8", snap.Dropped)
	}
	if len(snap.Events) != 1 {
		t.Errorf("len = %d, want 1", len(snap.Events))
	}
}

func TestFsEventStore_UnknownSessionReturnsZero(t *testing.T) {
	s := NewFsEventStore(0) // default cap
	snap := s.Snapshot("nope")
	if snap.SessionID != "nope" {
		t.Errorf("session_id = %q, want %q", snap.SessionID, "nope")
	}
	if len(snap.Events) != 0 || snap.Dropped != 0 || snap.TotalEvents != 0 {
		t.Errorf("expected empty snapshot, got %+v", snap)
	}
	if snap.BufferLimit != DefaultFsEventBufferCap {
		t.Errorf("buffer_limit = %d, want %d", snap.BufferLimit, DefaultFsEventBufferCap)
	}
}

func TestFsEventStore_Forget(t *testing.T) {
	s := NewFsEventStore(4)
	s.Ingest("g", []FsEvent{{Op: "open_read", Path: "/a"}}, 0)
	if got := len(s.Snapshot("g").Events); got != 1 {
		t.Fatalf("len before forget = %d, want 1", got)
	}
	s.Forget("g")
	if got := len(s.Snapshot("g").Events); got != 0 {
		t.Errorf("len after forget = %d, want 0", got)
	}
}
