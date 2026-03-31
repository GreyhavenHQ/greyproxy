package greyproxy

import (
	"net/http"
	"testing"
)

func TestQueryActivity(t *testing.T) {
	db := setupTestDB(t)

	// Seed connection logs
	CreateLogEntry(db, LogCreateInput{ContainerName: "myapp", DestinationHost: "api.example.com", DestinationPort: 443, Result: "allowed"})
	CreateLogEntry(db, LogCreateInput{ContainerName: "myapp", DestinationHost: "evil.com", DestinationPort: 443, Result: "blocked"})

	// Seed HTTP transactions
	CreateHttpTransaction(db, HttpTransactionCreateInput{
		ContainerName: "myapp", DestinationHost: "api.example.com", DestinationPort: 443,
		Method: "POST", URL: "https://api.example.com/v1/messages",
		RequestHeaders: http.Header{"Content-Type": {"application/json"}},
		StatusCode: 200, DurationMs: 150, Result: "auto",
	})

	t.Run("shows both connections and HTTP traffic", func(t *testing.T) {
		items, total, err := QueryActivity(db, ActivityFilter{Limit: 50})
		if err != nil {
			t.Fatalf("QueryActivity: %v", err)
		}
		// 2 connection rows + 1 HTTP transaction
		if total != 3 {
			t.Fatalf("total: got %d, want 3", total)
		}
		if len(items) != 3 {
			t.Fatalf("items: got %d, want 3", len(items))
		}

		var connCount, httpCount int
		for _, item := range items {
			switch item.Kind {
			case "connection":
				connCount++
			case "http":
				httpCount++
			}
		}
		if connCount != 2 {
			t.Errorf("connection items: got %d, want 2", connCount)
		}
		if httpCount != 1 {
			t.Errorf("http items: got %d, want 1", httpCount)
		}
	})

	t.Run("filter by kind=connection", func(t *testing.T) {
		items, total, err := QueryActivity(db, ActivityFilter{Kind: "connection", Limit: 50})
		if err != nil {
			t.Fatalf("QueryActivity: %v", err)
		}
		if total != 2 {
			t.Fatalf("total: got %d, want 2", total)
		}
		for _, item := range items {
			if item.Kind != "connection" {
				t.Errorf("expected kind=connection, got %s", item.Kind)
			}
		}
		_ = items
	})

	t.Run("filter by kind=http", func(t *testing.T) {
		items, total, err := QueryActivity(db, ActivityFilter{Kind: "http", Limit: 50})
		if err != nil {
			t.Fatalf("QueryActivity: %v", err)
		}
		if total != 1 {
			t.Fatalf("total: got %d, want 1", total)
		}
		if items[0].Kind != "http" {
			t.Errorf("expected kind=http, got %s", items[0].Kind)
		}
		if items[0].Method.String != "POST" {
			t.Errorf("expected method=POST, got %s", items[0].Method.String)
		}
	})

	t.Run("filter by result=blocked", func(t *testing.T) {
		items, total, err := QueryActivity(db, ActivityFilter{Result: "blocked", Limit: 50})
		if err != nil {
			t.Fatalf("QueryActivity: %v", err)
		}
		// Only connections have result=blocked; HTTP transactions use "auto" and are excluded
		if total != 1 {
			t.Fatalf("total: got %d, want 1", total)
		}
		if items[0].DestinationHost != "evil.com" {
			t.Errorf("expected evil.com, got %s", items[0].DestinationHost)
		}
	})

	t.Run("filter by container", func(t *testing.T) {
		items, total, err := QueryActivity(db, ActivityFilter{Container: "myapp", Limit: 50})
		if err != nil {
			t.Fatalf("QueryActivity: %v", err)
		}
		// 2 connections + 1 HTTP transaction
		if total != 3 {
			t.Fatalf("total: got %d, want 3", total)
		}
		_ = items
	})

	t.Run("filter by destination", func(t *testing.T) {
		items, total, err := QueryActivity(db, ActivityFilter{Destination: "evil", Limit: 50})
		if err != nil {
			t.Fatalf("QueryActivity: %v", err)
		}
		if total != 1 {
			t.Fatalf("total: got %d, want 1", total)
		}
		_ = items
	})

	t.Run("pagination", func(t *testing.T) {
		items, total, err := QueryActivity(db, ActivityFilter{Limit: 2})
		if err != nil {
			t.Fatalf("QueryActivity: %v", err)
		}
		if total != 3 {
			t.Fatalf("total: got %d, want 3", total)
		}
		if len(items) != 2 {
			t.Fatalf("items: got %d, want 2", len(items))
		}

		// Page 2
		items2, _, err := QueryActivity(db, ActivityFilter{Limit: 2, Offset: 2})
		if err != nil {
			t.Fatalf("QueryActivity page 2: %v", err)
		}
		if len(items2) != 1 {
			t.Fatalf("items page 2: got %d, want 1", len(items2))
		}
	})
}
