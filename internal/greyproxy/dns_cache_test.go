package greyproxy

import (
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestDNSCacheRegisterAndGet(t *testing.T) {
	cache := NewDNSCache(nil)

	cache.RegisterIPs("example.com", []string{"1.2.3.4", "5.6.7.8"})

	if got := cache.GetCached("1.2.3.4"); got != "example.com" {
		t.Errorf("got %q, want %q", got, "example.com")
	}
	if got := cache.GetCached("5.6.7.8"); got != "example.com" {
		t.Errorf("got %q, want %q", got, "example.com")
	}
	if got := cache.GetCached("9.9.9.9"); got != "" {
		t.Errorf("expected empty for unknown IP, got %q", got)
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	cache := &DNSCache{
		entries: make(map[string]dnsCacheEntry),
		ttl:     1 * time.Millisecond, // Very short TTL
	}

	cache.RegisterIPs("example.com", []string{"1.2.3.4"})

	// Should be cached immediately
	if got := cache.GetCached("1.2.3.4"); got != "example.com" {
		t.Errorf("expected cached value, got %q", got)
	}

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	if got := cache.GetCached("1.2.3.4"); got != "" {
		t.Errorf("expected expired entry to return empty, got %q", got)
	}
}

func TestDNSCacheResolveIPUsesCache(t *testing.T) {
	cache := NewDNSCache(nil)

	// Pre-populate cache
	cache.RegisterIPs("example.com", []string{"1.2.3.4"})

	// ResolveIP should use cache
	got := cache.ResolveIP("1.2.3.4")
	if got != "example.com" {
		t.Errorf("expected cached result, got %q", got)
	}
}

func setupDNSTestDB(t *testing.T) *DB {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "greyproxy_dns_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	db, err := OpenDB(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestDNSCacheDBPersistAndReload(t *testing.T) {
	db := setupDNSTestDB(t)

	// Create a cache with DB and register entries
	cache1 := NewDNSCache(db)
	cache1.RegisterIPs("example.com", []string{"10.0.0.1", "10.0.0.2"})

	// Let async DB writes complete
	time.Sleep(50 * time.Millisecond)

	// Verify entries are in the database
	var count int
	db.ReadDB().QueryRow("SELECT COUNT(*) FROM dns_cache").Scan(&count)
	if count != 2 {
		t.Fatalf("expected 2 rows in dns_cache, got %d", count)
	}

	// Create a new cache from the same DB (simulates restart)
	cache2 := NewDNSCache(db)

	// Should have the entries loaded from DB
	if got := cache2.GetCached("10.0.0.1"); got != "example.com" {
		t.Errorf("after reload: got %q, want %q", got, "example.com")
	}
	if got := cache2.GetCached("10.0.0.2"); got != "example.com" {
		t.Errorf("after reload: got %q, want %q", got, "example.com")
	}
}

func TestDNSCacheDBFallbackOnMemoryExpiry(t *testing.T) {
	db := setupDNSTestDB(t)

	// Create a cache with very short in-memory TTL but DB backing
	cache := &DNSCache{
		entries: make(map[string]dnsCacheEntry),
		ttl:     1 * time.Millisecond,
		db:      db,
	}
	cache.RegisterIPs("example.com", []string{"10.0.0.1"})

	// Let async DB write complete
	time.Sleep(50 * time.Millisecond)

	// In-memory entry should be expired
	if got := cache.GetCached("10.0.0.1"); got != "" {
		t.Errorf("expected in-memory entry to be expired, got %q", got)
	}

	// ResolveIP should fall back to DB and recover the hostname
	got := cache.ResolveIP("10.0.0.1")
	if got != "example.com" {
		t.Errorf("expected DB fallback to return %q, got %q", "example.com", got)
	}

	// After DB fallback, should be back in memory
	if got := cache.GetCached("10.0.0.1"); got != "example.com" {
		t.Errorf("expected re-cached value %q, got %q", "example.com", got)
	}
}

func TestDNSCacheDBExpiredEntriesNotLoaded(t *testing.T) {
	db := setupDNSTestDB(t)

	// Insert an entry with an old updated_at (beyond 7-day TTL)
	db.Lock()
	db.WriteDB().Exec(
		"INSERT INTO dns_cache (ip, hostname, updated_at) VALUES (?, ?, datetime('now', '-8 days'))",
		"10.0.0.1", "stale.example.com",
	)
	db.Unlock()

	// New cache should NOT load the stale entry
	cache := NewDNSCache(db)
	if got := cache.GetCached("10.0.0.1"); got != "" {
		t.Errorf("expected stale entry to not be loaded, got %q", got)
	}

	// getFromDB should also not return it
	if got := cache.getFromDB("10.0.0.1"); got != "" {
		t.Errorf("expected stale entry to not be returned from DB, got %q", got)
	}
}

func TestDNSCacheDBUpsertUpdatesTimestamp(t *testing.T) {
	db := setupDNSTestDB(t)

	cache := NewDNSCache(db)

	// Register, then re-register with different hostname
	cache.RegisterIPs("old.example.com", []string{"10.0.0.1"})
	time.Sleep(50 * time.Millisecond)

	cache.RegisterIPs("new.example.com", []string{"10.0.0.1"})
	time.Sleep(50 * time.Millisecond)

	// DB should have the latest hostname
	var hostname string
	db.ReadDB().QueryRow("SELECT hostname FROM dns_cache WHERE ip = ?", "10.0.0.1").Scan(&hostname)
	if hostname != "new.example.com" {
		t.Errorf("expected upserted hostname %q, got %q", "new.example.com", hostname)
	}

	// Only one row for that IP
	var count int
	db.ReadDB().QueryRow("SELECT COUNT(*) FROM dns_cache WHERE ip = ?", "10.0.0.1").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 row for IP, got %d", count)
	}
}
