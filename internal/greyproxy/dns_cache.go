package greyproxy

import (
	"context"
	"net"
	"sync"
	"time"
)

const defaultDNSCacheTTL = 1 * time.Hour

// dnsCacheDBTTL is how long DB entries are considered valid (7 days).
const dnsCacheDBTTL = 7 * 24 * time.Hour

type dnsCacheEntry struct {
	hostname string
	expiry   time.Time
}

// DNSCache provides a thread-safe IP-to-hostname cache with TTL.
// When a DB is attached, entries are persisted to SQLite and restored on startup.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry // IP -> hostname
	ttl     time.Duration
	db      *DB
}

func NewDNSCache(db *DB) *DNSCache {
	c := &DNSCache{
		entries: make(map[string]dnsCacheEntry),
		ttl:     defaultDNSCacheTTL,
		db:      db,
	}
	if db != nil {
		c.loadFromDB()
	}
	return c
}

// loadFromDB hydrates the in-memory cache from persisted entries.
func (c *DNSCache) loadFromDB() {
	cutoff := time.Now().Add(-dnsCacheDBTTL)
	rows, err := c.db.ReadDB().Query(
		"SELECT ip, hostname FROM dns_cache WHERE updated_at > ?",
		cutoff.UTC().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()

	c.mu.Lock()
	defer c.mu.Unlock()

	for rows.Next() {
		var ip, hostname string
		if err := rows.Scan(&ip, &hostname); err != nil {
			continue
		}
		c.entries[ip] = dnsCacheEntry{hostname: hostname, expiry: time.Now().Add(c.ttl)}
	}
}

// persistToDB writes an IP-to-hostname mapping to the database.
func (c *DNSCache) persistToDB(ip, hostname string) {
	if c.db == nil {
		return
	}
	go func() {
		c.db.Lock()
		defer c.db.Unlock()
		_, _ = c.db.WriteDB().Exec(
			"INSERT OR REPLACE INTO dns_cache (ip, hostname, updated_at) VALUES (?, ?, datetime('now'))",
			ip, hostname,
		)
	}()
}

// ResolveIP attempts to get a hostname for the given IP.
// Checks in-memory cache first, then DB, then falls back to reverse DNS lookup.
func (c *DNSCache) ResolveIP(ip string) string {
	// Check in-memory cache
	if hostname := c.GetCached(ip); hostname != "" {
		return hostname
	}

	// Check DB before reverse DNS
	if hostname := c.getFromDB(ip); hostname != "" {
		c.mu.Lock()
		c.entries[ip] = dnsCacheEntry{hostname: hostname, expiry: time.Now().Add(c.ttl)}
		c.mu.Unlock()
		return hostname
	}

	// Try reverse DNS
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}

	hostname := names[0]
	// Remove trailing dot from DNS names
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}

	c.mu.Lock()
	c.entries[ip] = dnsCacheEntry{hostname: hostname, expiry: time.Now().Add(c.ttl)}
	c.mu.Unlock()

	c.persistToDB(ip, hostname)

	return hostname
}

// getFromDB looks up a hostname from the persistent cache.
func (c *DNSCache) getFromDB(ip string) string {
	if c.db == nil {
		return ""
	}
	cutoff := time.Now().Add(-dnsCacheDBTTL)
	var hostname string
	err := c.db.ReadDB().QueryRow(
		"SELECT hostname FROM dns_cache WHERE ip = ? AND updated_at > ?",
		ip, cutoff.UTC().Format("2006-01-02 15:04:05"),
	)
	if err := err.Scan(&hostname); err != nil {
		return ""
	}
	return hostname
}

// RegisterHostname does a forward DNS lookup and caches all resulting IPs.
func (c *DNSCache) RegisterHostname(hostname string) {
	ips, err := net.DefaultResolver.LookupHost(context.Background(), hostname)
	if err != nil {
		return
	}
	c.RegisterIPs(hostname, ips)
}

// RegisterIPs pre-populates the cache with known IP -> hostname mappings.
func (c *DNSCache) RegisterIPs(hostname string, ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := time.Now().Add(c.ttl)
	for _, ip := range ips {
		c.entries[ip] = dnsCacheEntry{hostname: hostname, expiry: expiry}
	}

	// Persist to DB
	if c.db != nil {
		go func() {
			c.db.Lock()
			defer c.db.Unlock()
			for _, ip := range ips {
				_, _ = c.db.WriteDB().Exec(
					"INSERT OR REPLACE INTO dns_cache (ip, hostname, updated_at) VALUES (?, ?, datetime('now'))",
					ip, hostname,
				)
			}
		}()
	}
}

// GetCached returns the cached hostname for an IP, or empty string if not found/expired.
func (c *DNSCache) GetCached(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[ip]
	if !ok || time.Now().After(entry.expiry) {
		return ""
	}
	return entry.hostname
}
