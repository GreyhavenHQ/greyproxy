package plugins

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/resolver"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// minForwardCacheTTL is the floor applied to DNS TTLs so that very-short-lived
// records (e.g. TTL=1 from some CDN health checks) do not defeat the cache.
const minForwardCacheTTL = 10 * time.Second

// maxForwardCacheTTL caps how long we honour a TTL. Some providers publish
// TTL=86400 (24h) but rotate IPs mid-day; capping at 5 minutes prevents
// serving stale addresses for too long without excessive re-query churn.
const maxForwardCacheTTL = 5 * time.Minute

// fallbackForwardCacheTTL is used when the raw DNS query fails and we fall
// back to net.DefaultResolver, which does not expose TTL values.
const fallbackForwardCacheTTL = 30 * time.Second

type forwardCacheEntry struct {
	ips    []net.IP
	expiry time.Time
}

// Resolver implements resolver.Resolver.
// It resolves hostnames to IPs using the system DNS server directly via
// miekg/dns so that the actual record TTL can be used in the forward cache.
// This prevents DNS saturation under load. Falls back to net.DefaultResolver
// (with a fixed TTL) when the raw query fails.
type Resolver struct {
	cache     *greyproxy.DNSCache
	dnsServer string // "host:port" of the system resolver, e.g. "127.0.0.53:53"
	log       logger.Logger

	fwdMu  sync.RWMutex
	fwdMap map[string]forwardCacheEntry // "network:host" -> IPs
}

func NewResolver(cache *greyproxy.DNSCache, dnsServer string) *Resolver {
	return &Resolver{
		cache:     cache,
		dnsServer: dnsServer,
		log: logger.Default().WithFields(map[string]any{
			"kind":     "resolver",
			"resolver": "greyproxy",
		}),
		fwdMap: make(map[string]forwardCacheEntry),
	}
}

func (r *Resolver) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) ([]net.IP, error) {
	r.log.Debugf("resolve: %s/%s", host, network)

	key := network + ":" + host

	// Check forward cache first.
	r.fwdMu.RLock()
	entry, ok := r.fwdMap[key]
	r.fwdMu.RUnlock()
	if ok && time.Now().Before(entry.expiry) {
		r.log.Debugf("resolve cache hit: %s -> %v", host, entry.ips)
		return entry.ips, nil
	}

	ips, ttl, err := r.lookup(ctx, network, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no results", host)
	}

	// Store in forward cache with the TTL from the DNS response.
	r.fwdMu.Lock()
	r.fwdMap[key] = forwardCacheEntry{ips: ips, expiry: time.Now().Add(ttl)}
	r.fwdMu.Unlock()

	// Populate the reverse cache (IP -> hostname) for the UI. Only do this for
	// actual hostnames, not raw IPs passed through the resolver.
	if net.ParseIP(host) == nil {
		ipStrs := make([]string, len(ips))
		for i, ip := range ips {
			ipStrs[i] = ip.String()
		}
		r.cache.RegisterIPs(host, ipStrs)
	}

	r.log.Debugf("resolved %s -> %v (ttl=%s)", host, ips, ttl)
	return ips, nil
}

// lookup resolves host using the system DNS server directly when possible so
// we get the real record TTL. Falls back to net.DefaultResolver with a fixed
// TTL when the raw query fails (mDNS, split-horizon DNS, /etc/hosts entries
// that are not in the static gost hosts table, etc.).
func (r *Resolver) lookup(ctx context.Context, network, host string) ([]net.IP, time.Duration, error) {
	if r.dnsServer != "" {
		ips, ttl, err := rawDNSLookup(ctx, r.dnsServer, host, network)
		if err == nil && len(ips) > 0 {
			return ips, ttl, nil
		}
		r.log.Debugf("raw DNS query for %s failed (%v), falling back to OS resolver", host, err)
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, networkToIPVersion(network), host)
	return ips, fallbackForwardCacheTTL, err
}

// rawDNSLookup queries server directly and returns IPs with the minimum TTL
// across all returned records.
func rawDNSLookup(ctx context.Context, server, host, network string) ([]net.IP, time.Duration, error) {
	fqdn := dns.Fqdn(host)
	c := &dns.Client{Timeout: 5 * time.Second}

	var ips []net.IP
	var minTTL uint32

	qtypes := dnsQTypes(network)
	for _, qtype := range qtypes {
		m := new(dns.Msg)
		m.SetQuestion(fqdn, qtype)
		m.RecursionDesired = true

		resp, _, err := c.ExchangeContext(ctx, m, server)
		if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}

		for _, rr := range resp.Answer {
			ttl := rr.Header().Ttl
			if len(ips) == 0 || ttl < minTTL {
				minTTL = ttl
			}
			switch a := rr.(type) {
			case *dns.A:
				ips = append(ips, a.A)
			case *dns.AAAA:
				ips = append(ips, a.AAAA)
			}
		}
	}

	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no records for %s", host)
	}

	ttl := time.Duration(minTTL) * time.Second
	if ttl < minForwardCacheTTL {
		ttl = minForwardCacheTTL
	}
	if ttl > maxForwardCacheTTL {
		ttl = maxForwardCacheTTL
	}
	return ips, ttl, nil
}

// dnsQTypes returns the DNS query types to issue for the given network hint.
func dnsQTypes(network string) []uint16 {
	switch network {
	case "ip4":
		return []uint16{dns.TypeA}
	case "ip6":
		return []uint16{dns.TypeAAAA}
	default:
		return []uint16{dns.TypeA, dns.TypeAAAA}
	}
}

func networkToIPVersion(network string) string {
	switch network {
	case "ip4":
		return "ip4"
	case "ip6":
		return "ip6"
	default:
		return "ip"
	}
}
