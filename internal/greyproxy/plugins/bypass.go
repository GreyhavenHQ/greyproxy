package plugins

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	ctxvalue "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

type ContainerResolver interface {
	ResolveIP(ip string) (name string, id string)
}

// AllowAllChecker is satisfied by AllowAllManager. Extracted as an interface
// so the bypass plugin does not import the full greyproxy package for this.
type AllowAllChecker interface {
	IsActive() bool
	Mode() string // "allow" or "deny"
}

// Bypass implements bypass.Bypass.
// This is the main ACL enforcement point — it evaluates every destination
// against the rule database and decides whether to allow or block.
//
// IMPORTANT: In gost's blacklist mode (IsWhitelist()=false),
// Contains() returning true means BLOCK the connection.
type Bypass struct {
	db          *greyproxy.DB
	cache       *greyproxy.DNSCache
	bus         *greyproxy.EventBus
	waiters     *greyproxy.WaiterTracker
	connTracker *greyproxy.ConnTracker
	docker      ContainerResolver // optional; nil means no Docker resolution
	allowAll    AllowAllChecker   // optional; nil means feature is disabled
	log         logger.Logger
}

func NewBypass(db *greyproxy.DB, cache *greyproxy.DNSCache, bus *greyproxy.EventBus, waiters *greyproxy.WaiterTracker, connTracker *greyproxy.ConnTracker, docker ContainerResolver, allowAll AllowAllChecker) *Bypass {
	return &Bypass{
		db:          db,
		cache:       cache,
		bus:         bus,
		waiters:     waiters,
		connTracker: connTracker,
		docker:      docker,
		allowAll:    allowAll,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "bypass",
			"bypass": "greyproxy",
		}),
	}
}

// IsWhitelist returns false — we operate in blacklist mode.
// Contains()=true means the address should be BLOCKED.
func (b *Bypass) IsWhitelist() bool {
	return false
}

// gracePeriod is how long to hold a connection open waiting for user approval.
const gracePeriod = 30 * time.Second

// Contains evaluates the ACL for the given destination address.
// Returns true to BLOCK, false to ALLOW.
func (b *Bypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	start := time.Now()

	var o bypass.Options
	for _, opt := range opts {
		opt(&o)
	}

	// Silent mode: bypass all rule evaluation for the duration.
	// Connections are still logged (with nil rule ID) so activity remains visible.
	if b.allowAll != nil && b.allowAll.IsActive() {
		silentHost, silentPortStr, _ := net.SplitHostPort(addr)
		if silentHost == "" {
			silentHost = addr
			silentPortStr = "0"
		}
		silentPort, _ := strconv.Atoi(silentPortStr)
		elapsed := time.Since(start).Milliseconds()
		clientID := string(ctxvalue.ClientIDFromContext(ctx))
		srcIP := ""
		if srcAddr := ctxvalue.SrcAddrFromContext(ctx); srcAddr != nil {
			srcIP, _, _ = net.SplitHostPort(srcAddr.String())
		}
		var containerName, containerID string
		if b.docker != nil && srcIP != "" {
			containerName, containerID = b.docker.ResolveIP(srcIP)
		}
		if containerName == "" {
			containerName, containerID = ResolveIdentity(clientID, srcIP)
		}
		resolvedHostname := b.resolveHostname(silentHost)

		if b.allowAll.Mode() == greyproxy.SilentModeDeny {
			go b.logRequest(containerName, containerID, silentHost, silentPort, resolvedHostname, methodFromService(o.Service), "blocked", nil, &elapsed)
			b.log.Debugf("SILENT-DENY %s -> %s:%d (%s)", containerName, silentHost, silentPort, network)
			return true // block
		}

		go b.logRequest(containerName, containerID, silentHost, silentPort, resolvedHostname, methodFromService(o.Service), "allowed", nil, &elapsed)
		b.log.Debugf("SILENT-ALLOW %s -> %s:%d (%s)", containerName, silentHost, silentPort, network)
		return false // allow
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = "0"
	}
	port, _ := strconv.Atoi(portStr)

	// Get client identity from context (set by auther)
	clientID := string(ctxvalue.ClientIDFromContext(ctx))

	// Extract the real source IP from context. This is more reliable than parsing
	// clientID, which may be "unknown" in HTTP proxy mode before the auther runs.
	srcIP := ""
	if srcAddr := ctxvalue.SrcAddrFromContext(ctx); srcAddr != nil {
		srcIP, _, _ = net.SplitHostPort(srcAddr.String())
	}

	// Resolve container identity: Docker socket lookup takes priority when enabled,
	// so rules can match full Docker container names (e.g. "my-app-1").
	// Falls back to username-based or IP-based identity when Docker is unavailable.
	var containerName, containerID string
	if b.docker != nil && srcIP != "" {
		containerName, containerID = b.docker.ResolveIP(srcIP)
	}
	if containerName == "" {
		containerName, containerID = ResolveIdentity(clientID, srcIP)
	}

	// Resolve hostname
	resolvedHostname := b.resolveHostname(host)

	// Find matching rule
	matchHost := host
	if resolvedHostname != "" {
		matchHost = resolvedHostname
	}
	rule := greyproxy.FindMatchingRule(b.db, containerName, host, port, resolvedHostname)

	// Determine decision
	var allowed bool
	var ruleID *int64
	var deniedByRule bool

	if rule != nil {
		if rule.Action == "allow" {
			allowed = true
			ruleID = &rule.ID
		} else {
			allowed = false
			deniedByRule = true
			ruleID = &rule.ID
		}
	}
	// No rule = default deny (allowed stays false)

	// Store the rule ID and conn tracker in the context's BypassResult
	// so the handler can register the connection for cancellation.
	if allowed && ruleID != nil {
		if br := ctxvalue.BypassResultFromContext(ctx); br != nil {
			br.RuleID = *ruleID
			br.Tracker = b.connTracker
		}
	}

	// If blocked by default (no matching rule), hold the connection and wait
	// for the user to approve via the dashboard within the grace period.
	if !allowed && !deniedByRule {
		b.createPending(containerName, containerID, host, port, resolvedHostname)

		done := b.waiters.Add(containerName, host, port)
		defer done()

		if rule := b.waitForApproval(ctx, containerName, host, port, resolvedHostname); rule != nil {
			allowed = true
			ruleID = &rule.ID
			if br := ctxvalue.BypassResultFromContext(ctx); br != nil {
				br.RuleID = rule.ID
				br.Tracker = b.connTracker
			}
		}
	}

	// Log the request with the final decision
	elapsed := time.Since(start).Milliseconds()
	result := "blocked"
	if allowed {
		result = "allowed"
	}

	go b.logRequest(containerName, containerID, host, port, resolvedHostname, methodFromService(o.Service), result, ruleID, &elapsed)

	if allowed {
		b.log.Debugf("ALLOW %s -> %s:%d (%s) rule=%v", containerName, matchHost, port, network, ruleID)
	} else {
		b.log.Debugf("BLOCK %s -> %s:%d (%s)", containerName, matchHost, port, network)
	}

	// In blacklist mode: return true to BLOCK
	return !allowed
}

// waitForApproval subscribes to the event bus and waits up to gracePeriod for
// the user to allow the pending request. If a matching allow rule appears,
// it returns that rule. Otherwise it returns nil.
func (b *Bypass) waitForApproval(ctx context.Context, containerName, host string, port int, resolvedHostname string) *greyproxy.Rule {
	ch := b.bus.Subscribe(16)
	defer b.bus.Unsubscribe(ch)

	timer := time.NewTimer(gracePeriod)
	defer timer.Stop()

	b.log.Debugf("HOLD  %s -> %s:%d waiting up to %s for approval", containerName, host, port, gracePeriod)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return nil
		case evt := <-ch:
			switch evt.Type {
			case greyproxy.EventPendingAllowed:
				// A pending was just allowed and a rule was created.
				// Re-check if a rule now matches our connection.
				if rule := greyproxy.FindMatchingRule(b.db, containerName, host, port, resolvedHostname); rule != nil && rule.Action == "allow" {
					b.log.Debugf("APPROVED %s -> %s:%d during grace period (rule %d)", containerName, host, port, rule.ID)
					return rule
				}
			case greyproxy.EventPendingDismissed:
				// The user denied or dismissed the pending request.
				// Stop waiting if there's no rule or if the matching rule is a deny.
				rule := greyproxy.FindMatchingRule(b.db, containerName, host, port, resolvedHostname)
				if rule == nil || rule.Action == "deny" {
					b.log.Debugf("DENIED %s -> %s:%d during grace period", containerName, host, port)
					return nil
				}
			}
		}
	}
}

func (b *Bypass) resolveHostname(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		// It's already a hostname — register it for future IP lookups
		b.cache.RegisterHostname(host)
		return ""
	}
	// It's an IP — try to find the hostname
	return b.cache.ResolveIP(host)
}

// ResolveIdentity derives a display name for the connecting client.
// srcIP, when non-empty, is preferred over parsing the IP from clientID because
// clientID may be "unknown" in HTTP proxy mode before the auther runs.
// Pass srcIP as "" when only a clientID is available (e.g. MITM hooks).
func ResolveIdentity(clientID, srcIP string) (containerName, containerID string) {
	_, username := ParseClientID(clientID)

	if username != "" && username != "proxy" {
		return username, ""
	}

	ip := srcIP
	if ip == "" {
		ip, _ = ParseClientID(clientID)
	}
	return fmt.Sprintf("unknown-%s", ip), ""
}

// methodFromService maps a gost service name (e.g. "http-proxy", "socks5") to the
// protocol label stored in request_logs. Falls back to "unknown".
func methodFromService(service string) string {
	switch {
	case strings.Contains(service, "http"):
		return "HTTP"
	case strings.Contains(service, "socks"):
		return "SOCKS5"
	default:
		return "unknown"
	}
}

func (b *Bypass) logRequest(containerName, containerID, destHost string, destPort int, resolvedHostname, method, result string, ruleID *int64, responseTimeMs *int64) {
	_, err := greyproxy.CreateLogEntry(b.db, greyproxy.LogCreateInput{
		ContainerName:    containerName,
		ContainerID:      containerID,
		DestinationHost:  destHost,
		DestinationPort:  destPort,
		ResolvedHostname: resolvedHostname,
		Method:           method,
		Result:           result,
		RuleID:           ruleID,
		ResponseTimeMs:   responseTimeMs,
	})
	if err != nil {
		b.log.Warnf("failed to log request: %v", err)
	}
}

func (b *Bypass) createPending(containerName, containerID, destHost string, destPort int, resolvedHostname string) {
	pending, isNew, err := greyproxy.CreateOrUpdatePending(b.db, containerName, containerID, destHost, destPort, resolvedHostname)
	if err != nil {
		b.log.Warnf("failed to create pending: %v", err)
		return
	}

	if isNew {
		b.bus.Publish(greyproxy.Event{
			Type: greyproxy.EventPendingCreated,
			Data: pending.ToJSON(),
		})
	} else {
		b.bus.Publish(greyproxy.Event{
			Type: greyproxy.EventPendingUpdated,
			Data: pending.ToJSON(),
		})
	}
}
