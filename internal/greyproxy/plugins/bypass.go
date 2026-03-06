package plugins

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	ctxvalue "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// Bypass implements bypass.Bypass.
// This is the main ACL enforcement point — it evaluates every destination
// against the rule database and decides whether to allow or block.
//
// IMPORTANT: In gost's blacklist mode (IsWhitelist()=false),
// Contains() returning true means BLOCK the connection.
type Bypass struct {
	db    *greyproxy.DB
	cache *greyproxy.DNSCache
	bus   *greyproxy.EventBus
	log   logger.Logger
}

func NewBypass(db *greyproxy.DB, cache *greyproxy.DNSCache, bus *greyproxy.EventBus) *Bypass {
	return &Bypass{
		db:    db,
		cache: cache,
		bus:   bus,
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

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = "0"
	}
	port, _ := strconv.Atoi(portStr)

	// Get client identity from context (set by auther)
	clientID := string(ctxvalue.ClientIDFromContext(ctx))
	containerName, containerID := resolveIdentity(clientID)

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

	// If blocked by default (no matching rule), hold the connection and wait
	// for the user to approve via the dashboard within the grace period.
	if !allowed && !deniedByRule {
		b.createPending(containerName, containerID, host, port, resolvedHostname)

		if rule := b.waitForApproval(ctx, containerName, host, port, resolvedHostname); rule != nil {
			allowed = true
			ruleID = &rule.ID
		}
	}

	// Log the request with the final decision
	elapsed := time.Since(start).Milliseconds()
	result := "blocked"
	if allowed {
		result = "allowed"
	}

	go b.logRequest(containerName, containerID, host, port, resolvedHostname, result, ruleID, &elapsed)

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

func resolveIdentity(clientID string) (containerName, containerID string) {
	ip, username := ParseClientID(clientID)

	if username != "" && username != "proxy" {
		return username, ""
	}

	return fmt.Sprintf("unknown-%s", ip), ""
}

func (b *Bypass) logRequest(containerName, containerID, destHost string, destPort int, resolvedHostname, result string, ruleID *int64, responseTimeMs *int64) {
	_, err := greyproxy.CreateLogEntry(b.db, greyproxy.LogCreateInput{
		ContainerName:    containerName,
		ContainerID:      containerID,
		DestinationHost:  destHost,
		DestinationPort:  destPort,
		ResolvedHostname: resolvedHostname,
		Method:           "SOCKS5",
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
