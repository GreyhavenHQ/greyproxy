package ctx

import (
	"context"
	"net"
)

type Context interface {
	Context() context.Context
}

type WithContext interface {
	WithContext(ctx context.Context)
}

type srcAddrKey struct{}

func ContextWithSrcAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, srcAddrKey{}, addr)
}

func SrcAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(srcAddrKey{}).(net.Addr)
	return v
}

type dstAddrKey struct{}

func ContextWithDstAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, dstAddrKey{}, addr)
}

func DstAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(dstAddrKey{}).(net.Addr)
	return v
}

type (
	Sid string
	// sidKey saves the session ID.
	sidKey struct{}
)

func (s Sid) String() string {
	return string(s)
}

func ContextWithSid(ctx context.Context, sid Sid) context.Context {
	return context.WithValue(ctx, sidKey{}, sid)
}

func SidFromContext(ctx context.Context) Sid {
	v, _ := ctx.Value(sidKey{}).(Sid)
	return v
}

type (
	// hashKey saves the hash source for Selector.
	hashKey struct{}
	Hash    struct {
		Source string
	}
)

func ContextWithHash(ctx context.Context, hash *Hash) context.Context {
	return context.WithValue(ctx, hashKey{}, hash)
}

func HashFromContext(ctx context.Context) *Hash {
	if v, _ := ctx.Value(hashKey{}).(*Hash); v != nil {
		return v
	}
	return nil
}

type (
	ClientID    string
	clientIDKey struct{}
)

func (s ClientID) String() string {
	return string(s)
}

func ContextWithClientID(ctx context.Context, clientID ClientID) context.Context {
	return context.WithValue(ctx, clientIDKey{}, clientID)
}

func ClientIDFromContext(ctx context.Context) ClientID {
	v, _ := ctx.Value(clientIDKey{}).(ClientID)
	return v
}

// ConnCanceller allows registering connection cancel functions by rule ID.
// Implemented by greyproxy.ConnTracker.
type ConnCanceller interface {
	Register(ruleID int64, cancel context.CancelFunc) uint64
	Unregister(ruleID int64, id uint64)
}

// BypassResult is a mutable container placed in the context before calling
// bypass.Contains. The bypass plugin fills in the RuleID and Tracker when
// a connection is allowed by a rule, so the handler can register the
// connection for cancellation if the rule is later deleted.
type BypassResult struct {
	RuleID  int64
	Tracker ConnCanceller
}

type bypassResultKey struct{}

func ContextWithBypassResult(ctx context.Context, result *BypassResult) context.Context {
	return context.WithValue(ctx, bypassResultKey{}, result)
}

func BypassResultFromContext(ctx context.Context) *BypassResult {
	v, _ := ctx.Value(bypassResultKey{}).(*BypassResult)
	return v
}
