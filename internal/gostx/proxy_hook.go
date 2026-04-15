package gostx

import (
	cryptorand "crypto/rand"
	"context"
	"encoding/hex"
	"net/http"
)

// requestIDKey carries a short random id through ctx across the plain-HTTP
// request/response/round-trip hooks so subscribers (e.g. the middleware
// cascade and the transaction persistence hook) can correlate events back
// to one specific round-trip.
type requestIDKey struct{}

// NewRequestID returns a fresh short hex id.
func NewRequestID() string {
	var buf [8]byte
	_, _ = cryptorand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// WithRequestID stores id in ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext retrieves the id stored by WithRequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// ProxyRequestDecision controls what happens to a plain-HTTP request before
// it is forwarded upstream. nil = allow unchanged.
type ProxyRequestDecision struct {
	Deny       bool
	StatusCode int         // default 403 when Deny=true
	DenyBody   string
	NewHeaders http.Header // non-nil: merge into request headers
	NewBody    []byte      // non-nil: replace request body
}

// GlobalProxyRequestHook is called in proxyRoundTrip() before the upstream
// RoundTrip. containerName is the resolved Docker container or client ID.
var GlobalProxyRequestHook func(
	ctx context.Context,
	req *http.Request,
	containerName string,
) *ProxyRequestDecision

// ProxyResponseDecision controls what happens to a plain-HTTP response before
// it is written back to the client. nil = passthrough unchanged.
type ProxyResponseDecision struct {
	Block         bool
	StatusCode    int
	BlockBody     string
	NewStatusCode int
	NewHeaders    http.Header
	NewBody       []byte
}

// GlobalProxyResponseHook is called in proxyRoundTrip() after upstream responds.
var GlobalProxyResponseHook func(
	ctx context.Context,
	req *http.Request,
	resp *http.Response,
	containerName string,
) *ProxyResponseDecision

// ProxyRoundTripInfo is the post-hoc view of a completed plain-HTTP
// round-trip: request + response with bodies captured, durations measured,
// ready to persist. Symmetric with MitmRoundTripInfo but for the non-MITM
// path (plain HTTP upstreams, local servers, etc.).
type ProxyRoundTripInfo struct {
	RequestID       string
	Host            string // req.Host, may include :port
	Method          string
	URL             string // absolute URL as seen by the proxy
	Proto           string
	StatusCode      int
	RequestHeaders  http.Header
	RequestBody     []byte
	ResponseHeaders http.Header
	ResponseBody    []byte
	ContainerName   string
	DurationMs      int64
}

// GlobalProxyRoundTripHook fires at the end of proxyRoundTrip() after the
// response has been fully handled, regardless of whether a middleware was
// configured. Wire this to persist plain-HTTP transactions to the database
// the same way GlobalMitmHook does for MITM. nil = disabled.
var GlobalProxyRoundTripHook func(ctx context.Context, info ProxyRoundTripInfo)
