package gostx

import (
	"context"
	"net/http"

	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/sniffing"
)

// Request ID ctx helpers. The implementation lives in the sniffing
// package (the lowest-level package in the sniff→gostx chain) so both
// the sniffer's httpRoundTrip (which generates and writes the id) and
// the cmd layer's hook closures (which read it) agree on a single
// unexported ctx key. These wrappers exist for ergonomic access from
// handler/http/handler.go and cmd/greyproxy/program.go.

// NewRequestID returns a fresh 16-char hex id suitable for threading
// through ctx across the hooks of one round-trip.
func NewRequestID() string { return sniffing.NewRequestID() }

// WithRequestID stores id in ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return sniffing.WithRequestID(ctx, id)
}

// RequestIDFromContext retrieves the id stored by WithRequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	return sniffing.RequestIDFromContext(ctx)
}

// ProxyRequestDecision controls what happens to a plain-HTTP request before
// it is forwarded upstream. nil = allow unchanged.
type ProxyRequestDecision struct {
	Deny       bool
	StatusCode int // default 403 when Deny=true
	DenyBody   string
	NewHeaders http.Header // non-nil: merge into request headers
	NewBody    []byte      // non-nil: replace request body
}

// GlobalProxyRequestHook is called in proxyRoundTrip() before the upstream
// RoundTrip. containerName is the resolved Docker container or client ID.
// The hook may return a non-nil ctx to propagate values (e.g. a captured
// request body) through to the response hook; a nil ctx means "no change".
var GlobalProxyRequestHook func(
	ctx context.Context,
	req *http.Request,
	containerName string,
) (context.Context, *ProxyRequestDecision)

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
