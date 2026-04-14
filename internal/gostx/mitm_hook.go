package gostx

import (
	"context"
	"net/http"

	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/sniffing"
)

// MitmRoundTripInfo contains decrypted HTTP request/response data from a MITM round-trip.
// This re-exports the internal sniffing type for use outside the gostx/internal package.
type MitmRoundTripInfo struct {
	// RequestID uniquely identifies one MITM round-trip. Threaded through
	// both the middleware response hook and the round-trip persistence hook
	// so subscribers can correlate decisions back to the http_transactions
	// row created for this request.
	RequestID              string
	Host                   string
	Method                 string
	URI                    string
	Proto                  string
	StatusCode             int
	RequestHeaders         http.Header
	RequestBody            []byte
	ResponseHeaders        http.Header
	ResponseBody           []byte
	ContainerName          string
	DurationMs             int64
	SubstitutedCredentials []string
	SessionID              string
}

// CredentialSubstitutionInfo holds the result of a credential substitution pass.
// Re-exports the internal sniffing type.
type CredentialSubstitutionInfo = sniffing.CredentialSubstitutionInfo

// MitmRequestHoldInfo contains request details for the hold hook to evaluate.
type MitmRequestHoldInfo struct {
	Host           string
	Method         string
	URI            string
	RequestHeaders http.Header
	RequestBody    []byte
	ContainerName  string
}

// ConnectionFinishInfo contains connection metadata reported after a handler finishes.
type ConnectionFinishInfo struct {
	Host           string
	MitmSkipReason string
	ContainerName  string
}

// GlobalConnectionFinishHook is called (if set) after a handler finishes processing a CONNECT tunnel.
var GlobalConnectionFinishHook func(info ConnectionFinishInfo)

// SetGlobalConnectionFinishHook sets a callback that fires when a CONNECT tunnel handler finishes.
func SetGlobalConnectionFinishHook(hook func(info ConnectionFinishInfo)) {
	GlobalConnectionFinishHook = hook
}

// ErrRequestDenied is returned by the hold hook to deny a request.
var ErrRequestDenied = sniffing.ErrRequestDenied

// SetGlobalMitmEnabled enables or disables MITM TLS interception globally.
func SetGlobalMitmEnabled(enabled bool) {
	sniffing.SetGlobalMitmEnabled(enabled)
}

// IsMitmEnabled returns whether MITM TLS interception is globally enabled.
func IsMitmEnabled() bool {
	return sniffing.IsMitmEnabled()
}

// SetGlobalMitmHook sets a global callback that fires after every MITM-intercepted HTTP round-trip.
func SetGlobalMitmHook(hook func(info MitmRoundTripInfo)) {
	if hook == nil {
		sniffing.GlobalHTTPRoundTripHook = nil
		return
	}
	sniffing.GlobalHTTPRoundTripHook = func(info sniffing.HTTPRoundTripInfo) {
		hook(MitmRoundTripInfo{
			RequestID:              info.RequestID,
			Host:                   info.Host,
			Method:                 info.Method,
			URI:                    info.URI,
			Proto:                  info.Proto,
			StatusCode:             info.StatusCode,
			RequestHeaders:         info.RequestHeaders,
			RequestBody:            info.RequestBody,
			ResponseHeaders:        info.ResponseHeaders,
			ResponseBody:           info.ResponseBody,
			ContainerName:          info.ContainerName,
			DurationMs:             info.DurationMs,
			SubstitutedCredentials: info.SubstitutedCredentials,
			SessionID:              info.SessionID,
		})
	}
}

// SetGlobalCredentialSubstituter sets a callback that modifies HTTP requests in-place
// just before they are forwarded upstream. Used to replace credential placeholders
// with real values. Headers are already cloned for storage before this point.
// The hook returns substitution info (labels and session ID).
// Access is synchronized via atomic.Pointer (safe to call while requests are in flight).
func SetGlobalCredentialSubstituter(hook func(req *http.Request) *CredentialSubstitutionInfo) {
	sniffing.SetGlobalCredentialSubstituter(hook)
}

// MitmWebSocketFrameInfo contains a single WebSocket frame captured during MITM.
type MitmWebSocketFrameInfo struct {
	Host          string
	URI           string
	From          string // "client" or "server"
	OpCode        int
	Fin           bool
	Rsv1          bool // true when permessage-deflate compression is active
	Payload       []byte
	ContainerName string
}

// SetGlobalMitmWebSocketFrameHook sets a global callback that fires after each MITM-intercepted WebSocket frame.
func SetGlobalMitmWebSocketFrameHook(hook func(info MitmWebSocketFrameInfo)) {
	if hook == nil {
		sniffing.GlobalWebSocketFrameHook = nil
		return
	}
	sniffing.GlobalWebSocketFrameHook = func(info sniffing.WebSocketFrameInfo) {
		hook(MitmWebSocketFrameInfo{
			Host:          info.Host,
			URI:           info.URI,
			From:          info.From,
			OpCode:        info.OpCode,
			Fin:           info.Fin,
			Rsv1:          info.Rsv1,
			Payload:       info.Payload,
			ContainerName: info.ContainerName,
		})
	}
}

// SetGlobalMitmHoldHook sets a global callback that fires BEFORE forwarding a MITM-intercepted
// HTTP request upstream. Return nil to allow, ErrRequestDenied to deny with 403.
// The hook may block (e.g., waiting for user approval).
func SetGlobalMitmHoldHook(hook func(ctx context.Context, info MitmRequestHoldInfo) error) {
	if hook == nil {
		sniffing.GlobalHTTPRequestHoldHook = nil
		return
	}
	sniffing.GlobalHTTPRequestHoldHook = func(ctx context.Context, info sniffing.HTTPRequestHoldInfo) error {
		return hook(ctx, MitmRequestHoldInfo{
			Host:           info.Host,
			Method:         info.Method,
			URI:            info.URI,
			RequestHeaders: info.RequestHeaders,
			RequestBody:    info.RequestBody,
			ContainerName:  info.ContainerName,
		})
	}
}

// GlobalMitmRequestMiddlewareHook is called after the hold hook passes but
// before credential substitution. It receives the mutable *http.Request.
// Return nil to allow unchanged. Return ErrRequestDenied to block.
// Mutate req in place to rewrite.
var GlobalMitmRequestMiddlewareHook func(
	ctx context.Context,
	req *http.Request,
	containerName string,
) error

// SetGlobalMitmRequestMiddlewareHook sets the middleware request hook for the MITM pipeline.
func SetGlobalMitmRequestMiddlewareHook(
	hook func(ctx context.Context, req *http.Request, containerName string) error,
) {
	GlobalMitmRequestMiddlewareHook = hook
	sniffing.GlobalMitmRequestMiddlewareHook = hook
}

// MitmResponseDecision controls the MITM response path.
// nil = passthrough.
type MitmResponseDecision struct {
	Block         bool
	StatusCode    int
	BlockBody     string
	NewStatusCode int
	NewHeaders    http.Header
	NewBody       []byte
}

// GlobalMitmResponseHook is called after upstream responds but before writing
// the response to the client. It can block or rewrite the response.
var GlobalMitmResponseHook func(
	ctx context.Context,
	info MitmRoundTripInfo,
) *MitmResponseDecision

// SetGlobalMitmResponseHook sets the middleware response hook for the MITM pipeline.
func SetGlobalMitmResponseHook(
	hook func(ctx context.Context, info MitmRoundTripInfo) *MitmResponseDecision,
) {
	GlobalMitmResponseHook = hook
	if hook == nil {
		sniffing.GlobalMitmResponseHook = nil
		return
	}
	sniffing.GlobalMitmResponseHook = func(ctx context.Context, info sniffing.HTTPRoundTripInfo) *sniffing.MitmResponseDecision {
		d := hook(ctx, MitmRoundTripInfo{
			RequestID:       info.RequestID,
			Host:            info.Host,
			Method:          info.Method,
			URI:             info.URI,
			Proto:           info.Proto,
			StatusCode:      info.StatusCode,
			RequestHeaders:  info.RequestHeaders,
			RequestBody:     info.RequestBody,
			ResponseHeaders: info.ResponseHeaders,
			ResponseBody:    info.ResponseBody,
			ContainerName:   info.ContainerName,
			DurationMs:      info.DurationMs,
		})
		if d == nil {
			return nil
		}
		return &sniffing.MitmResponseDecision{
			Block:         d.Block,
			StatusCode:    d.StatusCode,
			BlockBody:     d.BlockBody,
			NewStatusCode: d.NewStatusCode,
			NewHeaders:    d.NewHeaders,
			NewBody:       d.NewBody,
		}
	}
}
