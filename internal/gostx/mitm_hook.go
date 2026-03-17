package gostx

import (
	"context"
	"net/http"

	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/sniffing"
)

// MitmRoundTripInfo contains decrypted HTTP request/response data from a MITM round-trip.
// This re-exports the internal sniffing type for use outside the gostx/internal package.
type MitmRoundTripInfo struct {
	Host            string
	Method          string
	URI             string
	Proto           string
	StatusCode      int
	RequestHeaders  http.Header
	RequestBody     []byte
	ResponseHeaders http.Header
	ResponseBody    []byte
	ContainerName   string
	DurationMs      int64
}

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
