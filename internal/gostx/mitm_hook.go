package gostx

import (
	"context"
	"net/http"

	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/sniffing"
)

// MitmRoundTripInfo contains decrypted HTTP request/response data from a MITM round-trip.
// This re-exports the internal sniffing type for use outside the gostx/internal package.
type MitmRoundTripInfo struct {
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
	PIIRedacted            []string
	PIIRedactCount         int
}

// PIIFilterResult re-exports the internal sniffing PII filter result type.
type PIIFilterResult = sniffing.PIIFilterResult

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
			PIIRedacted:            info.PIIRedacted,
			PIIRedactCount:         info.PIIRedactCount,
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

// SetGlobalPIIFilter sets a global callback that scans and redacts PII from HTTP request bodies
// before they are forwarded upstream. The hook receives the raw body and content type, and returns
// a result with the redacted body, or an error to block the request entirely.
func SetGlobalPIIFilter(hook func(body []byte, contentType string) (*PIIFilterResult, error)) {
	sniffing.SetGlobalPIIFilter(hook)
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
