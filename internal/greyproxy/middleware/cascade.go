package middleware

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"net/http"
)

// CascadeHook describes one middleware participating in a cascade. The cmd
// layer builds these once at startup; the cascade runners below consume them.
type CascadeHook struct {
	Client  *Client
	URL     string
	Name    string // friendly name from hello, may be ""
	Filters *HookFilter
}

// forbiddenRewriteHeaders lists header names a middleware is NOT allowed to
// set or override via a rewrite decision. These fall into two groups:
//
//   - Hop-by-hop headers (RFC 7230 §6.1): semantically invalid to forward
//     past the proxy, and Go's http stack strips most of these anyway.
//   - Credential / identity headers: a middleware overwriting these could
//     silently escalate or strip authentication. An operator who wants to
//     mutate auth should do it in a dedicated, auditable middleware and
//     opt in explicitly; the default rewrite path refuses.
var forbiddenRewriteHeaders = map[string]struct{}{
	// Hop-by-hop
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	// Credentials & identity (can't be forged by a middleware via rewrite)
	"Authorization": {},
	"Cookie":        {},
	"Set-Cookie":    {},
	"Host":          {},
}

// MergeRewriteHeaders copies every (k, v) from src into dst, skipping keys
// listed in forbiddenRewriteHeaders. Returns the header names that were
// actually written (for event stashing / diffing) and the ones that were
// rejected so the cascade caller can warn.
//
// The *unsafe* path that the original cascade used — `dst[k] = v` — let any
// middleware overwrite Authorization or Host. This helper is the scoped
// replacement and is the only place the cascade should mutate headers
// from a middleware decision.
func MergeRewriteHeaders(dst http.Header, src http.Header) (applied, rejected []string) {
	for k, v := range src {
		canonical := http.CanonicalHeaderKey(k)
		if _, forbidden := forbiddenRewriteHeaders[canonical]; forbidden {
			rejected = append(rejected, canonical)
			continue
		}
		dst[canonical] = v
		applied = append(applied, canonical)
	}
	return applied, rejected
}

// NewID returns a fresh 128-bit hex id suitable for correlating a Send with
// its Decision. Not RFC 4122 UUID-formatted on purpose: the middleware
// protocol doesn't care about the v4 layout, and plain hex is cheaper.
func NewID() string {
	var buf [16]byte
	_, _ = cryptorand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// requestBodyCtxKey threads the request body captured in the request hook
// through to the response hook so the plain-HTTP response cascade can fill
// ResponseMsg.RequestBody. ctx-based threading keeps the hook signatures
// stable and avoids a separate map keyed by request ID.
type requestBodyCtxKey struct{}

// WithRequestBody stores body on ctx under an unexported key.
func WithRequestBody(ctx context.Context, body []byte) context.Context {
	return context.WithValue(ctx, requestBodyCtxKey{}, body)
}

// RequestBodyFromContext returns the body stored by WithRequestBody, or nil.
func RequestBodyFromContext(ctx context.Context) []byte {
	body, _ := ctx.Value(requestBodyCtxKey{}).([]byte)
	return body
}

// ActionForTimeoutKind reports the Action the fallback path would pick
// given (onTimeout policy, isResponse). Exposed for tests.
func ActionForTimeoutKind(onTimeout string, isResponse bool) string {
	switch onTimeout {
	case "allow":
		if isResponse {
			return "passthrough"
		}
		return "allow"
	default:
		if isResponse {
			return "block"
		}
		return "deny"
	}
}

// IsKnownAction reports whether action is one the cascade recognises.
// Unknown actions fall through to allow/passthrough but the caller logs
// a warning — one typo in a middleware author's code should not silently
// bypass policy.
func IsKnownAction(action string) bool {
	switch action {
	case "allow", "deny", "rewrite", "passthrough", "block":
		return true
	}
	return false
}

// BodyChanged reports whether newBody actually differs from oldBody.
// A nil newBody means "no rewrite", never "empty body".
func BodyChanged(oldBody, newBody []byte) bool {
	if newBody == nil {
		return false
	}
	return !bytes.Equal(oldBody, newBody)
}
