package middleware

import (
	"net/http"
	"regexp"
	"sync"
)

// HelloMsg is the hello exchange on both sides.
//
// Proxy → middleware:
//
//	{"type":"hello","version":<current>}
//
// Middleware → proxy:
//
//	{"type":"hello","min_version":1,"max_version":1,"name":"...","hooks":[...]}
//
// Version negotiation: the proxy picks the highest integer in the overlap
// of [middleware.MinVersion, middleware.MaxVersion] and [1, ProtocolVersion].
// If there is no overlap the connection is refused with a readable error.
// A middleware that omits both version bounds is assumed to speak v1, so
// existing v1 middlewares keep working unchanged as the proxy evolves.
type HelloMsg struct {
	Type    string `json:"type"`              // "hello"
	Version int    `json:"version,omitempty"` // current protocol version the proxy is speaking
	// MinVersion and MaxVersion are set by the *middleware* in its hello
	// response to declare the inclusive range of protocol versions it
	// supports. Both zero means "assume v1" for backwards compatibility.
	MinVersion int `json:"min_version,omitempty"`
	MaxVersion int `json:"max_version,omitempty"`
	// Name is an optional human-friendly identifier the middleware returns
	// in its hello response. Displayed in the greyproxy Activity view
	// alongside middleware events. If empty, the middleware URL is used.
	Name         string     `json:"name,omitempty"`
	Hooks        []HookSpec `json:"hooks,omitempty"`          // populated in response
	MaxBodyBytes int64      `json:"max_body_bytes,omitempty"` // 0 = no limit
}

// HookSpec declares a hook the middleware wants, with optional filters.
type HookSpec struct {
	Type    string      `json:"type"`              // "http-request" or "http-response"
	Filters *HookFilter `json:"filters,omitempty"` // nil = receive everything
}

// HookFilter controls which requests/responses are sent to the middleware.
// Within a field: OR (any match). Across fields: AND (all must match).
// Absent/empty field = matches everything.
type HookFilter struct {
	Host        []string `json:"host,omitempty"`         // glob: *.openai.com
	Path        []string `json:"path,omitempty"`         // regex: /v1/.*
	Method      []string `json:"method,omitempty"`       // exact: POST, PUT
	ContentType []string `json:"content_type,omitempty"` // glob: application/json, text/*
	Container   []string `json:"container,omitempty"`    // glob: my-app-*
	TLS         *bool    `json:"tls,omitempty"`          // nil = both; true = HTTPS only
	// LLM gates on whether the proxy's endpoint registry currently resolves
	// a decoder for this request. nil = don't care, true = LLM only,
	// false = non-LLM only. Lets middleware subscribe to "LLM traffic"
	// without duplicating greyproxy's endpoint→decoder mapping.
	LLM *bool `json:"llm,omitempty"`

	// compiled is populated lazily by compiledPaths() on first match and
	// kept for the lifetime of the HookFilter. Storing it inline avoids
	// the global `map[*HookFilter]*compiledFilter` cache the earlier
	// implementation used, which leaked on every reconnect because each
	// hello response produced a fresh filter pointer.
	compileOnce sync.Once
	compiled    []*regexp.Regexp
}

// RequestMsg is sent for every intercepted HTTP request that passes filters.
type RequestMsg struct {
	Type      string      `json:"type"` // "http-request"
	ID        string      `json:"id"`   // UUID correlation
	Host      string      `json:"host"`
	Method    string      `json:"method"`
	URI       string      `json:"uri"`
	Proto     string      `json:"proto"`
	Headers   http.Header `json:"headers"`
	Body      []byte      `json:"body"` // JSON marshaller encodes as base64; null if over max_body_bytes
	Container string      `json:"container"`
	TLS       bool        `json:"tls"`
}

// ResponseMsg is sent after upstream responds. Includes full original request
// context so the middleware can correlate (e.g., "what prompt generated this?").
type ResponseMsg struct {
	Type            string      `json:"type"` // "http-response"
	ID              string      `json:"id"`
	Host            string      `json:"host"`
	Method          string      `json:"method"`
	URI             string      `json:"uri"`
	StatusCode      int         `json:"status_code"`
	RequestHeaders  http.Header `json:"request_headers"`
	RequestBody     []byte      `json:"request_body"`
	ResponseHeaders http.Header `json:"response_headers"`
	ResponseBody    []byte      `json:"response_body"`
	Container       string      `json:"container"`
	DurationMs      int64       `json:"duration_ms"`
}

// Decision is returned by the middleware for both request and response hooks.
type Decision struct {
	Type       string      `json:"type"` // "decision"
	ID         string      `json:"id"`
	Action     string      `json:"action"`                // allow|deny|rewrite|passthrough|block
	StatusCode int         `json:"status_code,omitempty"` // for deny/block
	Body       []byte      `json:"body,omitempty"`        // for deny/block/rewrite
	Headers    http.Header `json:"headers,omitempty"`     // for rewrite
	// Tags is a structlog-style bag the middleware can emit on any action,
	// including allow/passthrough. Keys are middleware-defined; greyproxy
	// preserves them verbatim per middleware (no cross-middleware merging)
	// so that two middlewares emitting the same key never clobber each other.
	Tags map[string]any `json:"tags,omitempty"`
	// Fallback is set when this Decision was synthesised locally because
	// the middleware could not respond (disconnected, timeout, write error,
	// context cancel). Never sent or received over the wire; kept in-process
	// so cascades can log *why* the default action was applied.
	Fallback string `json:"-"`
}

// Config holds configuration for one middleware client. Exactly one of
// URL or Command must be non-empty:
//
//   - URL connects over WebSocket to an already-running middleware, good
//     for shared services and remote deployments.
//   - Command launches a child process owned by greyproxy and talks to
//     it over stdin/stdout NDJSON. Preferred for local, single-host
//     middlewares because the operator doesn't have to manage ports,
//     PIDs, or a separate start command.
//
// Name is optional but recommended; it's used in log prefixes for a
// stdio middleware's stderr forwarding, before the middleware has a
// chance to declare its own name in the hello exchange.
type Config struct {
	URL          string   `yaml:"url,omitempty" json:"url,omitempty"`
	Command      []string `yaml:"command,omitempty" json:"command,omitempty"`
	Name         string   `yaml:"name,omitempty" json:"name,omitempty"`
	TimeoutMs    int      `yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
	OnDisconnect string   `yaml:"on_disconnect,omitempty" json:"on_disconnect,omitempty"` // "allow"|"deny"
	AuthHeader   string   `yaml:"auth_header,omitempty" json:"auth_header,omitempty"`
}
