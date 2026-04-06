package middleware

import "net/http"

// HelloMsg is sent by the proxy on connect and returned by middleware with hooks.
type HelloMsg struct {
	Type         string     `json:"type"`                    // "hello"
	Version      int        `json:"version,omitempty"`       // 1 (sent by proxy)
	Hooks        []HookSpec `json:"hooks,omitempty"`         // populated in response
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
}

// RequestMsg is sent for every intercepted HTTP request that passes filters.
type RequestMsg struct {
	Type      string      `json:"type"`      // "http-request"
	ID        string      `json:"id"`        // UUID correlation
	Host      string      `json:"host"`
	Method    string      `json:"method"`
	URI       string      `json:"uri"`
	Proto     string      `json:"proto"`
	Headers   http.Header `json:"headers"`
	Body      []byte      `json:"body"`      // JSON marshaller encodes as base64; null if over max_body_bytes
	Container string      `json:"container"`
	TLS       bool        `json:"tls"`
}

// ResponseMsg is sent after upstream responds. Includes full original request
// context so the middleware can correlate (e.g., "what prompt generated this?").
type ResponseMsg struct {
	Type            string      `json:"type"`             // "http-response"
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
	Type       string      `json:"type"`                  // "decision"
	ID         string      `json:"id"`
	Action     string      `json:"action"`                // allow|deny|rewrite|passthrough|block
	StatusCode int         `json:"status_code,omitempty"` // for deny/block
	Body       []byte      `json:"body,omitempty"`        // for deny/block/rewrite
	Headers    http.Header `json:"headers,omitempty"`     // for rewrite
}

// Config holds configuration for the middleware WebSocket client.
type Config struct {
	URL          string `yaml:"url" json:"url"`
	TimeoutMs    int    `yaml:"timeout_ms" json:"timeout_ms"`
	OnDisconnect string `yaml:"on_disconnect" json:"on_disconnect"` // "allow"|"deny"
	AuthHeader   string `yaml:"auth_header" json:"auth_header"`
}
