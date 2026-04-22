package greyproxy

import "time"

// Config holds configuration for the embedded proxy API service.
type Config struct {
	Addr          string              `yaml:"addr" json:"addr"`
	PathPrefix    string              `yaml:"pathPrefix" json:"pathPrefix"`
	DB            string              `yaml:"db" json:"db"`
	Auther        string              `yaml:"auther" json:"auther"`
	Admission     string              `yaml:"admission" json:"admission"`
	Bypass        string              `yaml:"bypass" json:"bypass"`
	Resolver      string              `yaml:"resolver" json:"resolver"`
	Notifications NotificationsConfig `yaml:"notifications" json:"notifications"`
	Docker        DockerConfig        `yaml:"docker" json:"docker"`
	Middlewares   []MiddlewareConfig  `yaml:"middlewares,omitempty" json:"middlewares,omitempty"`
}

// NotificationsConfig controls OS desktop notifications for pending requests.
type NotificationsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// MiddlewareConfig holds configuration for one external middleware.
// Multiple entries cascade in declaration order: each middleware sees the
// previous one's output as its input; deny/block short-circuits the chain.
//
// Exactly one of URL or Command must be set:
//
//   - URL opens a WebSocket to an already-running middleware.
//   - Command launches a child process whose stdin/stdout speak NDJSON.
//     Preferred for local middlewares — greyproxy owns the lifecycle.
type MiddlewareConfig struct {
	URL          string   `yaml:"url,omitempty" json:"url,omitempty"`
	Command      []string `yaml:"command,omitempty" json:"command,omitempty"`
	Name         string   `yaml:"name,omitempty" json:"name,omitempty"`
	TimeoutMs    int      `yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
	OnDisconnect string   `yaml:"on_disconnect,omitempty" json:"on_disconnect,omitempty"` // "allow"|"deny"
	AuthHeader   string   `yaml:"auth_header,omitempty" json:"auth_header,omitempty"`
}

// MiddlewareStatus is a read-only snapshot of one middleware client's state,
// shaped for the UI and API (which live outside the middleware package).
// cmd/greyproxy builds these from the live clients on each request to the
// /api/middlewares endpoint, so the list is always fresh — no event bus,
// no cache invalidation.
type MiddlewareStatus struct {
	URL             string   `json:"url"`  // ws://... or "stdio:<cmd>"
	Kind            string   `json:"kind"` // "ws" | "stdio"
	Name            string   `json:"name,omitempty"`
	Connected       bool     `json:"connected"`
	ProtocolVersion int      `json:"protocol_version,omitempty"`
	Hooks           []string `json:"hooks,omitempty"` // "http-request" / "http-response"
	MaxBodyBytes    int64    `json:"max_body_bytes,omitempty"`
	TimeoutMs       int      `json:"timeout_ms"`
	OnDisconnect    string   `json:"on_disconnect"`
}

// DockerConfig enables optional Docker socket integration for resolving container
// IP addresses to container names. When enabled, the bypass plugin uses the Docker
// API to map source IPs to the actual container name, producing more meaningful
// ACL rule matching (e.g. "docker-backend-1" instead of "unknown-172.17.0.2").
type DockerConfig struct {
	// Enabled controls whether Docker socket resolution is active.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Socket is the path to the Docker/Podman socket. Defaults to /var/run/docker.sock.
	Socket string `yaml:"socket" json:"socket"`
	// CacheTTL controls how long resolved container names are cached.
	// Accepts Go duration strings (e.g. "30s", "1m"). Defaults to 30s.
	CacheTTL time.Duration `yaml:"cacheTTL" json:"cacheTTL"`
}
