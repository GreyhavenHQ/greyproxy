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
}

// NotificationsConfig controls OS desktop notifications for pending requests.
type NotificationsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
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
