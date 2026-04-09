package greyproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DockerResolver resolves container IP addresses to container names
// by querying the Docker daemon via its Unix socket API.
// All methods are safe to call on a nil receiver (returns empty strings).
type DockerResolver struct {
	client   *http.Client
	mu       sync.RWMutex
	cache    map[string]dockerCacheEntry
	cacheTTL time.Duration
}

type dockerCacheEntry struct {
	containerName string
	containerID   string
	expiresAt     time.Time
}

// dockerContainerSummary parses the relevant fields from Docker's /containers/json response.
type dockerContainerSummary struct {
	ID              string   `json:"Id"`
	Names           []string `json:"Names"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// NewDockerResolver creates a resolver that connects to the Docker daemon at socketPath.
// cacheTTL controls how long resolved entries are cached. Pass 0 to use the default (30s).
func NewDockerResolver(socketPath string, cacheTTL time.Duration) *DockerResolver {
	if cacheTTL == 0 {
		cacheTTL = 30 * time.Second
	}
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}

	return &DockerResolver{
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
		cache:    make(map[string]dockerCacheEntry),
		cacheTTL: cacheTTL,
	}
}

// newDockerResolverWithClient creates a DockerResolver with a custom HTTP client.
// Used in tests to inject a mock server.
func newDockerResolverWithClient(client *http.Client, cacheTTL time.Duration) *DockerResolver {
	if cacheTTL == 0 {
		cacheTTL = 30 * time.Second
	}
	return &DockerResolver{
		client:   client,
		cache:    make(map[string]dockerCacheEntry),
		cacheTTL: cacheTTL,
	}
}

// ResolveIP returns the name and short ID of the running container whose network interface
// has the given IP address. Returns ("", "") if no match is found or on error.
// Safe to call on a nil receiver.
func (r *DockerResolver) ResolveIP(ip string) (containerName, containerID string) {
	if r == nil || ip == "" {
		return "", ""
	}

	// Check cache first.
	r.mu.RLock()
	if entry, ok := r.cache[ip]; ok && time.Now().Before(entry.expiresAt) {
		r.mu.RUnlock()
		return entry.containerName, entry.containerID
	}
	r.mu.RUnlock()

	// Query Docker API.
	name, id, err := r.queryDockerForIP(ip)
	if err != nil {
		// Don't cache errors so the next call can retry.
		return "", ""
	}

	// Only cache successful lookups. Misses are not cached so that a container
	// starting after a miss is discovered on the very next request.
	if name == "" {
		return "", ""
	}
	r.mu.Lock()
	r.cache[ip] = dockerCacheEntry{
		containerName: name,
		containerID:   id,
		expiresAt:     time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()

	return name, id
}

func (r *DockerResolver) queryDockerForIP(ip string) (containerName, containerID string, err error) {
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"http://docker/containers/json", nil,
	)
	if err != nil {
		return "", "", fmt.Errorf("create request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("docker api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read response: %w", err)
	}

	var containers []dockerContainerSummary
	if err := json.Unmarshal(body, &containers); err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}

	for _, c := range containers {
		for _, net := range c.NetworkSettings.Networks {
			if net.IPAddress == ip {
				name := containerNameFromDocker(c)
				id := c.ID
				if len(id) > 12 {
					id = id[:12]
				}
				return name, id, nil
			}
		}
	}

	return "", "", nil
}

// containerNameFromDocker returns a clean container name, stripping the leading "/" Docker adds.
func containerNameFromDocker(c dockerContainerSummary) string {
	if len(c.Names) == 0 {
		if len(c.ID) > 12 {
			return c.ID[:12]
		}
		return c.ID
	}
	return strings.TrimPrefix(c.Names[0], "/")
}
