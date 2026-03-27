package greyproxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// buildTestDockerClient returns an *http.Client whose requests are always routed
// to the given test server, regardless of the URL host. This lets us test the
// DockerResolver against a plain TCP httptest.Server instead of a Unix socket.
func buildTestDockerClient(server *httptest.Server) *http.Client {
	addr := server.Listener.Addr().String()
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			},
		},
		Timeout: 5 * time.Second,
	}
}

func makeContainerJSON(id, name, network, ip string) map[string]any {
	return map[string]any{
		"Id":    id,
		"Names": []string{"/" + name},
		"NetworkSettings": map[string]any{
			"Networks": map[string]any{
				network: map[string]any{
					"IPAddress": ip,
				},
			},
		},
	}
}

func TestDockerResolverResolveIPFound(t *testing.T) {
	containers := []any{
		makeContainerJSON("abc123def456789", "internalai-myapp-1", "iai_proxy", "172.17.0.2"),
		makeContainerJSON("def456abc123789", "internalai-other-1", "iai_proxy", "172.17.0.3"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(containers)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 1*time.Second)

	name, id := resolver.ResolveIP("172.17.0.2")
	if name != "internalai-myapp-1" {
		t.Errorf("got name %q, want %q", name, "internalai-myapp-1")
	}
	if id != "abc123def456" {
		t.Errorf("got id %q, want %q", id, "abc123def456")
	}
}

func TestDockerResolverResolveIPNotFound(t *testing.T) {
	containers := []any{
		makeContainerJSON("abc123def456789", "internalai-myapp-1", "iai_proxy", "172.17.0.2"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(containers)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 1*time.Second)

	name, id := resolver.ResolveIP("10.0.0.99")
	if name != "" || id != "" {
		t.Errorf("expected empty result for unknown IP, got name=%q id=%q", name, id)
	}
}

func TestDockerResolverNilReceiver(t *testing.T) {
	var r *DockerResolver
	name, id := r.ResolveIP("172.17.0.2")
	if name != "" || id != "" {
		t.Errorf("nil receiver should return empty strings, got name=%q id=%q", name, id)
	}
}

func TestDockerResolverEmptyIP(t *testing.T) {
	resolver := newDockerResolverWithClient(http.DefaultClient, 1*time.Second)
	name, id := resolver.ResolveIP("")
	if name != "" || id != "" {
		t.Errorf("empty IP should return empty strings, got name=%q id=%q", name, id)
	}
}

func TestDockerResolverCaching(t *testing.T) {
	callCount := 0
	containers := []any{
		makeContainerJSON("abc123def456789", "myapp", "bridge", "10.0.0.1"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(containers)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 10*time.Second)

	// First call — should hit Docker API.
	resolver.ResolveIP("10.0.0.1")
	if callCount != 1 {
		t.Fatalf("expected 1 API call, got %d", callCount)
	}

	// Second call — should use cache.
	resolver.ResolveIP("10.0.0.1")
	if callCount != 1 {
		t.Errorf("expected cache hit (1 API call total), got %d", callCount)
	}
}

func TestDockerResolverCacheExpiry(t *testing.T) {
	callCount := 0
	containers := []any{
		makeContainerJSON("abc123def456789", "myapp", "bridge", "10.0.0.1"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(containers)
	}))
	defer server.Close()

	// Very short TTL so we can test expiry.
	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 1*time.Millisecond)

	resolver.ResolveIP("10.0.0.1")
	time.Sleep(5 * time.Millisecond)
	resolver.ResolveIP("10.0.0.1")

	if callCount != 2 {
		t.Errorf("expected 2 API calls after cache expiry, got %d", callCount)
	}
}

func TestDockerResolverMultipleNetworks(t *testing.T) {
	// Container with IPs on multiple networks.
	containers := []any{
		map[string]any{
			"Id":    "abc123def456789",
			"Names": []string{"/multi-net-container"},
			"NetworkSettings": map[string]any{
				"Networks": map[string]any{
					"network-a": map[string]any{"IPAddress": "172.18.0.2"},
					"network-b": map[string]any{"IPAddress": "172.19.0.5"},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(containers)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 1*time.Second)

	// Both IPs should resolve to the same container.
	name1, _ := resolver.ResolveIP("172.18.0.2")
	name2, _ := resolver.ResolveIP("172.19.0.5")

	if name1 != "multi-net-container" {
		t.Errorf("IP on network-a: got %q, want %q", name1, "multi-net-container")
	}
	if name2 != "multi-net-container" {
		t.Errorf("IP on network-b: got %q, want %q", name2, "multi-net-container")
	}
}

func TestDockerResolverStripsLeadingSlash(t *testing.T) {
	containers := []any{
		makeContainerJSON("abc123def456789", "my-service", "bridge", "10.0.0.1"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(containers)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 1*time.Second)

	name, _ := resolver.ResolveIP("10.0.0.1")
	if name != "my-service" {
		t.Errorf("expected leading slash stripped, got %q", name)
	}
}

func TestDockerResolverIDTruncatedTo12(t *testing.T) {
	containers := []any{
		makeContainerJSON("abcdefghijklmnopqrstuvwxyz", "myapp", "bridge", "10.0.0.1"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(containers)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 1*time.Second)

	_, id := resolver.ResolveIP("10.0.0.1")
	if len(id) != 12 {
		t.Errorf("expected ID length 12, got %d (%q)", len(id), id)
	}
}

func TestDockerResolverMissNotCached(t *testing.T) {
	callCount := 0
	containers := &[]any{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(*containers)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 10*time.Second)

	// First call — no match.
	name, _ := resolver.ResolveIP("10.0.0.1")
	if name != "" {
		t.Fatalf("expected miss, got %q", name)
	}

	// Container starts.
	*containers = []any{
		makeContainerJSON("abc123def456789", "late-starter", "bridge", "10.0.0.1"),
	}

	// Second call — miss was not cached, so Docker is queried again and finds the container.
	name, _ = resolver.ResolveIP("10.0.0.1")
	if callCount != 2 {
		t.Errorf("expected 2 API calls (miss not cached), got %d", callCount)
	}
	if name != "late-starter" {
		t.Errorf("expected container discovered immediately after miss, got %q", name)
	}
}

func TestDockerResolverAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	resolver := newDockerResolverWithClient(buildTestDockerClient(server), 1*time.Second)

	// 500 response body is plain text, not JSON — parse error → empty result.
	name, id := resolver.ResolveIP("10.0.0.1")
	if name != "" || id != "" {
		t.Errorf("expected empty result on API error, got name=%q id=%q", name, id)
	}
}
