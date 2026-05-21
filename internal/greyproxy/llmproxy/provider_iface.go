// provider_*.go define the abstract Backend surface every upstream LLM
// integration implements and the built-in factories (openai,
// openai-compat, openrouter, …). One Backend value per
// (provider_type, base_url, api_key) triple; instances are cheap to
// construct and re-used across requests.
//
// "Backend" rather than "Provider" because the latter is taken by the
// CRUD record type in crud.go — the two are intentionally separated:
// Provider lives in the database, Backend lives in the request hot path.
package llmproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Backend is the abstract surface every upstream LLM integration
// implements. Mirrors LiteLLM's BaseConfig
// (litellm/llms/base_llm/chat/transformation.py) but is intentionally
// narrower: five methods, no per-call config blob.
type Backend interface {
	// Name returns the provider type key (e.g. "openai", "anthropic").
	Name() string

	// Validate sanity-checks the configuration (api_key shape, base_url
	// reachability if cheap, etc.). Called at startup; not on the hot path.
	Validate() error

	// BuildRequest serialises the IR to an HTTP request ready to dispatch
	// at the upstream. The returned request carries auth headers and the
	// content body.
	BuildRequest(ctx context.Context, ir *ChatRequest, modelID string) (*http.Request, error)

	// ParseResponse decodes a non-streaming JSON body into the canonical
	// IR. Body is closed by the caller.
	ParseResponse(body []byte) (*ChatResponse, error)

	// ParseStream consumes an SSE stream, pushing events onto out. The
	// channel is NOT closed by ParseStream — the caller owns it.
	ParseStream(r io.Reader, out chan<- *StreamEvent) error
}

// BackendFactory builds a Backend from runtime config.
type BackendFactory func(baseURL, apiKey string, metadata map[string]string) (Backend, error)

var backendRegistry = map[string]BackendFactory{}

// RegisterBackend adds a backend factory under the given type key.
// Called from init() in each provider implementation file. Panics on
// duplicate keys to surface name collisions at startup.
func RegisterBackend(name string, f BackendFactory) {
	if _, dup := backendRegistry[name]; dup {
		panic("llmproxy: duplicate backend registration for " + name)
	}
	backendRegistry[name] = f
}

// BackendTypes returns the sorted list of registered backend type keys.
// The management API surfaces this through /api/llm/provider-types so
// the dashboard can populate the type dropdown.
func BackendTypes() []string {
	out := make([]string, 0, len(backendRegistry))
	for k := range backendRegistry {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// ErrUnknownBackendType is returned by NewBackend when the type key is
// not registered.
var ErrUnknownBackendType = errors.New("llmproxy: unknown backend type")

// NewBackend constructs a backend by type key.
func NewBackend(typ, baseURL, apiKey string, metadata map[string]string) (Backend, error) {
	f, ok := backendRegistry[typ]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownBackendType, typ)
	}
	return f(baseURL, apiKey, metadata)
}
