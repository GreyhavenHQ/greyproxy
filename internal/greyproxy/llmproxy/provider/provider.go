// Package provider defines the abstraction over upstream LLM backends
// and ships the built-in implementations (openai, anthropic, openai-compat,
// openrouter). One Provider value per (provider_type, base_url, api_key)
// triple; instances are cheap to construct and can be re-used across
// requests.
package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
)

// Provider is the abstract surface every upstream backend implements. It
// mirrors LiteLLM's BaseConfig (litellm/llms/base_llm/chat/transformation.py)
// but is intentionally narrower: five methods, no streaming/non-streaming
// branch in the same call, no per-call config blob.
type Provider interface {
	// Name returns the provider type key (e.g. "openai", "anthropic").
	Name() string

	// Validate sanity-checks the configuration (api_key shape, base_url
	// reachability if cheap, etc.). Called at startup; not on the hot path.
	Validate() error

	// BuildRequest serialises the IR to an HTTP request ready to dispatch
	// at the upstream. The returned request carries auth headers and the
	// content body.
	BuildRequest(ctx context.Context, ir *llmproxy.ChatRequest, modelID string) (*http.Request, error)

	// ParseResponse decodes a non-streaming JSON body into the canonical
	// IR. Body is closed by the caller.
	ParseResponse(body []byte) (*llmproxy.ChatResponse, error)

	// ParseStream consumes an SSE stream, pushing events onto out. The
	// channel is NOT closed by ParseStream — the caller owns it.
	ParseStream(r io.Reader, out chan<- *llmproxy.StreamEvent) error
}

// Factory builds a provider from runtime config.
type Factory func(baseURL, apiKey string, metadata map[string]string) (Provider, error)

var registry = map[string]Factory{}

// Register adds a provider factory under the given type key. Called from
// init() in each provider implementation file. Panics on duplicate keys
// to surface name collisions at startup.
func Register(name string, f Factory) {
	if _, dup := registry[name]; dup {
		panic("llmproxy/provider: duplicate registration for " + name)
	}
	registry[name] = f
}

// Types returns the sorted list of registered provider type keys. The
// management API surfaces this through /api/llm/provider-types so the
// dashboard can populate the type dropdown.
func Types() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	// stable order for deterministic API output
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// ErrUnknownType is returned by New when the type key is not registered.
var ErrUnknownType = errors.New("llmproxy/provider: unknown type")

// New constructs a provider by type key.
func New(typ, baseURL, apiKey string, metadata map[string]string) (Provider, error) {
	f, ok := registry[typ]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, typ)
	}
	return f(baseURL, apiKey, metadata)
}
