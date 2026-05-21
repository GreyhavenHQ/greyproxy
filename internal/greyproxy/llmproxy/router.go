package llmproxy

import (
	"context"
)

// Router resolves an incoming ChatRequest to the (provider, model) pair
// that will actually serve it. Phase 1 is alias-lookup only; Phase 3
// layers in redirect rules (`inbound_shape`, `model` globs), Phase 5
// adds auto-routing on top.
//
// The interface is small enough that the gateway can swap in a stub in
// tests without touching DB plumbing.
type Router interface {
	Resolve(ctx context.Context, ir *ChatRequest) (*ResolvedAlias, error)
}

// StoreRouter is the production Router: it consults the SQLite-backed
// alias table via Store.
type StoreRouter struct {
	store *Store
}

// NewStoreRouter builds a Router that reads from the given Store.
func NewStoreRouter(s *Store) *StoreRouter {
	return &StoreRouter{store: s}
}

// Resolve maps ir.Model (a public alias name) to a ResolvedAlias.
// Returns ErrNotFound when the alias does not exist; ErrDisabled when
// either the alias or its provider is disabled.
func (r *StoreRouter) Resolve(_ context.Context, ir *ChatRequest) (*ResolvedAlias, error) {
	return r.store.ResolveAlias(ir.Model)
}
