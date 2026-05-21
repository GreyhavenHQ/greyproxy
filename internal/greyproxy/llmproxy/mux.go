package llmproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Server is the path-prefix mux for the LLM gateway. The gostx handler
// (internal/gostx/handler/llmproxy/) forwards every accepted connection
// to an http.Server whose handler is this Server. It can also be tested
// directly via httptest.
//
// OpenAI dialect lives at the root; every other dialect will mount under
// /<dialect>/ in subsequent phases (Phase 2 adds /anthropic/).
type Server struct {
	store  *Store
	router Router

	// Client is the http.Client used to dispatch upstream calls. Tests
	// override this; production uses a long-lived one.
	Client *http.Client
}

// NewServer constructs a Server wired to the given Store and Router.
func NewServer(store *Store, router Router) *Server {
	return &Server{
		store:  store,
		router: router,
		Client: &http.Client{Timeout: 5 * time.Minute},
	}
}

// ServeHTTP dispatches inbound HTTP requests to the per-dialect handler.
// Path matching is intentionally explicit (no third-party router) — the
// surface is small and a tagged switch keeps the dispatch table readable.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		// Lightweight CORS preflight; the proxy is intended for local-only
		// use by default. Operators can put a reverse proxy in front for
		// real CORS policy.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := r.URL.Path
	switch {
	case path == "/healthz" && r.Method == http.MethodGet:
		s.handleHealthz(w, r)
	case path == "/v1/chat/completions" && r.Method == http.MethodPost:
		s.handleOpenAIChat(w, r)
	case path == "/v1/models" && r.Method == http.MethodGet:
		s.handleListModels(w, r)
	case strings.HasPrefix(path, "/v1/models/") && r.Method == http.MethodGet:
		s.handleGetModel(w, r, strings.TrimPrefix(path, "/v1/models/"))
	default:
		EncodeOpenAIChatError(w, http.StatusNotFound, "route_not_found",
			fmt.Sprintf("route not found: %s %s", r.Method, path))
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleListModels(w http.ResponseWriter, _ *http.Request) {
	aliases, err := s.store.ListAliases()
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	ids := make([]string, 0, len(aliases))
	for _, a := range aliases {
		if a.Enabled {
			ids = append(ids, a.Name)
		}
	}
	if err := EncodeOpenAIModelsList(w, ids); err != nil {
		// Headers already sent in most cases; log via response anyway.
		_, _ = w.Write([]byte(`{"error":{"message":"encode list","type":"server_error"}}`))
	}
}

func (s *Server) handleGetModel(w http.ResponseWriter, _ *http.Request, name string) {
	a, err := s.store.GetAliasByName(name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			EncodeOpenAIChatError(w, http.StatusNotFound, "model_not_found",
				fmt.Sprintf("model %q not found", name))
			return
		}
		EncodeOpenAIChatError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	if !a.Enabled {
		EncodeOpenAIChatError(w, http.StatusNotFound, "model_not_found",
			fmt.Sprintf("model %q is disabled", name))
		return
	}
	_ = EncodeOpenAIModel(w, name)
}

// handleOpenAIChat is the Phase 1 hot path: decode wire body, resolve
// alias, build upstream request via Provider, send, re-encode response.
func (s *Server) handleOpenAIChat(w http.ResponseWriter, r *http.Request) {
	ir, err := DecodeOpenAIChat(r)
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if ir.Model == "" {
		EncodeOpenAIChatError(w, http.StatusBadRequest, "model_required",
			"request is missing the model field")
		return
	}

	resolved, err := s.router.Resolve(r.Context(), ir)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			EncodeOpenAIChatError(w, http.StatusNotFound, "alias_unknown",
				fmt.Sprintf("unknown model alias %q", ir.Model))
		case errors.Is(err, ErrDisabled):
			EncodeOpenAIChatError(w, http.StatusUnprocessableEntity, "alias_disabled",
				err.Error())
		default:
			EncodeOpenAIChatError(w, http.StatusInternalServerError, "resolve_error",
				err.Error())
		}
		return
	}

	secret, err := s.store.GetProviderSecret(resolved.Provider.ID)
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusInternalServerError, "secret_error", err.Error())
		return
	}

	prov, err := NewBackend(resolved.Provider.Type, resolved.Provider.BaseURL, secret, resolved.Provider.Metadata)
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusUnprocessableEntity, "provider_type_unknown", err.Error())
		return
	}

	// Phase 1 ignores ir.Stream — we always proxy as non-streaming and
	// re-encode in the inbound dialect. Streaming SSE lands in Phase 2.
	ir.Stream = false

	upReq, err := prov.BuildRequest(r.Context(), ir, resolved.ModelID)
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusInternalServerError, "build_request_error", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	upReq = upReq.WithContext(ctx)

	upResp, err := s.Client.Do(upReq)
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	defer func() { _ = upResp.Body.Close() }()

	body, err := io.ReadAll(upResp.Body)
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusBadGateway, "upstream_read_error", err.Error())
		return
	}

	if upResp.StatusCode >= 400 {
		// Surface the upstream's status. Keep the OpenAI-shaped error
		// envelope since the inbound dialect was openai-chat.
		EncodeOpenAIChatError(w, http.StatusBadGateway, "upstream_status",
			fmt.Sprintf("upstream returned %d: %s", upResp.StatusCode, truncate(string(body), 500)))
		return
	}

	chatResp, err := prov.ParseResponse(body)
	if err != nil {
		EncodeOpenAIChatError(w, http.StatusBadGateway, "parse_response_error", err.Error())
		return
	}

	// Stamp the alias back as the visible model id so clients see what
	// they asked for, not the resolved backend id. Mirrors how LiteLLM
	// reflects the model_list alias back.
	visibleModel := chatResp.Model
	if visibleModel == "" {
		visibleModel = resolved.ModelID
	}
	chatResp.Model = visibleModel

	if err := EncodeOpenAIChat(w, chatResp); err != nil {
		// Body already partially written; nothing to do but log via tests.
		_ = err
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
