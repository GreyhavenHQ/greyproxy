package llmproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/handler"
	mdata "github.com/greyhavenhq/greyproxy/internal/gostcore/metadata"
	greylp "github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
)

func init() {
	registry.HandlerRegistry().Register("llmproxy", NewHandler)
}

// llmproxyHandler bridges a gostx TCP service into the in-process LLM
// gateway. On Init() it spins up an http.Server backed by a chanListener
// and a Handle() call simply forwards the accepted conn into that
// listener.
type llmproxyHandler struct {
	options handler.Options
	md      metadata

	mu       sync.Mutex
	listener *chanListener
	httpSrv  *http.Server
	started  bool
}

// NewHandler is the factory wired into the gostx HandlerRegistry by
// init(). gostx's loader passes the per-service Options (auther,
// logger, service name, etc.).
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &llmproxyHandler{options: options}
}

// Init parses metadata and starts the embedded http.Server. Returns an
// error if no LLM gateway is registered (greyproxy.yml has the service
// entry but `llm:` is missing in the config — easy to overlook).
func (h *llmproxyHandler) Init(md mdata.Metadata) error {
	h.md = parseMetadata(md)

	gateway := greylp.GlobalHandler()
	if gateway == nil {
		return errors.New("llmproxy handler: no LLM gateway registered " +
			"(check that the `llm:` config block is present)")
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started {
		return nil
	}

	h.listener = newChanListener(loopbackAddr{})

	mux := http.NewServeMux()
	// Wrap the gateway with an inbound auth filter if the operator
	// flipped auth.require=true. The bearer-key check is tiny — keeping
	// it here rather than in the gateway lets non-auth tests run the
	// gateway directly without going through the handler.
	final := withInboundAuth(gateway, h.md)
	mux.Handle("/", final)

	h.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		// No write timeout: streaming SSE responses can be long-lived.
	}
	go func() {
		// Ignore http.ErrServerClosed; that's the normal shutdown path.
		_ = h.httpSrv.Serve(h.listener)
	}()
	h.started = true
	return nil
}

// Handle pushes the accepted connection into the chanListener so the
// embedded http.Server can drive its HTTP read loop. Returns once the
// listener has accepted the conn — the http.Server takes ownership.
func (h *llmproxyHandler) Handle(_ context.Context, conn net.Conn, _ ...handler.HandleOption) error {
	h.mu.Lock()
	l := h.listener
	h.mu.Unlock()
	if l == nil {
		_ = conn.Close()
		return fmt.Errorf("llmproxy handler: not initialised")
	}
	if err := l.Submit(conn); err != nil {
		_ = conn.Close()
		return err
	}
	return nil
}

// Close shuts down the embedded http.Server, draining in-flight
// requests with a short timeout.
func (h *llmproxyHandler) Close() error {
	h.mu.Lock()
	srv, l := h.httpSrv, h.listener
	h.httpSrv, h.listener, h.started = nil, nil, false
	h.mu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	if l != nil {
		_ = l.Close()
	}
	return nil
}

// withInboundAuth wraps the gateway handler with a bearer-token check
// when auth.require is set. When require=false (the Phase 1 default for
// local dev) it returns the handler unchanged so the request path stays
// lock-free.
func withInboundAuth(next http.Handler, md metadata) http.Handler {
	if !md.authRequire || len(md.authKeys) == 0 {
		return next
	}
	keys := make(map[string]struct{}, len(md.authKeys))
	for _, k := range md.authKeys {
		if k != "" {
			keys[k] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if len(hdr) > 7 && hdr[:7] == "Bearer " {
			if _, ok := keys[hdr[7:]]; ok {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"missing or invalid bearer token","type":"permission_error","code":"unauthorized"}}`))
	})
}
