package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

// Client manages a persistent WebSocket connection to a middleware service.
type Client struct {
	url        string
	authHeader string
	timeoutMs  int
	onTimeout  string // "allow"|"deny"

	mu      sync.Mutex
	conn    *websocket.Conn
	pending map[string]chan Decision

	hooks        []HookSpec
	maxBodyBytes int64
	ready        chan struct{} // closed after first successful hello exchange
	readyOnce    sync.Once

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // closed when background goroutines exit
}

// New creates a new middleware client with the given configuration.
func New(cfg Config) *Client {
	timeout := cfg.TimeoutMs
	if timeout <= 0 {
		timeout = 2000
	}
	onTimeout := cfg.OnDisconnect
	if onTimeout == "" {
		onTimeout = "allow"
	}
	return &Client{
		url:        cfg.URL,
		authHeader: cfg.AuthHeader,
		timeoutMs:  timeout,
		onTimeout:  onTimeout,
		pending:    make(map[string]chan Decision),
		ready:      make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// Start connects to the middleware, performs the hello exchange, and starts
// the background reader goroutine. It reconnects automatically on disconnect.
// Blocks until context is cancelled.
func (c *Client) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)
	defer close(c.done)

	backoff := 100 * time.Millisecond
	maxBackoff := 10 * time.Second

	for {
		if err := c.ctx.Err(); err != nil {
			return err
		}

		err := c.connectAndRun()
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}

		if err != nil {
			logger.Default().Warnf("middleware connection lost: %v, reconnecting in %v", err, backoff)
		}

		// Drain all pending requests on disconnect
		c.drainPending()

		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-time.After(backoff):
		}

		backoff = backoff * 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// connectAndRun establishes the WebSocket, does the hello exchange, then reads
// until the connection drops or context is cancelled.
func (c *Client) connectAndRun() error {
	dialer := websocket.DefaultDialer

	header := http.Header{}
	if c.authHeader != "" {
		parts := strings.SplitN(c.authHeader, ":", 2)
		if len(parts) == 2 {
			header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	conn, _, err := dialer.DialContext(c.ctx, c.url, header)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	defer func() {
		conn.Close()
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	// Send hello
	hello := HelloMsg{Type: "hello", Version: 1}
	if err := conn.WriteJSON(hello); err != nil {
		return err
	}

	// Read hello response (5s deadline)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp HelloMsg
	if err := conn.ReadJSON(&resp); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})

	if resp.Type != "hello" {
		return err
	}

	c.mu.Lock()
	c.hooks = resp.Hooks
	c.maxBodyBytes = resp.MaxBodyBytes
	c.mu.Unlock()

	// Precompile regex filters for hot-path performance
	PrecompileFilters(resp.Hooks)

	// Signal that hooks are available
	c.readyOnce.Do(func() { close(c.ready) })

	logger.Default().Infof("middleware hello: hooks=%d, max_body_bytes=%d", len(resp.Hooks), resp.MaxBodyBytes)

	// Read loop: dispatch incoming decisions to waiting channels
	for {
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}

		var d Decision
		if err := conn.ReadJSON(&d); err != nil {
			return err
		}

		c.mu.Lock()
		ch, ok := c.pending[d.ID]
		if ok {
			delete(c.pending, d.ID)
		}
		c.mu.Unlock()

		if ok {
			ch <- d
		}
	}
}

// HookSpecs blocks until the hello exchange completes (up to 5s), then returns
// the hook specs declared by the middleware.
func (c *Client) HookSpecs() []HookSpec {
	select {
	case <-c.ready:
	case <-time.After(5 * time.Second):
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hooks
}

// MaxBodyBytes returns the middleware-declared body size limit.
func (c *Client) MaxBodyBytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxBodyBytes
}

// Send sends a message to the middleware and waits for the corresponding decision.
// If the middleware doesn't respond within timeoutMs, returns a default decision
// based on the onTimeout policy (not an error).
func (c *Client) Send(ctx context.Context, msg any) (Decision, error) {
	// Extract ID from the message
	var id string
	switch m := msg.(type) {
	case RequestMsg:
		id = m.ID
	case ResponseMsg:
		id = m.ID
	}

	ch := make(chan Decision, 1)

	c.mu.Lock()
	conn := c.conn
	c.pending[id] = ch
	c.mu.Unlock()

	if conn == nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return c.defaultDecision(id), nil
	}

	data, err := json.Marshal(msg)
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return c.defaultDecision(id), nil
	}

	c.mu.Lock()
	writeErr := conn.WriteMessage(websocket.TextMessage, data)
	c.mu.Unlock()

	if writeErr != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return c.defaultDecision(id), nil
	}

	timeout := time.Duration(c.timeoutMs) * time.Millisecond
	select {
	case d := <-ch:
		return d, nil
	case <-time.After(timeout):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return c.defaultDecision(id), nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return c.defaultDecision(id), nil
	}
}

// Close shuts down the client, drains pending requests, and closes the WebSocket.
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	// Wait for background goroutines to exit (with timeout)
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
	}
	c.drainPending()
}

func (c *Client) drainPending() {
	c.mu.Lock()
	for id, ch := range c.pending {
		ch <- c.defaultDecisionLocked(id)
		delete(c.pending, id)
	}
	c.mu.Unlock()
}

func (c *Client) defaultDecision(id string) Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.defaultDecisionLocked(id)
}

func (c *Client) defaultDecisionLocked(id string) Decision {
	switch c.onTimeout {
	case "deny":
		return Decision{Type: "decision", ID: id, Action: "deny", StatusCode: 403}
	default: // "allow"
		return Decision{Type: "decision", ID: id, Action: "allow"}
	}
}

// RequestBodyContextKey is used to pass captured request body through context
// for the plain HTTP response hook.
type requestBodyContextKey struct{}

// WithRequestBody stores the request body in the context.
func WithRequestBody(ctx context.Context, body []byte) context.Context {
	return context.WithValue(ctx, requestBodyContextKey{}, body)
}

// RequestBodyFromContext retrieves the request body stored by the request hook.
func RequestBodyFromContext(ctx context.Context) []byte {
	body, _ := ctx.Value(requestBodyContextKey{}).([]byte)
	return body
}
