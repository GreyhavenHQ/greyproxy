package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

// Reconnect tuning. The max is deliberately short: middleware crashes
// during a live LLM request flow are common (py reload, container restart)
// and a 10s tail means an entire conversation can pile up in the "fail
// closed" fallback. 2s keeps the wait under one typical user-visible
// latency budget while still giving the middleware room to come back up.
const (
	reconnectInitial = 100 * time.Millisecond
	reconnectMax     = 2 * time.Second
	// A connection that was up for at least this long is considered
	// "healthy enough": the next disconnect resets backoff to initial.
	// Without this, a restart→reconnect→restart cycle stays stuck at
	// the max backoff forever because the variable lives across the
	// outer for loop.
	reconnectHealthyAfter = 5 * time.Second
)

// pendingEntry tracks an in-flight Send(): the channel that receives the
// decision plus whether the message was a response (so drainPending can
// return the correct default action on disconnect).
type pendingEntry struct {
	ch         chan Decision
	isResponse bool
}

// Client manages a persistent WebSocket connection to a middleware service.
type Client struct {
	url        string
	authHeader string
	timeoutMs  int
	onTimeout  string // "allow"|"deny"

	// writeMu serializes WebSocket writes without blocking state reads.
	// Gorilla websocket.Conn requires writes to be serialized; keeping
	// this separate from mu means a slow peer can't stall reads of
	// pending/hooks/name.
	writeMu sync.Mutex

	mu      sync.Mutex
	conn    *websocket.Conn
	pending map[string]pendingEntry

	hooks        []HookSpec
	maxBodyBytes int64
	name         string        // middleware-declared friendly name, may be empty
	ready        chan struct{} // closed after first successful hello exchange
	readyOnce    sync.Once

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // closed when background goroutines exit
}

// New creates a new middleware client with the given configuration.
//
// If Config.OnDisconnect is empty, the client defaults to "deny": when the
// middleware is unreachable, requests are rejected (403) and responses are
// blocked (502) rather than silently flowing through. Operators who run a
// middleware purely for observation (audit log, cost tracker) should set
// OnDisconnect: "allow" explicitly — advisory-only policy is an opt-in.
func New(cfg Config) *Client {
	timeout := cfg.TimeoutMs
	if timeout <= 0 {
		timeout = 2000
	}
	onTimeout := cfg.OnDisconnect
	if onTimeout == "" {
		onTimeout = "deny"
	}
	return &Client{
		url:        cfg.URL,
		authHeader: cfg.AuthHeader,
		timeoutMs:  timeout,
		onTimeout:  onTimeout,
		pending:    make(map[string]pendingEntry),
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

	backoff := reconnectInitial

	for {
		if err := c.ctx.Err(); err != nil {
			return err
		}

		connectStart := time.Now()
		err := c.connectAndRun()
		connectedFor := time.Since(connectStart)

		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}

		// Drain all pending requests on disconnect so in-flight Sends
		// wake with a fallback decision immediately.
		c.drainPending()

		// If the previous connection was up long enough to be healthy,
		// reset the backoff so a middleware restart cycle doesn't stay
		// stuck at the max wait.
		if connectedFor >= reconnectHealthyAfter {
			backoff = reconnectInitial
		}

		wait := backoffWithJitter(backoff)
		if err != nil {
			logger.Default().Warnf("middleware %s disconnected (up %s): %v — reconnecting in %s",
				c.url, connectedFor.Round(time.Millisecond), err, wait.Round(time.Millisecond))
		}

		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-time.After(wait):
		}

		backoff *= 2
		if backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// backoffWithJitter adds ±20% jitter to d. Jitter prevents every middleware
// (and every greyproxy instance, when several talk to the same service)
// from reconnecting in lockstep after a shared outage.
func backoffWithJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	jitter := time.Duration(rand.Int63n(int64(d) / 5)) //nolint:gosec // not security-sensitive
	if rand.Intn(2) == 0 {
		return d - jitter
	}
	return d + jitter
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
		return fmt.Errorf("middleware hello: unexpected type %q (want %q)", resp.Type, "hello")
	}

	c.mu.Lock()
	c.hooks = resp.Hooks
	c.maxBodyBytes = resp.MaxBodyBytes
	c.name = resp.Name
	c.mu.Unlock()

	// Precompile regex filters for hot-path performance
	PrecompileFilters(resp.Hooks)

	// Signal that hooks are available
	c.readyOnce.Do(func() { close(c.ready) })

	logger.Default().Infof("middleware hello: name=%q hooks=%d max_body_bytes=%d", resp.Name, len(resp.Hooks), resp.MaxBodyBytes)

	// Read loop: dispatch incoming decisions to waiting channels.
	// A malformed frame is logged and skipped; only transport errors drop
	// the connection (and trigger reconnect + drainPending).
	for {
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}

		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
			continue
		}

		var d Decision
		if err := json.Unmarshal(data, &d); err != nil {
			logger.Default().Warnf("middleware %s: malformed frame, skipping: %v", c.url, err)
			continue
		}

		c.mu.Lock()
		entry, ok := c.pending[d.ID]
		if ok {
			delete(c.pending, d.ID)
		}
		c.mu.Unlock()

		if ok {
			entry.ch <- d
		} else {
			logger.Default().Warnf("middleware %s: decision for unknown id %q (late response or duplicate)", c.url, d.ID)
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

// Name returns the middleware-declared friendly name, or "" if the
// middleware did not provide one in its hello response.
func (c *Client) Name() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.name
}

// Send sends a message to the middleware and waits for the corresponding
// decision. Send never returns an error: when the middleware fails to respond
// (disconnected, write failure, timeout, context cancel), Send returns a
// default Decision whose Fallback field names the reason, and callers can
// log/branch on it.
//
// The default action depends on (a) which message type was sent (request vs
// response) and (b) the onTimeout policy on this client, so a response hook
// gets "block" (not "deny") when on_disconnect=deny, matching the documented
// protocol semantics.
func (c *Client) Send(ctx context.Context, msg any) Decision {
	// Extract the ID and remember whether this was a response message so
	// the default action can pick the right verb.
	var (
		id         string
		isResponse bool
	)
	switch m := msg.(type) {
	case RequestMsg:
		id = m.ID
	case ResponseMsg:
		id = m.ID
		isResponse = true
	}

	ch := make(chan Decision, 1)

	c.mu.Lock()
	conn := c.conn
	c.pending[id] = pendingEntry{ch: ch, isResponse: isResponse}
	c.mu.Unlock()

	cleanup := func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}

	if conn == nil {
		cleanup()
		return c.fallback(id, isResponse, "disconnected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		cleanup()
		logger.Default().Warnf("middleware %s: marshal failed: %v", c.url, err)
		return c.fallback(id, isResponse, "marshal_error")
	}

	c.writeMu.Lock()
	writeErr := conn.WriteMessage(websocket.TextMessage, data)
	c.writeMu.Unlock()

	if writeErr != nil {
		cleanup()
		return c.fallback(id, isResponse, "write_error")
	}

	timeout := time.Duration(c.timeoutMs) * time.Millisecond
	select {
	case d := <-ch:
		return d
	case <-time.After(timeout):
		cleanup()
		return c.fallback(id, isResponse, "timeout")
	case <-ctx.Done():
		cleanup()
		return c.fallback(id, isResponse, "context_cancelled")
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

// drainPending releases every in-flight Send() with a "disconnected"
// fallback when the connection drops. Each pending entry carries its own
// isResponse flag, so response-hook sends get block/passthrough and
// request-hook sends get deny/allow, matching whichever onTimeout policy
// applies.
func (c *Client) drainPending() {
	c.mu.Lock()
	for id, entry := range c.pending {
		entry.ch <- c.fallbackLocked(id, entry.isResponse, "disconnected")
		delete(c.pending, id)
	}
	c.mu.Unlock()
}

// fallback builds a default Decision when the middleware can't respond.
// isResponse selects between request semantics (allow/deny 403) and response
// semantics (passthrough/block 502). The reason is stored on
// Decision.Fallback for caller logging; it never travels over the wire.
func (c *Client) fallback(id string, isResponse bool, reason string) Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fallbackLocked(id, isResponse, reason)
}

func (c *Client) fallbackLocked(id string, isResponse bool, reason string) Decision {
	d := Decision{Type: "decision", ID: id, Fallback: reason}
	switch c.onTimeout {
	case "allow":
		if isResponse {
			d.Action = "passthrough"
		} else {
			d.Action = "allow"
		}
	default: // "deny" (secure default)
		if isResponse {
			d.Action = "block"
			d.StatusCode = 502
		} else {
			d.Action = "deny"
			d.StatusCode = 403
		}
	}
	return d
}
