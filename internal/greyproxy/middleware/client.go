package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

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

// Client manages a persistent connection to a middleware service over
// whatever Transport was supplied at construction time (WebSocket or
// stdio-spawned child process). The client is transport-agnostic below
// the Dialer; reconnect, hello exchange, pending-map dispatching, and
// fallback decisions are all framing-independent.
type Client struct {
	dial      Dialer
	endpoint  string // "ws://..." or "stdio:<cmd>", for logs + UI
	kind      string // "ws" | "stdio"
	timeoutMs int
	onTimeout string // "allow"|"deny"

	mu        sync.Mutex
	transport Transport
	pending   map[string]pendingEntry

	hooks           []HookSpec
	maxBodyBytes    int64
	name            string        // middleware-declared friendly name, may be empty
	protocolVersion int           // agreed version after hello negotiation
	ready           chan struct{} // closed after first successful hello exchange
	readyOnce       sync.Once

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // closed when background goroutines exit
}

// New creates a middleware client. Exactly one of Config.URL or
// Config.Command must be set; the caller is expected to validate that
// upstream. Defaults applied here: TimeoutMs=10s, OnDisconnect=deny.
//
// If Config.OnDisconnect is empty, the client defaults to "deny": when the
// middleware is unreachable, requests are rejected (403) and responses are
// blocked (502) rather than silently flowing through. Operators who run a
// middleware purely for observation (audit log, cost tracker) should set
// OnDisconnect: "allow" explicitly — advisory-only policy is an opt-in.
func New(cfg Config) *Client {
	timeout := cfg.TimeoutMs
	if timeout <= 0 {
		// 10s accommodates middlewares that call out to an LLM or a
		// slow scanner to compute their decision. Operators whose
		// middleware is purely local can shorten this in config to
		// surface hangs faster.
		timeout = 10000
	}
	onTimeout := cfg.OnDisconnect
	if onTimeout == "" {
		onTimeout = "deny"
	}

	c := &Client{
		timeoutMs: timeout,
		onTimeout: onTimeout,
		pending:   make(map[string]pendingEntry),
		ready:     make(chan struct{}),
		done:      make(chan struct{}),
	}

	switch {
	case len(cfg.Command) > 0:
		c.kind = "stdio"
		c.endpoint = "stdio:" + cfg.Command[0]
		// The process environment passed to the child tells it how
		// it was launched; a shared helper library picks transport
		// based on this.
		env := []string{"GREYPROXY_TRANSPORT=stdio"}
		c.dial = NewStdioDialer(cfg.Command, env, cfg.Name)
	default:
		c.kind = "ws"
		c.endpoint = cfg.URL
		c.dial = NewWSDialer(cfg.URL, cfg.AuthHeader)
	}
	return c
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
				c.endpoint, connectedFor.Round(time.Millisecond), err, wait.Round(time.Millisecond))
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

// connectAndRun dials the transport, runs the hello exchange, then pumps
// incoming decisions to waiting Sends until the transport dies or ctx is
// cancelled.
func (c *Client) connectAndRun() error {
	transport, err := c.dial(c.ctx)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.transport = transport
	c.mu.Unlock()

	defer func() {
		_ = transport.Close()
		c.mu.Lock()
		c.transport = nil
		c.mu.Unlock()
	}()

	resp, agreed, err := helloExchange(c.ctx, transport)
	if err != nil {
		return fmt.Errorf("middleware %s: %w", c.endpoint, err)
	}

	c.mu.Lock()
	c.hooks = resp.Hooks
	c.maxBodyBytes = resp.MaxBodyBytes
	c.name = resp.Name
	c.protocolVersion = agreed
	c.mu.Unlock()

	// Precompile regex filters for hot-path performance
	PrecompileFilters(resp.Hooks)

	// Signal that hooks are available
	c.readyOnce.Do(func() { close(c.ready) })

	logger.Default().Infof("middleware hello: name=%q endpoint=%s transport=%s protocol=v%d hooks=%d max_body_bytes=%d",
		resp.Name, c.endpoint, c.kind, agreed, len(resp.Hooks), resp.MaxBodyBytes)

	// Read loop: dispatch incoming decisions to waiting channels.
	// A malformed frame is logged and skipped; only transport errors drop
	// the connection (and trigger reconnect + drainPending).
	for {
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}

		data, err := transport.ReadMessage()
		if err != nil {
			return err
		}

		var d Decision
		if err := json.Unmarshal(data, &d); err != nil {
			logger.Default().Warnf("middleware %s: malformed frame, skipping: %v", c.endpoint, err)
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
			logger.Default().Warnf("middleware %s: decision for unknown id %q (late response or duplicate)", c.endpoint, d.ID)
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

// ProtocolVersion returns the agreed protocol version after hello
// negotiation. Returns 0 if the hello exchange hasn't completed.
func (c *Client) ProtocolVersion() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.protocolVersion
}

// IsConnected reports whether the underlying transport is currently live.
// Flips to false as soon as the read loop exits (transport error, peer
// close, or context cancel) and flips back to true only after the next
// successful hello exchange.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transport != nil
}

// URL returns the endpoint for this client — a ws:// URL or a synthetic
// "stdio:<command>" string, depending on transport. Kept named URL() for
// continuity with the JSON field that /api/middlewares surfaces.
func (c *Client) URL() string { return c.endpoint }

// Kind returns the transport kind: "ws" or "stdio".
func (c *Client) Kind() string { return c.kind }

// TimeoutMs returns the configured per-message timeout in milliseconds.
func (c *Client) TimeoutMs() int { return c.timeoutMs }

// OnDisconnect returns the configured policy (currently "allow" or "deny").
func (c *Client) OnDisconnect() string { return c.onTimeout }

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
	transport := c.transport
	c.pending[id] = pendingEntry{ch: ch, isResponse: isResponse}
	c.mu.Unlock()

	cleanup := func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}

	if transport == nil {
		cleanup()
		return c.fallback(id, isResponse, "disconnected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		cleanup()
		logger.Default().Warnf("middleware %s: marshal failed: %v", c.endpoint, err)
		return c.fallback(id, isResponse, "marshal_error")
	}

	if err := transport.WriteMessage(data); err != nil {
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

// Close shuts down the client, drains pending requests, and closes the
// transport. For a stdio transport, Close also waits for the child to
// exit (SIGKILL after the grace period).
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	// Wait for background goroutines to exit (with timeout)
	select {
	case <-c.done:
	case <-time.After(stdioCloseGrace + time.Second):
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
