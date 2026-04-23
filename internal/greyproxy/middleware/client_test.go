package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// startMockServer stands up a WebSocket server driven by a handler that gets
// the server's connection and a *testing.T. The server echoes decisions back
// on the same connection. The handler may pause reading to simulate a
// timeout, return a wrong hello type to exercise validation, etc.
func startMockServer(t *testing.T, handler func(*testing.T, *websocket.Conn)) (url string, stop func()) {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		handler(t, conn)
	}))
	return "ws" + strings.TrimPrefix(srv.URL, "http"), srv.Close
}

func readHello(t *testing.T, c *websocket.Conn) {
	t.Helper()
	var h HelloMsg
	if err := c.ReadJSON(&h); err != nil {
		t.Fatalf("server read hello: %v", err)
	}
	if h.Type != "hello" {
		t.Fatalf("server saw hello.type = %q", h.Type)
	}
}

// TestClient_RejectsBogusHelloType asserts the bug at client.go:141 is
// fixed: a server that returns the wrong type in its hello response must
// cause the connection to fail rather than being silently accepted.
func TestClient_RejectsBogusHelloType(t *testing.T) {
	url, stop := startMockServer(t, func(t *testing.T, c *websocket.Conn) {
		readHello(t, c)
		_ = c.WriteJSON(map[string]any{"type": "not-hello"})
	})
	defer stop()

	c := New(Config{URL: url, TimeoutMs: 500})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = c.Start(ctx) }()

	// The client should never flag itself as ready, because the hello
	// exchange failed.
	select {
	case <-c.ready:
		t.Fatal("client marked ready after bogus hello type")
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	c.Close()
	wg.Wait()
}

// TestClient_HelloExchange asserts a correct hello path marks the client
// ready and surfaces hooks/name.
func TestClient_HelloExchange(t *testing.T) {
	url, stop := startMockServer(t, func(t *testing.T, c *websocket.Conn) {
		readHello(t, c)
		_ = c.WriteJSON(HelloMsg{
			Type: "hello", Name: "mock",
			Hooks:        []HookSpec{{Type: "http-request"}},
			MaxBodyBytes: 4096,
		})
		// Stay alive so the client can run its read loop.
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer stop()

	c := New(Config{URL: url, TimeoutMs: 500})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()

	select {
	case <-c.ready:
	case <-time.After(1 * time.Second):
		t.Fatal("client not ready after 1s")
	}
	if got := c.Name(); got != "mock" {
		t.Errorf("Name = %q, want mock", got)
	}
	if got := c.MaxBodyBytes(); got != 4096 {
		t.Errorf("MaxBodyBytes = %d, want 4096", got)
	}
	if hooks := c.HookSpecs(); len(hooks) != 1 || hooks[0].Type != "http-request" {
		t.Errorf("HookSpecs = %+v", hooks)
	}
}

// TestClient_FallbackOnTimeout checks that when the server accepts the
// hello but never replies to a request, the client returns a fallback
// Decision with the right Action and a Fallback reason set.
func TestClient_FallbackOnTimeout(t *testing.T) {
	cases := []struct {
		name       string
		onTimeout  string
		isResponse bool
		wantAction string
	}{
		{"req/deny-default", "", false, "deny"},
		{"req/allow-opt-in", "allow", false, "allow"},
		{"resp/block-default", "", true, "block"},
		{"resp/passthrough-opt-in", "allow", true, "passthrough"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, stop := startMockServer(t, func(t *testing.T, c *websocket.Conn) {
				readHello(t, c)
				_ = c.WriteJSON(HelloMsg{Type: "hello"})
				// Never respond to whatever the client sends.
				for {
					if _, _, err := c.ReadMessage(); err != nil {
						return
					}
				}
			})
			defer stop()

			c := New(Config{URL: url, TimeoutMs: 100, OnDisconnect: tc.onTimeout})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = c.Start(ctx) }()
			<-c.ready

			var msg any
			if tc.isResponse {
				msg = ResponseMsg{Type: "http-response", ID: NewID()}
			} else {
				msg = RequestMsg{Type: "http-request", ID: NewID()}
			}
			d := c.Send(context.Background(), msg)
			if d.Action != tc.wantAction {
				t.Errorf("Action = %q, want %q", d.Action, tc.wantAction)
			}
			if d.Fallback != "timeout" {
				t.Errorf("Fallback = %q, want %q", d.Fallback, "timeout")
			}
		})
	}
}

// TestClient_SkipsMalformedFrame checks that a JSON parse error on one
// frame does not drop the whole connection — a later valid decision still
// reaches the waiting Send.
func TestClient_SkipsMalformedFrame(t *testing.T) {
	url, stop := startMockServer(t, func(t *testing.T, c *websocket.Conn) {
		readHello(t, c)
		_ = c.WriteJSON(HelloMsg{Type: "hello"})

		// Wait for a request, send garbage, then a real decision.
		_, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		var msg map[string]any
		_ = json.Unmarshal(data, &msg)
		id, _ := msg["id"].(string)

		_ = c.WriteMessage(websocket.TextMessage, []byte("{not json"))
		time.Sleep(10 * time.Millisecond)
		_ = c.WriteJSON(Decision{Type: "decision", ID: id, Action: "allow"})

		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer stop()

	c := New(Config{URL: url, TimeoutMs: 2000})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	<-c.ready

	d := c.Send(context.Background(), RequestMsg{Type: "http-request", ID: NewID()})
	if d.Action != "allow" {
		t.Fatalf("Action = %q, want allow (malformed frame should have been skipped)", d.Action)
	}
	if d.Fallback != "" {
		t.Errorf("Fallback = %q, want empty (real decision delivered)", d.Fallback)
	}
}

// TestClient_RejectsIncompatibleVersion asserts that a middleware
// declaring a min_version higher than the proxy's ProtocolVersion causes
// the connection to be refused. The failure must not silently mark the
// client ready — otherwise an operator could connect a v2-only middleware
// to a v1 proxy and watch fields they declared in their hello (and rely
// on later) just disappear.
func TestClient_RejectsIncompatibleVersion(t *testing.T) {
	url, stop := startMockServer(t, func(t *testing.T, c *websocket.Conn) {
		readHello(t, c)
		// Middleware requires at least v2; this proxy only speaks v1.
		_ = c.WriteJSON(HelloMsg{
			Type: "hello", Name: "future-mw",
			MinVersion: ProtocolVersion + 1,
			MaxVersion: ProtocolVersion + 5,
		})
	})
	defer stop()

	c := New(Config{URL: url, TimeoutMs: 500})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = c.Start(ctx) }()

	select {
	case <-c.ready:
		t.Fatal("client marked ready after version mismatch")
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	c.Close()
}

// TestClient_OmittedVersionsAssumeV1 asserts that a middleware that omits
// both version bounds (the shape of every example in the repo) still
// negotiates successfully and is assigned protocol v1. This is the
// backwards-compatibility guarantee the docs promise.
func TestClient_OmittedVersionsAssumeV1(t *testing.T) {
	url, stop := startMockServer(t, func(t *testing.T, c *websocket.Conn) {
		readHello(t, c)
		_ = c.WriteJSON(HelloMsg{Type: "hello", Name: "legacy"})
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer stop()

	c := New(Config{URL: url, TimeoutMs: 500})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()

	select {
	case <-c.ready:
	case <-time.After(1 * time.Second):
		t.Fatal("client not ready after 1s")
	}
	if v := c.ProtocolVersion(); v != 1 {
		t.Fatalf("ProtocolVersion = %d, want 1 (back-compat default)", v)
	}
}

// TestClient_DefaultTimeoutGenerous pins the default timeout to a value
// that accommodates middlewares which offload their decision to another
// LLM or slow scanner. If this regresses to something like 2s, policy
// middlewares that do a real-model round-trip will start failing.
func TestClient_DefaultTimeoutGenerous(t *testing.T) {
	c := New(Config{URL: "ws://127.0.0.1:0"})
	if c.timeoutMs < 10000 {
		t.Fatalf("default timeoutMs = %d, want >= 10000 (LLM-offload budget)", c.timeoutMs)
	}
}

// TestBackoffWithJitter_BoundsAndShape asserts the backoff jitter stays
// inside ±20% of the base so the reconnect cap never regresses into a
// multi-second tail after a transient outage.
func TestBackoffWithJitter_BoundsAndShape(t *testing.T) {
	base := 100 * time.Millisecond
	minAllowed := time.Duration(float64(base) * 0.8)
	maxAllowed := time.Duration(float64(base) * 1.2)
	for i := 0; i < 200; i++ {
		got := backoffWithJitter(base)
		if got < minAllowed || got > maxAllowed {
			t.Fatalf("iter %d: backoffWithJitter(%v) = %v, out of [%v,%v]",
				i, base, got, minAllowed, maxAllowed)
		}
	}
	if backoffWithJitter(0) != 0 {
		t.Fatal("backoffWithJitter(0) should return 0")
	}
}

// TestClient_DrainOnDisconnectRespectsMessageKind asserts that when the
// connection drops, an in-flight response Send gets a response-shaped
// default (block/passthrough), not a request-shaped one (deny/allow).
// Regression test for the drainPending bug that defaulted every pending
// entry to request semantics.
func TestClient_DrainOnDisconnectRespectsMessageKind(t *testing.T) {
	var (
		serverConn *websocket.Conn
		gotReq     = make(chan struct{}, 1)
	)
	url, stop := startMockServer(t, func(t *testing.T, c *websocket.Conn) {
		serverConn = c
		readHello(t, c)
		_ = c.WriteJSON(HelloMsg{Type: "hello"})
		_, _, _ = c.ReadMessage()
		gotReq <- struct{}{}
		// Block forever until the test closes us.
		select {}
	})
	defer stop()

	c := New(Config{URL: url, TimeoutMs: 5000}) // default deny
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	<-c.ready

	done := make(chan Decision, 1)
	go func() {
		done <- c.Send(context.Background(), ResponseMsg{Type: "http-response", ID: NewID()})
	}()

	<-gotReq
	// Server drops the connection; client must wake the Send with a
	// response-shaped default (block).
	_ = serverConn.Close()

	select {
	case d := <-done:
		if d.Action != "block" {
			t.Fatalf("Action = %q, want block (response-hook default on disconnect)", d.Action)
		}
		if d.Fallback != "disconnected" {
			t.Fatalf("Fallback = %q, want disconnected", d.Fallback)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not return after server disconnect")
	}
}
