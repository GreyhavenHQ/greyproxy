package llmproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	xmdata "github.com/greyhavenhq/greyproxy/internal/gostx/metadata"
	greylp "github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
)

// echoHandler is a stand-in for the real LLM gateway: it just echoes
// the path so tests can verify the gostx handler successfully bridged
// the inbound TCP conn to net/http and back.
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "echo:"+r.URL.Path)
	})
}

func TestHandler_BridgesTCPToHTTP(t *testing.T) {
	greylp.SetGlobalHandler(echoHandler())
	t.Cleanup(func() { greylp.SetGlobalHandler(nil) })

	h := NewHandler().(*llmproxyHandler)
	if err := h.Init(xmdata.NewMetadata(map[string]any{})); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	// Make a localhost pipe; the server-side of the pipe is what we hand
	// to Handle().
	server, client := net.Pipe()
	go func() { _ = h.Handle(context.Background(), server) }()

	// Send an HTTP request through the client side.
	_, err := client.Write([]byte("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "echo:/healthz") {
		t.Fatalf("body=%q", body)
	}
}

func TestHandler_RefusesInitWithoutGateway(t *testing.T) {
	greylp.SetGlobalHandler(nil)
	h := NewHandler().(*llmproxyHandler)
	err := h.Init(xmdata.NewMetadata(map[string]any{}))
	if err == nil {
		t.Fatal("expected init to fail when no gateway is registered")
	}
	if !strings.Contains(err.Error(), "no LLM gateway") {
		t.Fatalf("error: %v", err)
	}
}

func TestHandler_BearerAuthRequired(t *testing.T) {
	greylp.SetGlobalHandler(echoHandler())
	t.Cleanup(func() { greylp.SetGlobalHandler(nil) })

	md := xmdata.NewMetadata(map[string]any{
		"auth.require": true,
		"auth.keys":    []string{"sk-allowed"},
	})
	h := NewHandler().(*llmproxyHandler)
	if err := h.Init(md); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	// no Authorization header → 401
	{
		server, client := net.Pipe()
		go func() { _ = h.Handle(context.Background(), server) }()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	}

	// good bearer → 200
	{
		server, client := net.Pipe()
		go func() { _ = h.Handle(context.Background(), server) }()
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer sk-allowed\r\n\r\n"))
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	}
}
