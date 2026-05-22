package llmproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	greylp "github.com/greyhavenhq/greyproxy/internal/greyproxy/llmproxy"
	xmdata "github.com/greyhavenhq/greyproxy/internal/gostx/metadata"
	_ "modernc.org/sqlite"
)

// TestE2E_GatewayThroughHandler wires the whole Phase 1 stack:
// gostx handler -> embedded http.Server -> llmproxy.Server -> Backend ->
// stub upstream, and back. A client speaks raw HTTP over a net.Pipe and
// must get a well-formed OpenAI Chat Completions response with the alias
// resolved to the backend model id on the upstream side.
func TestE2E_GatewayThroughHandler(t *testing.T) {
	// Stub upstream OpenAI server.
	var gotModel, gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		gotModel, _ = body["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"chatcmpl-e2e","model":"gpt-4o-mini","object":"chat.completion",
			"choices":[{"index":0,"finish_reason":"stop",
				"message":{"role":"assistant","content":"pong"}}],
			"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
		}`)
	}))
	defer up.Close()

	// Real Store on a temp DB, seeded with a provider + alias.
	f, err := os.CreateTemp("", "llmproxy_e2e_*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	db, err := greyproxy.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	store := greylp.NewStore(db, key)
	p, err := store.CreateProvider(greylp.ProviderInput{
		Name: "stub", Type: "openai", BaseURL: up.URL, APIKey: "sk-e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAlias(greylp.AliasInput{
		Name: "fast", ProviderID: p.ID, ModelID: "gpt-4o-mini",
	}); err != nil {
		t.Fatal(err)
	}

	// Register the gateway, then start the gostx handler.
	greylp.SetGlobalHandler(greylp.NewServer(store, greylp.NewStoreRouter(store)))
	t.Cleanup(func() { greylp.SetGlobalHandler(nil) })

	h := NewHandler().(*llmproxyHandler)
	if err := h.Init(xmdata.NewMetadata(map[string]any{})); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })

	// Drive a request through a pipe.
	server, client := net.Pipe()
	go func() { _ = h.Handle(context.Background(), server) }()

	reqBody := `{"model":"fast","messages":[{"role":"user","content":"ping"}]}`
	httpReq := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + itoa(len(reqBody)) + "\r\n" +
		"Connection: close\r\n\r\n" + reqBody
	if _, err := client.Write([]byte(httpReq)); err != nil {
		t.Fatal(err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode resp: %v body=%s", err, raw)
	}
	if out["object"] != "chat.completion" {
		t.Fatalf("object: %v", out["object"])
	}
	choices := out["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "pong" {
		t.Fatalf("content: %v", msg["content"])
	}

	// Upstream-side assertions: alias resolved to backend model, auth set.
	if gotModel != "gpt-4o-mini" {
		t.Fatalf("upstream saw model %q, want resolved gpt-4o-mini", gotModel)
	}
	if gotAuth != "Bearer sk-e2e" {
		t.Fatalf("upstream auth: %q", gotAuth)
	}
}

// TestE2E_UnknownAliasFlowsBackAs404 confirms gateway errors propagate
// through the handler bridge with the right status + envelope.
func TestE2E_UnknownAliasFlowsBackAs404(t *testing.T) {
	f, _ := os.CreateTemp("", "llmproxy_e2e2_*.db")
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	db, err := greyproxy.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_ = db.Migrate()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	store := greylp.NewStore(db, key)

	greylp.SetGlobalHandler(greylp.NewServer(store, greylp.NewStoreRouter(store)))
	t.Cleanup(func() { greylp.SetGlobalHandler(nil) })

	h := NewHandler().(*llmproxyHandler)
	if err := h.Init(xmdata.NewMetadata(map[string]any{})); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })

	server, client := net.Pipe()
	go func() { _ = h.Handle(context.Background(), server) }()

	body := `{"model":"ghost","messages":[]}`
	req := "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	_, _ = client.Write([]byte(req))
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "alias_unknown") {
		t.Fatalf("error envelope: %s", raw)
	}
}

// itoa avoids pulling strconv into the test for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
