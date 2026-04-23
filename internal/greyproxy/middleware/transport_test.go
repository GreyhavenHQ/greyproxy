package middleware

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Stdio tests rely on a tiny fake middleware written as a Go `run` helper
// in a sibling testmain_test.go. Running `go test` in this package builds
// the package's test binary, and we re-exec *that binary* with a special
// env var to have it act as the fake middleware. This keeps the whole
// setup hermetic: no python, no extra binary to build.

// TestMain sees GREYPROXY_FAKE_MW in env and runs the fake middleware
// instead of the test suite. runFakeMiddleware is defined in main_test.go.

func TestStdioTransport_HelloAndDecision(t *testing.T) {
	// Fake middleware acks hello and echoes an "allow" decision for every
	// request. This exercises: spawn, hello exchange, NDJSON framing on
	// both directions, dispatch back to the pending channel.
	dialer := NewStdioDialer(fakeMwCmd(t, "echo-allow"), nil, "test-mw")
	transport, err := dialer(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = transport.Close() }()

	resp, agreed, err := helloExchange(context.Background(), transport)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if resp.Name != "fake-stdio" {
		t.Errorf("name = %q, want fake-stdio", resp.Name)
	}
	if agreed != 1 {
		t.Errorf("protocol = %d, want 1", agreed)
	}

	// Send one request, expect one decision back.
	req := RequestMsg{Type: "http-request", ID: "abc", Host: "h", Method: "GET", URI: "/"}
	b, _ := json.Marshal(req)
	if err := transport.WriteMessage(b); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := transport.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var d Decision
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if d.Action != "allow" || d.ID != "abc" {
		t.Fatalf("decision = %+v, want allow id=abc", d)
	}
}

func TestStdioTransport_ChildExit_TriggersReadError(t *testing.T) {
	// A middleware that exits after hello is a realistic failure mode
	// (middleware crashed mid-conversation). The transport's ReadMessage
	// must surface this as an error so the client reconnect loop kicks in.
	dialer := NewStdioDialer(fakeMwCmd(t, "exit-after-hello"), nil, "test-mw")
	transport, err := dialer(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = transport.Close() }()

	if _, _, err := helloExchange(context.Background(), transport); err != nil {
		t.Fatalf("hello: %v", err)
	}

	_, err = transport.ReadMessage()
	if err == nil {
		t.Fatal("read after child exit should have returned error")
	}
}

func TestStdioTransport_CloseKillsChild(t *testing.T) {
	// A child that ignores stdin EOF must eventually be SIGKILL'd.
	// We spawn one, close the transport, and check the process exited
	// within stdioCloseGrace + slack.
	dialer := NewStdioDialer(fakeMwCmd(t, "ignore-stdin"), nil, "test-mw")
	transport, err := dialer(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Skip hello; ignore-stdin doesn't speak it.
	start := time.Now()
	if err := transport.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	elapsed := time.Since(start)
	// Close should not block beyond the grace period by much.
	if elapsed > stdioCloseGrace+2*time.Second {
		t.Fatalf("Close took %s, want <= %s", elapsed, stdioCloseGrace+2*time.Second)
	}
}

// fakeMwCmd returns argv for re-executing the test binary with a
// GREYPROXY_FAKE_MW env var that picks one of the behaviours in
// runFakeMiddleware. The env var is exported into the child via
// NewStdioDialer's env arg — but since we own the binary path and flags,
// we pass it through cmd.Env via the exec package directly.
func fakeMwCmd(t *testing.T, mode string) []string {
	t.Helper()
	// Re-exec self with a flag that our TestMain intercepts.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// Absolute path so the child's PATH doesn't matter.
	exe, _ = filepath.Abs(exe)
	// Set GREYPROXY_FAKE_MW via a wrapper script? No — we need it in
	// the child's env. exec.Command's cmd.Env handling happens inside
	// NewStdioDialer via append(cmd.Environ(), env...). But env is a
	// []string we pass as ["KEY=VALUE"]; the helper already merges.
	// Hacky fix: a tiny shell wrapper would work, but let's just set
	// the env in the test's own process and let it leak to the child.
	t.Setenv("GREYPROXY_FAKE_MW", mode)
	return []string{exe}
}

// Unused but kept in case we want to exercise splitCommand-style argv
// paths from a test: run `sh -c "..."`.
var _ = exec.Command
var _ bufio.Scanner
var _ = strings.TrimSpace
var _ = fmt.Sprintf
