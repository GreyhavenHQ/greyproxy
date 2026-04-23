package middleware

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

// Transport is the framing layer between the middleware Client and whatever
// it's talking to. Two implementations exist: wsTransport (the original
// external WebSocket) and stdioTransport (a child process launched and
// owned by greyproxy, speaking newline-delimited JSON on stdin/stdout).
//
// Transports speak *messages*, not bytes: one WriteMessage call on one
// side produces exactly one ReadMessage call on the other. Malformed
// payloads are the Client's problem, not the transport's — a transport
// that returns framed bytes that don't parse as JSON is still "healthy"
// from the framing point of view; only I/O errors drop the connection.
type Transport interface {
	// WriteMessage sends one framed message. Must be safe for
	// concurrent use.
	WriteMessage(data []byte) error
	// ReadMessage blocks until the next framed message arrives, the
	// transport is closed, or the peer disconnects. A returned error
	// means "transport is dead, reconnect"; a zero-length message is
	// not an error.
	ReadMessage() ([]byte, error)
	// Close tears the transport down. A pending ReadMessage wakes with
	// an error. Idempotent.
	Close() error
}

// Dialer produces a fresh Transport for one connection attempt. The same
// Dialer is called again on reconnect/respawn, so it must be idempotent
// and not hold transport state between calls.
type Dialer func(ctx context.Context) (Transport, error)

// ---------------------------------------------------------------------------
// WebSocket transport
// ---------------------------------------------------------------------------

// wsTransport wraps a gorilla *websocket.Conn behind the Transport
// interface. gorilla.Conn requires writes to be serialized; the mutex
// here enforces that without blocking readers.
type wsTransport struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

// NewWSDialer returns a Dialer that opens a WebSocket to url on each call.
// authHeader is parsed as "Key: Value" and sent on the upgrade request; an
// empty string disables it.
func NewWSDialer(url, authHeader string) Dialer {
	return func(ctx context.Context) (Transport, error) {
		header := http.Header{}
		if authHeader != "" {
			parts := strings.SplitN(authHeader, ":", 2)
			if len(parts) == 2 {
				header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, url, header)
		if err != nil {
			return nil, err
		}
		return &wsTransport{conn: conn}, nil
	}
}

func (t *wsTransport) WriteMessage(data []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.conn.WriteMessage(websocket.TextMessage, data)
}

func (t *wsTransport) ReadMessage() ([]byte, error) {
	for {
		msgType, data, err := t.conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
			// Ignore control frames (ping/pong/close handled by gorilla).
			continue
		}
		return data, nil
	}
}

func (t *wsTransport) Close() error { return t.conn.Close() }

// ---------------------------------------------------------------------------
// Stdio transport (child process)
// ---------------------------------------------------------------------------

// stdioTransport runs a child process and frames messages as newline-
// delimited JSON on stdin/stdout. stderr is forwarded to greyproxy's
// logger line by line, with a prefix so an operator can tell which
// middleware produced which log line.
//
// The child's lifecycle is owned by the transport: Close() first closes
// stdin (so a middleware that exits cleanly on EOF has a chance to), then
// waits up to stdioCloseGrace before SIGKILL. The proxy owns the child;
// crashes reconnect through the usual Client.Start backoff loop, which
// re-invokes the Dialer and spawns a fresh child.
type stdioTransport struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Scanner
	writeMu sync.Mutex

	closed   chan struct{}
	closeOne sync.Once
}

const (
	// stdioMaxLineBytes bounds one NDJSON frame. Bodies are already
	// capped by max_body_bytes per middleware; 32 MiB gives plenty of
	// headroom while still stopping runaway output from killing the
	// proxy via an unbounded scanner buffer.
	stdioMaxLineBytes = 32 << 20
	// stdioCloseGrace is how long the child has between stdin EOF and
	// SIGKILL. Enough for a middleware to flush its logs on clean
	// shutdown; short enough that a hung child doesn't block ctx cancel.
	stdioCloseGrace = 2 * time.Second
)

// NewStdioDialer returns a Dialer that spawns command[0] with command[1:]
// as argv and connects to its stdin/stdout. env is merged into the child's
// environment (format "KEY=VALUE"); the proxy's own env is always
// inherited so the child sees $PATH etc.
//
// mwName is a short identifier used in the stderr log prefix — usually
// the middleware's declared name if known at dial time, or the command
// basename as a fallback.
func NewStdioDialer(command, env []string, mwName string) Dialer {
	// Fall back to the command's basename when the caller didn't supply
	// a name. Better than "?" in stderr logs until the middleware sends
	// its hello.
	if mwName == "" && len(command) > 0 {
		mwName = filepath.Base(command[0])
	}
	return func(ctx context.Context) (Transport, error) {
		if len(command) == 0 {
			return nil, errors.New("stdio middleware: empty command")
		}
		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		cmd.Env = append(cmd.Environ(), env...)
		// Critical: put the child in its own process group so Close()
		// can reap the whole tree, not just the immediate child. See
		// transport_unix.go for the rationale — without this, a wrapper
		// like `uv run ...` leaves the real worker orphaned and holding
		// ports / fds open.
		configureProcessGroup(cmd)

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("stdin pipe: %w", err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("stdout pipe: %w", err)
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("stderr pipe: %w", err)
		}

		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("start %q: %w", command[0], err)
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1<<20), stdioMaxLineBytes)

		t := &stdioTransport{
			cmd:    cmd,
			stdin:  stdin,
			stdout: scanner,
			closed: make(chan struct{}),
		}

		go forwardStderr(stderr, mwName)

		return t, nil
	}
}

func (t *stdioTransport) WriteMessage(data []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	select {
	case <-t.closed:
		return errors.New("stdio middleware: transport closed")
	default:
	}
	// Each NDJSON frame is one line, no embedded newlines allowed.
	// json.Marshal output never contains a literal '\n' unless the
	// caller explicitly indented, so we only need to append one.
	if _, err := t.stdin.Write(data); err != nil {
		return err
	}
	if _, err := t.stdin.Write([]byte{'\n'}); err != nil {
		return err
	}
	return nil
}

func (t *stdioTransport) ReadMessage() ([]byte, error) {
	if !t.stdout.Scan() {
		if err := t.stdout.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	// Return a copy because bufio.Scanner reuses its buffer; callers
	// json.Unmarshal asynchronously and we can't have the bytes move
	// under them between calls.
	line := t.stdout.Bytes()
	out := make([]byte, len(line))
	copy(out, line)
	return out, nil
}

func (t *stdioTransport) Close() error {
	t.closeOne.Do(func() {
		close(t.closed)
	})
	// Phase 1: close stdin so a well-behaved middleware exits on EOF.
	_ = t.stdin.Close()

	// Phase 2: wait briefly for clean exit, then SIGKILL the whole
	// process group. Killing just t.cmd.Process is insufficient when
	// the command is a wrapper (e.g. `uv run mw.py`): the wrapper dies,
	// the grandchild is re-parented to init, and whatever ports it
	// bound stay held until it notices or is killed by hand.
	exited := make(chan error, 1)
	go func() { exited <- t.cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(stdioCloseGrace):
		killProcessGroup(t.cmd.Process)
		<-exited
	}
	return nil
}

// forwardStderr reads lines from the child's stderr and re-logs them at
// Info level with a prefix. A buggy middleware that spams stderr won't
// OOM greyproxy because bufio.Scanner has a bounded buffer; lines over
// 64 KiB are truncated.
func forwardStderr(r io.ReadCloser, mwName string) {
	defer func() { _ = r.Close() }()
	if mwName == "" {
		mwName = "?"
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 65536)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		logger.Default().Infof("mw[%s] %s", mwName, line)
	}
}

// ---------------------------------------------------------------------------
// Hello read with timeout (transport-agnostic)
// ---------------------------------------------------------------------------

// readMessageWithTimeout runs transport.ReadMessage in a goroutine so a
// transport without a native read deadline (stdio) can still enforce the
// 5-second hello timeout. On timeout the transport is closed, which
// unblocks the goroutine; the caller discards that final read.
func readMessageWithTimeout(t Transport, d time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := t.ReadMessage()
		ch <- result{data, err}
	}()
	select {
	case r := <-ch:
		return r.data, r.err
	case <-time.After(d):
		_ = t.Close()
		<-ch
		return nil, fmt.Errorf("read timeout after %s", d)
	}
}

// helloExchange runs the proxy-side hello exchange over any Transport.
// Returns the middleware's parsed hello and the agreed protocol version,
// or an error that the caller translates into a reconnect trigger.
func helloExchange(ctx context.Context, t Transport) (HelloMsg, int, error) {
	sendHello := HelloMsg{Type: "hello", Version: ProtocolVersion}
	sendBytes, err := json.Marshal(sendHello)
	if err != nil {
		return HelloMsg{}, 0, fmt.Errorf("hello marshal: %w", err)
	}
	if err := t.WriteMessage(sendBytes); err != nil {
		return HelloMsg{}, 0, fmt.Errorf("hello write: %w", err)
	}

	respBytes, err := readMessageWithTimeout(t, 5*time.Second)
	if err != nil {
		return HelloMsg{}, 0, fmt.Errorf("hello read: %w", err)
	}
	var resp HelloMsg
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return HelloMsg{}, 0, fmt.Errorf("hello parse: %w", err)
	}
	if resp.Type != "hello" {
		return HelloMsg{}, 0, fmt.Errorf("hello: unexpected type %q", resp.Type)
	}
	agreed, err := negotiateVersion(ProtocolVersion, resp.MinVersion, resp.MaxVersion)
	if err != nil {
		return HelloMsg{}, 0, err
	}
	return resp, agreed, nil
}
