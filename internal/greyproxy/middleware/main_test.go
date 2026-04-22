package middleware

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
)

// Tests in this package touch code paths that call logger.Default().Warnf.
// In production the binary installs a real logger via logger.SetDefault;
// under `go test` nothing does. Install a no-op logger so the Warnf calls
// in drainPending/cascade fallback paths don't panic on nil.
//
// TestMain also hijacks execution when GREYPROXY_FAKE_MW is set: the test
// binary re-execs itself as a fake stdio middleware (see fakeMwCmd). Done
// this way to avoid shipping an extra binary just for tests.
func TestMain(m *testing.M) {
	if mode := os.Getenv("GREYPROXY_FAKE_MW"); mode != "" {
		runFakeMiddleware(mode)
		return
	}
	logger.SetDefault(nopLogger{})
	os.Exit(m.Run())
}

// runFakeMiddleware speaks the proxy's stdio protocol on stdin/stdout
// and implements whichever canned behaviour `mode` names. Always exits
// the process; never returns.
func runFakeMiddleware(mode string) {
	switch mode {
	case "echo-allow":
		fakeEchoAllow()
	case "exit-after-hello":
		fakeExitAfterHello()
	case "ignore-stdin":
		fakeIgnoreStdin()
	default:
		fmt.Fprintf(os.Stderr, "fake-mw: unknown mode %q\n", mode)
		os.Exit(2)
	}
	os.Exit(0)
}

// fakeEchoAllow: respond to every request with action=allow, echoing the id.
func fakeEchoAllow() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<16), 1<<24)
	// Read proxy hello.
	if !sc.Scan() {
		return
	}
	// Respond with our hello.
	hello := HelloMsg{Type: "hello", Name: "fake-stdio", MinVersion: 1, MaxVersion: 1}
	helloBytes, _ := json.Marshal(hello)
	fmt.Println(string(helloBytes))
	// Echo decisions.
	for sc.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			continue
		}
		id, _ := msg["id"].(string)
		d := Decision{Type: "decision", ID: id, Action: "allow"}
		out, _ := json.Marshal(d)
		fmt.Println(string(out))
	}
}

// fakeExitAfterHello: complete the hello exchange, then exit cleanly.
// Exercises the "child dies mid-conversation" path.
func fakeExitAfterHello() {
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return
	}
	hello := HelloMsg{Type: "hello", Name: "fake-stdio", MinVersion: 1, MaxVersion: 1}
	helloBytes, _ := json.Marshal(hello)
	fmt.Println(string(helloBytes))
	// Exit immediately so the next ReadMessage on the proxy side gets EOF.
}

// fakeIgnoreStdin: do nothing, sit idle. Exercises the SIGKILL path
// when the transport is closed.
func fakeIgnoreStdin() {
	// Block forever — ignore stdin close, ignore SIGTERM (we rely on
	// SIGKILL from the transport). Not quite "ignore SIGTERM" — Go's
	// default signal handling will kill us on SIGTERM too — but the
	// test sends SIGKILL directly, so this is fine.
	_, _ = io.Copy(io.Discard, os.Stdin)
	// If stdin somehow closes, still block.
	time.Sleep(10 * time.Second)
}

type nopLogger struct{}

func (nopLogger) WithFields(map[string]any) logger.Logger { return nopLogger{} }
func (nopLogger) Trace(...any)                            {}
func (nopLogger) Tracef(string, ...any)                   {}
func (nopLogger) Debug(...any)                            {}
func (nopLogger) Debugf(string, ...any)                   {}
func (nopLogger) Info(...any)                             {}
func (nopLogger) Infof(string, ...any)                    {}
func (nopLogger) Warn(...any)                             {}
func (nopLogger) Warnf(string, ...any)                    {}
func (nopLogger) Error(...any)                            {}
func (nopLogger) Errorf(string, ...any)                   {}
func (nopLogger) Fatal(...any)                            {}
func (nopLogger) Fatalf(string, ...any)                   {}
func (nopLogger) GetLevel() logger.LogLevel               { return logger.InfoLevel }
func (nopLogger) IsLevelEnabled(logger.LogLevel) bool     { return false }
