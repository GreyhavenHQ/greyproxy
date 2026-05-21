// Package llmproxy is the gostx handler that fronts greyproxy's LLM
// gateway. The handler accepts TCP connections from a regular gostx
// service (services: handler.type: llmproxy in greyproxy.yml) and
// dispatches each one into an in-process http.Server whose handler is
// the gateway from internal/greyproxy/llmproxy.
package llmproxy

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// chanListener turns a stream of net.Conn handoffs into a net.Listener
// so the standard library's http.Server can drive the request loop.
//
// gostx handlers are connection-oriented: Handle(ctx, conn) is called
// once per accepted TCP connection. An http.Server, by contrast, wants
// to own the Accept loop. We bridge by pushing each accepted conn onto
// a channel that pretends to be an Accept queue.
type chanListener struct {
	conns  chan net.Conn
	closed atomic.Bool
	once   sync.Once
	addr   net.Addr
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		conns: make(chan net.Conn, 16),
		addr:  addr,
	}
}

// Accept blocks until a conn is pushed (via Submit) or the listener is
// closed. The error returned on close mirrors net.ErrClosed so
// http.Server's serve loop exits cleanly.
func (l *chanListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

// Submit hands a connection to whichever http.Server goroutine is
// currently blocked in Accept. Returns an error if the listener was
// closed (so the gostx handler can drop the conn cleanly).
func (l *chanListener) Submit(c net.Conn) error {
	if l.closed.Load() {
		return errors.New("llmproxy: listener closed")
	}
	defer func() {
		// In a tight close race the channel may have been closed between
		// the load above and this send. Recover so we don't crash.
		_ = recover()
	}()
	l.conns <- c
	return nil
}

func (l *chanListener) Close() error {
	l.once.Do(func() {
		l.closed.Store(true)
		close(l.conns)
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

// loopbackAddr is a placeholder addr used when no socket-level address
// is available (the gostx listener owns the real one). It satisfies
// net.Addr's small interface and never collides with a real port.
type loopbackAddr struct{}

func (loopbackAddr) Network() string { return "tcp" }
func (loopbackAddr) String() string  { return "llmproxy-virtual" }
