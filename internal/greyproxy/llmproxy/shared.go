package llmproxy

import (
	"net/http"
	"sync/atomic"
)

// globalHandler holds the http.Handler the gostx llmproxy handler
// dispatches to. It's wired by cmd/greyproxy/program.go right after the
// Server is constructed (see "How the handler reaches in-process state"
// in the task plan §12). atomic.Pointer keeps the hot path lock-free
// without dropping the ability to swap at config reload.
var globalHandler atomic.Pointer[http.Handler]

// SetGlobalHandler registers the gateway handler. Subsequent gostx
// handler Init() calls pick it up. Passing nil clears it.
func SetGlobalHandler(h http.Handler) {
	if h == nil {
		globalHandler.Store(nil)
		return
	}
	globalHandler.Store(&h)
}

// GlobalHandler returns the currently registered handler or nil. The
// gostx handler calls this on Init() and refuses to start the service
// when no handler is wired (greyproxy without the llm: section).
func GlobalHandler() http.Handler {
	if p := globalHandler.Load(); p != nil {
		return *p
	}
	return nil
}
