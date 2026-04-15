package sniffing

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
)

// requestIDKey carries a short random id through ctx across the
// request/response/round-trip hooks in a MITM or plain-HTTP round-trip,
// so subscribers (the middleware cascade, the transaction persistence
// hook) can correlate events back to one specific round-trip.
//
// Defined in this lowest-level package because both the sniffer (which
// generates and writes the id) and the higher-level gostx package
// (which reads the id from hook closures set by the cmd layer) need
// access to the same ctx key. gostx re-exports NewRequestID /
// WithRequestID / RequestIDFromContext as thin wrappers.
type requestIDKey struct{}

// NewRequestID returns a fresh 16-char hex id.
func NewRequestID() string {
	var buf [8]byte
	_, _ = cryptorand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// WithRequestID stores id in ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext retrieves the id stored by WithRequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
