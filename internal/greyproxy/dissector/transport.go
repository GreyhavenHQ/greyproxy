package dissector

import (
	"net/http"
	"time"
)

// TransportUnpacker extracts JSON payloads from transport framing.
// HTTP transactions pass through unchanged. WebSocket transactions
// require frame-level parsing (future: Codex support).
type TransportUnpacker interface {
	// Unpack extracts zero or more JSON payloads from a raw transaction.
	Unpack(tx RawTransaction) ([]UnpackedPayload, error)
}

// RawTransaction represents a single HTTP or WebSocket transaction
// as stored in the database.
type RawTransaction struct {
	ID             int64
	URL            string
	Method         string
	Host           string
	StatusCode     int
	RequestHeaders http.Header
	RequestBody    []byte
	ResponseBody   []byte
	RequestCT      string
	ResponseCT     string
	Timestamp      time.Time
	ContainerName  string
	DurationMs     int64
}

// UnpackedPayload is the output of the transport unpacker.
// For HTTP, this is the request/response body pair.
// For WebSocket, this is a single turn's worth of frames.
type UnpackedPayload struct {
	TransactionID  int64
	RequestJSON    []byte
	ResponseJSON   []byte
	RequestHeaders http.Header
	URL            string
	Host           string
	Timestamp      time.Time
	ContainerName  string
	DurationMs     int64
	Transport      string // "http" or "websocket"
}

// HTTPUnpacker passes HTTP transactions through unchanged.
type HTTPUnpacker struct{}

func (u *HTTPUnpacker) Unpack(tx RawTransaction) ([]UnpackedPayload, error) {
	return []UnpackedPayload{{
		TransactionID:  tx.ID,
		RequestJSON:    tx.RequestBody,
		ResponseJSON:   tx.ResponseBody,
		RequestHeaders: tx.RequestHeaders,
		URL:            tx.URL,
		Host:           tx.Host,
		Timestamp:      tx.Timestamp,
		ContainerName:  tx.ContainerName,
		DurationMs:     tx.DurationMs,
		Transport:      "http",
	}}, nil
}
