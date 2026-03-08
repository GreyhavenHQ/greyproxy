package gostx

import (
	"net/http"

	"github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/sniffing"
)

// MitmRoundTripInfo contains decrypted HTTP request/response data from a MITM round-trip.
// This re-exports the internal sniffing type for use outside the gostx/internal package.
type MitmRoundTripInfo struct {
	Host            string
	Method          string
	URI             string
	Proto           string
	StatusCode      int
	RequestHeaders  http.Header
	RequestBody     []byte
	ResponseHeaders http.Header
	ResponseBody    []byte
	ContainerName   string
	DurationMs      int64
}

// SetGlobalMitmHook sets a global callback that fires after every MITM-intercepted HTTP round-trip.
func SetGlobalMitmHook(hook func(info MitmRoundTripInfo)) {
	if hook == nil {
		sniffing.GlobalHTTPRoundTripHook = nil
		return
	}
	sniffing.GlobalHTTPRoundTripHook = func(info sniffing.HTTPRoundTripInfo) {
		hook(MitmRoundTripInfo{
			Host:            info.Host,
			Method:          info.Method,
			URI:             info.URI,
			Proto:           info.Proto,
			StatusCode:      info.StatusCode,
			RequestHeaders:  info.RequestHeaders,
			RequestBody:     info.RequestBody,
			ResponseHeaders: info.ResponseHeaders,
			ResponseBody:    info.ResponseBody,
			ContainerName:   info.ContainerName,
			DurationMs:      info.DurationMs,
		})
	}
}
