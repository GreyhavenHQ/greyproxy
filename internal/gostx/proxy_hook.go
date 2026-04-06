package gostx

import (
	"context"
	"net/http"
)

// ProxyRequestDecision controls what happens to a plain-HTTP request before
// it is forwarded upstream. nil = allow unchanged.
type ProxyRequestDecision struct {
	Deny       bool
	StatusCode int         // default 403 when Deny=true
	DenyBody   string
	NewHeaders http.Header // non-nil: merge into request headers
	NewBody    []byte      // non-nil: replace request body
}

// GlobalProxyRequestHook is called in proxyRoundTrip() before the upstream
// RoundTrip. containerName is the resolved Docker container or client ID.
var GlobalProxyRequestHook func(
	ctx context.Context,
	req *http.Request,
	containerName string,
) *ProxyRequestDecision

// ProxyResponseDecision controls what happens to a plain-HTTP response before
// it is written back to the client. nil = passthrough unchanged.
type ProxyResponseDecision struct {
	Block         bool
	StatusCode    int
	BlockBody     string
	NewStatusCode int
	NewHeaders    http.Header
	NewBody       []byte
}

// GlobalProxyResponseHook is called in proxyRoundTrip() after upstream responds.
var GlobalProxyResponseHook func(
	ctx context.Context,
	req *http.Request,
	resp *http.Response,
	containerName string,
) *ProxyResponseDecision
