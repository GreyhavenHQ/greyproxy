package sniffing

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/observer/stats"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/recorder"
	dissector "github.com/greyhavenhq/greyproxy/internal/tlsdissector"
	xbypass "github.com/greyhavenhq/greyproxy/internal/gostx/bypass"
	xctx "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
	xio "github.com/greyhavenhq/greyproxy/internal/gostx/internal/io"
	xnet "github.com/greyhavenhq/greyproxy/internal/gostx/internal/net"
	xhttp "github.com/greyhavenhq/greyproxy/internal/gostx/internal/net/http"
	tls_util "github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/tls"
	ws_util "github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/ws"
	xstats "github.com/greyhavenhq/greyproxy/internal/gostx/observer/stats"
	stats_wrapper "github.com/greyhavenhq/greyproxy/internal/gostx/observer/stats/wrapper"
	xrecorder "github.com/greyhavenhq/greyproxy/internal/gostx/recorder"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

const (
	DefaultReadTimeout = 30 * time.Second

	// DefaultBodySize is the default HTTP body or websocket frame size to record.
	DefaultBodySize = 2 * 1024 * 1024 // 2MB
	// MaxBodySize is the maximum HTTP body or websocket frame size to record.
	MaxBodySize = 2 * 1024 * 1024 // 2MB
	// DeafultSampleRate is the default websocket sample rate (samples per second).
	DefaultSampleRate = 10.0
)

var (
	DefaultCertPool = tls_util.NewMemoryCertPool()
)

type HandleOptions struct {
	service string
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	dialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)

	bypass         bypass.Bypass
	recorderObject *xrecorder.HandlerRecorderObject
	log            logger.Logger
}

type HandleOption func(opts *HandleOptions)

func WithService(service string) HandleOption {
	return func(opts *HandleOptions) {
		opts.service = service
	}
}

func WithDial(dial func(ctx context.Context, network, address string) (net.Conn, error)) HandleOption {
	return func(opts *HandleOptions) {
		opts.dial = dial
	}
}

func WithDialTLS(dialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)) HandleOption {
	return func(opts *HandleOptions) {
		opts.dialTLS = dialTLS
	}
}

func WithBypass(bypass bypass.Bypass) HandleOption {
	return func(opts *HandleOptions) {
		opts.bypass = bypass
	}
}

func WithRecorderObject(ro *xrecorder.HandlerRecorderObject) HandleOption {
	return func(opts *HandleOptions) {
		opts.recorderObject = ro
	}
}

func WithLog(log logger.Logger) HandleOption {
	return func(opts *HandleOptions) {
		opts.log = log
	}
}

// HTTPRoundTripInfo contains decrypted HTTP request/response data from a MITM round-trip.
type HTTPRoundTripInfo struct {
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

// GlobalHTTPRoundTripHook is called (if set) after each MITM-intercepted HTTP round-trip.
// Set this from program initialization to record transactions to the database.
var GlobalHTTPRoundTripHook func(info HTTPRoundTripInfo)

// ErrRequestDenied is returned by the hold hook to indicate the request should be denied.
var ErrRequestDenied = errors.New("request denied")

// ErrNotHTTP is returned by HandleHTTP when the decrypted stream is not HTTP.
// The caller should fall back to raw piping.
var ErrNotHTTP = errors.New("not HTTP")

// HTTPRequestHoldInfo contains request details for the hold hook to evaluate.
type HTTPRequestHoldInfo struct {
	Host          string
	Method        string
	URI           string
	RequestHeaders http.Header
	RequestBody   []byte
	ContainerName string
}

// GlobalHTTPRequestHoldHook is called (if set) before forwarding a MITM-intercepted HTTP request upstream.
// Return nil to allow, ErrRequestDenied to send 403, or block until approval.
var GlobalHTTPRequestHoldHook func(ctx context.Context, info HTTPRequestHoldInfo) error

// globalMitmEnabled controls whether MITM TLS interception is active. Default: enabled (1).
var globalMitmEnabled atomic.Int32

func init() {
	globalMitmEnabled.Store(1) // enabled by default
}

// SetGlobalMitmEnabled enables or disables MITM TLS interception globally.
func SetGlobalMitmEnabled(enabled bool) {
	if enabled {
		globalMitmEnabled.Store(1)
	} else {
		globalMitmEnabled.Store(0)
	}
}

// IsMitmEnabled returns whether MITM TLS interception is globally enabled.
func IsMitmEnabled() bool {
	return globalMitmEnabled.Load() != 0
}

type Sniffer struct {
	Websocket           bool
	WebsocketSampleRate float64

	Recorder        recorder.Recorder
	RecorderOptions *recorder.Options

	// MITM TLS termination
	Certificate        *x509.Certificate
	PrivateKey         crypto.PrivateKey
	NegotiatedProtocol string
	CertPool           tls_util.CertPool
	MitmBypass         bypass.Bypass

	ReadTimeout time.Duration

	// UpstreamRootCAs overrides the system root CAs when verifying upstream TLS certificates.
	UpstreamRootCAs *x509.CertPool

	// OnHTTPRoundTrip is called after each decrypted HTTP round-trip with request/response details.
	OnHTTPRoundTrip func(info HTTPRoundTripInfo)

	// OnMitmSkip is called when MITM is skipped for a TLS connection, before piping starts.
	OnMitmSkip func()
}

func (h *Sniffer) HandleHTTP(ctx context.Context, network string, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	if h.ReadTimeout <= 0 {
		h.ReadTimeout = DefaultReadTimeout
	}

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)

	// Peek at the first bytes to verify this is actually HTTP before attempting
	// to parse. After MITM TLS termination without ALPN, the decrypted stream
	// could be a non-HTTP protocol. In that case, fall back to raw piping.
	if hdr, err := br.Peek(5); err == nil && !isHTTP(string(hdr)) {
		return ErrNotHTTP
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	log := ho.log
	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	ro := ho.recorderObject
	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   req.Host,
		Proto:  req.Proto,
		Scheme: req.URL.Scheme,
		Method: req.Method,
		URI:    req.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: req.ContentLength,
			Header:        req.Header.Clone(),
		},
	}

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
		ctx = xctx.ContextWithSrcAddr(ctx, &net.TCPAddr{IP: clientIP})
	}

	// http/2
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		return h.serveH2(ctx, network, xnet.NewReadWriteConn(br, conn, conn), &ho)
	}

	host := req.Host
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
		}
		ro.Host = host

		log = log.WithFields(map[string]any{
			"host": host,
		})

		if ho.bypass != nil && ho.bypass.Contains(ctx, network, host, bypass.WithService(ho.service)) {
			return xbypass.ErrBypass
		}
	}

	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, network, host)
	if err != nil {
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()
	ro.Time = time.Time{}

	shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, req, ro, &pStats, log)
	if err != nil || shouldClose {
		return err
	}

	for {
		pStats.Reset()

		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpRequest(req, false)
			log.Trace(string(dump))
		}

		if shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, req, ro, &pStats, log); err != nil || shouldClose {
			return err
		}
	}
}

func (h *Sniffer) serveH2(ctx context.Context, network string, conn net.Conn, ho *HandleOptions) error {
	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		return fmt.Errorf("h2: error reading client preface: %s", err)
	}
	if string(buf[:n]) != expectedBody {
		return errors.New("h2: invalid client preface")
	}

	ro := ho.recorderObject
	log := ho.log

	ro.Time = time.Time{}

	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, nw, addr string, cfg *tls.Config) (net.Conn, error) {
			if dial := ho.dialTLS; dial != nil {
				return dial(ctx, network, addr, cfg)
			}

			cc, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
			ro.SrcAddr = cc.LocalAddr().String()
			ro.DstAddr = cc.RemoteAddr().String()

			cc = tls.Client(cc, cfg)
			return cc, nil
		},
	}
	defer tr.CloseIdleConnections()

	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Context:          ctx,
		SawClientPreface: true,
		Handler: &h2Handler{
			transport:       tr,
			recorder:        h.Recorder,
			recorderOptions: h.RecorderOptions,
			recorderObject:  ro,
			log:             log,
			onHTTPRoundTrip: h.OnHTTPRoundTrip,
		},
	})
	return nil
}

func (h *Sniffer) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriteCloser, req *http.Request, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger) (close bool, err error) {
	close = true

	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro = ro2

	ro.Time = time.Now()
	log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if err := ro.Record(ctx, h.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	}()

	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   req.Host,
		Proto:  req.Proto,
		Scheme: req.URL.Scheme,
		Method: req.Method,
		URI:    req.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: req.ContentLength,
			Header:        req.Header.Clone(),
		},
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	var reqBody *xhttp.Body
	captureBody := (h.RecorderOptions != nil && h.RecorderOptions.HTTPBody) || h.OnHTTPRoundTrip != nil || GlobalHTTPRequestHoldHook != nil
	if captureBody {
		if req.Body != nil {
			bodySize := DefaultBodySize
			if opts := h.RecorderOptions; opts != nil && opts.MaxBodySize > 0 {
				bodySize = opts.MaxBodySize
			}
			if bodySize > MaxBodySize {
				bodySize = MaxBodySize
			}
			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	// Request-level hold: evaluate before forwarding upstream
	if GlobalHTTPRequestHoldHook != nil {
		containerName := string(xctx.ClientIDFromContext(ctx))
		if containerName == "" {
			containerName = ro.ClientID
		}
		// Read the body first so it's captured for the hook
		var holdBody []byte
		if reqBody != nil {
			// Force body to be read by reading through the tee
			bodyBuf := new(bytes.Buffer)
			if req.Body != nil {
				bodyBuf.ReadFrom(req.Body)
				// Reconstruct body for forwarding
				req.Body = io.NopCloser(bodyBuf)
				req.ContentLength = int64(bodyBuf.Len())
			}
			holdBody = reqBody.Content()
		}

		holdInfo := HTTPRequestHoldInfo{
			Host:           req.Host,
			Method:         req.Method,
			URI:            req.RequestURI,
			RequestHeaders: req.Header.Clone(),
			RequestBody:    holdBody,
			ContainerName:  containerName,
		}
		if holdErr := GlobalHTTPRequestHoldHook(ctx, holdInfo); holdErr != nil {
			// Request denied — send 403 to client
			denyResp := &http.Response{
				StatusCode: http.StatusForbidden,
				Proto:      req.Proto,
				ProtoMajor: req.ProtoMajor,
				ProtoMinor: req.ProtoMinor,
				Header:     http.Header{"Content-Type": {"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("Request denied by proxy")),
			}
			denyResp.ContentLength = 22
			denyResp.Write(rw)
			close = true
			return
		}
	}

	err = req.Write(cc)

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		return
	}

	br := bufio.NewReader(cc)
	var resp *http.Response
	for {
		xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
		resp, err = http.ReadResponse(br, req)
		if err != nil {
			err = fmt.Errorf("read response: %v", err)
			return
		}
		if resp.StatusCode == http.StatusContinue {
			resp.Write(rw)
			resp.Body.Close()
			continue
		}

		break
	}
	defer resp.Body.Close()
	xio.SetReadDeadline(cc, time.Time{})

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		h.handleUpgradeResponse(ctx, rw, cc, req, resp, ro, log)
		return
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if !resp.Close {
			resp.Header.Set("Connection", "keep-alive")
		}
		resp.ProtoMajor = req.ProtoMajor
		resp.ProtoMinor = req.ProtoMinor
	}

	var respBody *xhttp.Body
	if captureBody {
		bodySize := DefaultBodySize
		if opts := h.RecorderOptions; opts != nil && opts.MaxBodySize > 0 {
			bodySize = opts.MaxBodySize
		}
		if bodySize > MaxBodySize {
			bodySize = MaxBodySize
		}
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	err = resp.Write(rw)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if err != nil {
		err = fmt.Errorf("write response: %w", err)
		return
	}

	if h.OnHTTPRoundTrip != nil || GlobalHTTPRoundTripHook != nil {
		containerName := string(xctx.ClientIDFromContext(ctx))
		if containerName == "" {
			containerName = ro.ClientID
		}
		info := HTTPRoundTripInfo{
			Host:            req.Host,
			Method:          req.Method,
			URI:             req.RequestURI,
			Proto:           req.Proto,
			StatusCode:      resp.StatusCode,
			RequestHeaders:  ro.HTTP.Request.Header,
			ResponseHeaders: ro.HTTP.Response.Header,
			ContainerName:   containerName,
			DurationMs:      time.Since(ro.Time).Milliseconds(),
		}
		if reqBody != nil {
			info.RequestBody = reqBody.Content()
		}
		if respBody != nil {
			info.ResponseBody = respBody.Content()
		}
		if h.OnHTTPRoundTrip != nil {
			h.OnHTTPRoundTrip(info)
		}
		if GlobalHTTPRoundTripHook != nil {
			GlobalHTTPRoundTripHook(info)
		}
	}

	if resp.ContentLength >= 0 {
		close = resp.Close
	}

	return
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (h *Sniffer) handleUpgradeResponse(ctx context.Context, rw, cc io.ReadWriteCloser, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		return fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
	}

	res.Body = nil
	if err := res.Write(rw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}

	if reqUpType == "websocket" && h.Websocket {
		return h.sniffingWebsocketFrame(ctx, rw, cc, ro, log)
	}

	// return xnet.Transport(rw, cc)
	return xnet.Pipe(ctx, rw, cc)
}

func (h *Sniffer) sniffingWebsocketFrame(ctx context.Context, rw, cc io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	errc := make(chan error, 1)

	sampleRate := h.WebsocketSampleRate
	if sampleRate == 0 {
		sampleRate = DefaultSampleRate
	}
	if sampleRate < 0 {
		sampleRate = math.MaxFloat64
	}

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := h.copyWebsocketFrame(cc, rw, buf, "client", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, h.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := h.copyWebsocketFrame(rw, cc, buf, "server", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, h.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	<-errc
	return nil
}

func (h *Sniffer) copyWebsocketFrame(w io.Writer, r io.Reader, buf *bytes.Buffer, from string, ro *xrecorder.HandlerRecorderObject) (err error) {
	fr := ws_util.Frame{}
	if _, err = fr.ReadFrom(r); err != nil {
		return err
	}

	ws := &xrecorder.WebsocketRecorderObject{
		From:    from,
		Fin:     fr.Header.Fin,
		Rsv1:    fr.Header.Rsv1,
		Rsv2:    fr.Header.Rsv2,
		Rsv3:    fr.Header.Rsv3,
		OpCode:  int(fr.Header.OpCode),
		Masked:  fr.Header.Masked,
		MaskKey: fr.Header.MaskKey,
		Length:  fr.Header.PayloadLength,
	}
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = DefaultBodySize
		}
		if bodySize > MaxBodySize {
			bodySize = MaxBodySize
		}

		buf.Reset()
		if _, err := io.Copy(buf, io.LimitReader(fr.Data, int64(bodySize))); err != nil {
			return err
		}
		ws.Payload = buf.Bytes()
	}

	ro.Websocket = ws
	length := uint64(fr.Header.Length()) + uint64(fr.Header.PayloadLength)
	if from == "client" {
		ro.InputBytes = length
		ro.OutputBytes = 0
	} else {
		ro.InputBytes = 0
		ro.OutputBytes = length
	}

	fr.Data = io.MultiReader(bytes.NewReader(buf.Bytes()), fr.Data)
	if _, err := fr.WriteTo(w); err != nil {
		return err
	}

	return nil
}

func (h *Sniffer) HandleTLS(ctx context.Context, network string, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	if h.ReadTimeout <= 0 {
		h.ReadTimeout = DefaultReadTimeout
	}

	buf := new(bytes.Buffer)
	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	log := ho.log

	ro := ho.recorderObject
	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  clientHello.ServerName,
		ClientHello: hex.EncodeToString(buf.Bytes()),
	}
	if len(clientHello.SupportedProtos) > 0 {
		ro.TLS.Proto = clientHello.SupportedProtos[0]
	}

	// ctx = xctx.ContextWithClientAddr(ctx, xctx.ClientAddr(ro.RemoteAddr))

	host := clientHello.ServerName
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
		}
		ro.Host = host

		if ho.bypass != nil && ho.bypass.Contains(ctx, network, host, bypass.WithService(ho.service)) {
			return xbypass.ErrBypass
		}
	}

	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, network, host)
	if err != nil {
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	if !IsMitmEnabled() {
		ro.MitmSkipReason = "mitm_disabled"
	} else if h.Certificate != nil && h.PrivateKey != nil {
		if host == "" {
			host = ro.Host
		}
		if h.MitmBypass == nil || !h.MitmBypass.Contains(ctx, network, host, bypass.WithService(ho.service)) {
			return h.terminateTLS(ctx, network, xnet.NewReadWriteConn(io.MultiReader(buf, conn), conn, conn), cc, clientHello, &ho)
		}
		ro.MitmSkipReason = "mitm_bypass"
	} else {
		ro.MitmSkipReason = "no_cert"
	}

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
	serverHello, err := dissector.ParseServerHello(io.TeeReader(cc, buf))
	xio.SetReadDeadline(cc, time.Time{})

	if serverHello != nil {
		ro.TLS.CipherSuite = tls_util.CipherSuite(serverHello.CipherSuite).String()
		ro.TLS.CompressionMethod = serverHello.CompressionMethod
		if serverHello.Proto != "" {
			ro.TLS.Proto = serverHello.Proto
		}
		if serverHello.Version > 0 {
			ro.TLS.Version = tls_util.Version(serverHello.Version).String()
		}
	}

	if buf.Len() > 0 {
		ro.TLS.ServerHello = hex.EncodeToString(buf.Bytes())
	}

	if _, err := buf.WriteTo(conn); err != nil {
		return err
	}

	if h.OnMitmSkip != nil {
		h.OnMitmSkip()
	}

	log.Infof("%s <-> %s", ro.RemoteAddr, ro.Host)
	// xnet.Transport(conn, cc)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, ro.Host)

	return err
}

func (h *Sniffer) terminateTLS(ctx context.Context, network string, conn, cc net.Conn, clientHello *dissector.ClientHelloInfo, ho *HandleOptions) error {
	ro := ho.recorderObject
	log := ho.log

	// Deferred connect mode: if a hold hook is set, we do client-side TLS first
	// (without upstream) so we can read and evaluate HTTP requests before connecting.
	if GlobalHTTPRequestHoldHook != nil {
		return h.terminateTLSDeferred(ctx, network, conn, cc, clientHello, ho)
	}

	// Original flow: connect upstream first, then client
	nextProtos := clientHello.SupportedProtos
	if h.NegotiatedProtocol != "" {
		nextProtos = []string{h.NegotiatedProtocol}
	}

	cfg := &tls.Config{
		ServerName:   clientHello.ServerName,
		NextProtos:   nextProtos,
		CipherSuites: clientHello.CipherSuites,
		RootCAs:      h.UpstreamRootCAs,
	}
	if cfg.ServerName == "" {
		cfg.InsecureSkipVerify = true
	}
	clientConn := tls.Client(cc, cfg)
	if err := clientConn.HandshakeContext(ctx); err != nil {
		return err
	}

	cs := clientConn.ConnectionState()
	ro.TLS.CipherSuite = tls_util.CipherSuite(cs.CipherSuite).String()
	ro.TLS.Proto = cs.NegotiatedProtocol
	ro.TLS.Version = tls_util.Version(cs.Version).String()

	host := cfg.ServerName
	if host == "" {
		if host = cs.PeerCertificates[0].Subject.CommonName; host == "" {
			host = ro.Host
		}
	}
	if h, _, _ := net.SplitHostPort(host); h != "" {
		host = h
	}

	negotiatedProtocol := cs.NegotiatedProtocol
	if h.NegotiatedProtocol != "" {
		negotiatedProtocol = h.NegotiatedProtocol
	}
	nextProtos = nil
	if negotiatedProtocol != "" {
		nextProtos = []string{negotiatedProtocol}
	}

	// cache the tls server handshake record.
	wb := &bytes.Buffer{}
	conn = xnet.NewReadWriteConn(conn, io.MultiWriter(wb, conn), conn)

	serverConn := tls.Server(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certPool := h.CertPool
			if certPool == nil {
				certPool = DefaultCertPool
			}
			serverName := chi.ServerName
			if serverName == "" {
				serverName = host
			}
			cert, err := certPool.Get(serverName)
			if cert != nil {
				pool := x509.NewCertPool()
				pool.AddCert(h.Certificate)
				if _, err = cert.Verify(x509.VerifyOptions{
					DNSName: serverName,
					Roots:   pool,
				}); err != nil {
					log.Warnf("verify cached certificate for %s: %v", serverName, err)
					cert = nil
				}
			}
			if cert == nil {
				cert, err = tls_util.GenerateCertificate(serverName, 7*24*time.Hour, h.Certificate, h.PrivateKey)
				certPool.Put(serverName, cert)
			}
			if err != nil {
				return nil, err
			}

			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw, h.Certificate.Raw},
				PrivateKey:  h.PrivateKey,
			}, nil
		},
	})
	err := serverConn.HandshakeContext(ctx)
	if record, _ := dissector.ReadRecord(wb); record != nil {
		wb.Reset()
		record.WriteTo(wb)
		ro.TLS.ServerHello = hex.EncodeToString(wb.Bytes())
	}
	if err != nil {
		return err
	}

	opts := []HandleOption{
		WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
			return clientConn, nil
		}),
		WithDialTLS(func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return clientConn, nil
		}),
		WithRecorderObject(ro),
		WithLog(log),
	}
	if err := h.HandleHTTP(ctx, network, serverConn, opts...); err != nil && errors.Is(err, ErrNotHTTP) {
		// Decrypted stream is not HTTP (binary protocol over TLS).
		// Fall back to piping the decrypted connections.
		log.Debugf("MITM: decrypted stream is not HTTP, falling back to pipe")
		ro.MitmSkipReason = "non_http_after_tls"
		xnet.Pipe(ctx, serverConn, clientConn)
		return nil
	} else {
		return err
	}
}

// terminateTLSDeferred performs the client-side TLS handshake FIRST (without upstream),
// allowing us to read HTTP requests before deciding whether to connect upstream.
// This enables request-level hold/approval: the user sees the full HTTP request
// before any data reaches the destination.
func (h *Sniffer) terminateTLSDeferred(ctx context.Context, network string, conn, cc net.Conn, clientHello *dissector.ClientHelloInfo, ho *HandleOptions) error {
	ro := ho.recorderObject
	log := ho.log

	host := clientHello.ServerName
	if host == "" {
		host = ro.Host
	}
	if hostPart, _, _ := net.SplitHostPort(host); hostPart != "" {
		host = hostPart
	}

	// For deferred mode, prefer http/1.1 with the client but respect client ALPN if present.
	// (HTTP/2 deferred connect is a future enhancement)
	nextProtos := []string{"http/1.1"}
	if len(clientHello.SupportedProtos) > 0 {
		nextProtos = clientHello.SupportedProtos
	}

	ro.TLS.Proto = "http/1.1"

	// Step 1: TLS handshake with client (MITM) — no upstream connection yet
	wb := &bytes.Buffer{}
	conn = xnet.NewReadWriteConn(conn, io.MultiWriter(wb, conn), conn)

	serverConn := tls.Server(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certPool := h.CertPool
			if certPool == nil {
				certPool = DefaultCertPool
			}
			serverName := chi.ServerName
			if serverName == "" {
				serverName = host
			}
			cert, err := certPool.Get(serverName)
			if cert != nil {
				pool := x509.NewCertPool()
				pool.AddCert(h.Certificate)
				if _, err = cert.Verify(x509.VerifyOptions{
					DNSName: serverName,
					Roots:   pool,
				}); err != nil {
					log.Warnf("verify cached certificate for %s: %v", serverName, err)
					cert = nil
				}
			}
			if cert == nil {
				cert, err = tls_util.GenerateCertificate(serverName, 7*24*time.Hour, h.Certificate, h.PrivateKey)
				certPool.Put(serverName, cert)
			}
			if err != nil {
				return nil, err
			}
			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw, h.Certificate.Raw},
				PrivateKey:  h.PrivateKey,
			}, nil
		},
	})
	if err := serverConn.HandshakeContext(ctx); err != nil {
		return err
	}
	if record, _ := dissector.ReadRecord(wb); record != nil {
		wb.Reset()
		record.WriteTo(wb)
		ro.TLS.ServerHello = hex.EncodeToString(wb.Bytes())
	}

	// Step 2: Lazy upstream connection — established on first dial
	var upstreamOnce sync.Once
	var upstreamConn net.Conn
	var upstreamErr error

	lazyDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		upstreamOnce.Do(func() {
			// TLS handshake with upstream — match what we negotiated with the client
			upstreamCfg := &tls.Config{
				ServerName:   clientHello.ServerName,
				NextProtos:   nextProtos,
				CipherSuites: clientHello.CipherSuites,
				RootCAs:      h.UpstreamRootCAs,
			}
			if upstreamCfg.ServerName == "" {
				upstreamCfg.InsecureSkipVerify = true
			}
			tlsConn := tls.Client(cc, upstreamCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				upstreamErr = err
				return
			}
			cs := tlsConn.ConnectionState()
			ro.TLS.CipherSuite = tls_util.CipherSuite(cs.CipherSuite).String()
			ro.TLS.Version = tls_util.Version(cs.Version).String()
			upstreamConn = tlsConn
		})
		return upstreamConn, upstreamErr
	}

	// Step 3: HandleHTTP reads requests from the decrypted client connection
	// and forwards them via the lazy dialer
	opts := []HandleOption{
		WithDial(lazyDial),
		WithDialTLS(func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return lazyDial(ctx, network, address)
		}),
		WithRecorderObject(ro),
		WithLog(log),
	}
	if err := h.HandleHTTP(ctx, network, serverConn, opts...); err != nil && errors.Is(err, ErrNotHTTP) {
		// Decrypted stream is not HTTP. Establish upstream and pipe raw bytes.
		log.Debugf("MITM: decrypted stream is not HTTP, falling back to pipe")
		ro.MitmSkipReason = "non_http_after_tls"
		upstream, dialErr := lazyDial(ctx, network, "")
		if dialErr != nil {
			return dialErr
		}
		xnet.Pipe(ctx, serverConn, upstream)
		return nil
	} else {
		return err
	}
}

type h2Handler struct {
	transport       http.RoundTripper
	recorder        recorder.Recorder
	recorderOptions *recorder.Options
	recorderObject  *xrecorder.HandlerRecorderObject
	log             logger.Logger
	onHTTPRoundTrip func(info HTTPRoundTripInfo)
}

func (h *h2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.log

	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *h.recorderObject
	ro.Time = time.Now()

	var err error
	log.Infof("%s <-> %s", ro.RemoteAddr, r.Host)
	defer func() {
		ro.Duration = time.Since(ro.Time)
		if err != nil {
			ro.Err = err.Error()
		}
		if err := ro.Record(r.Context(), h.recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(ro.Time),
		}).Infof("%s >-< %s", ro.RemoteAddr, r.Host)
	}()

	if clientIP := xhttp.GetClientIP(r); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}
	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   r.Host,
		Proto:  r.Proto,
		Scheme: "https",
		Method: r.Method,
		URI:    r.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: r.ContentLength,
			Header:        r.Header.Clone(),
		},
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Trace(string(dump))
	}

	url := r.URL
	url.Scheme = "https"
	url.Host = r.Host
	req := &http.Request{
		Method:        r.Method,
		URL:           url,
		Host:          r.Host,
		Header:        r.Header,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Trailer:       r.Trailer,
	}

	var reqBody *xhttp.Body
	h2CaptureBody := (h.recorderOptions != nil && h.recorderOptions.HTTPBody) || h.onHTTPRoundTrip != nil
	if h2CaptureBody {
		if req.Body != nil {
			bodySize := DefaultBodySize
			if opts := h.recorderOptions; opts != nil && opts.MaxBodySize > 0 {
				bodySize = opts.MaxBodySize
			}
			if bodySize > MaxBodySize {
				bodySize = MaxBodySize
			}

			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	resp, err := h.transport.RoundTrip(req.WithContext(r.Context()))
	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	h.setHeader(w, resp.Header)
	w.WriteHeader(resp.StatusCode)

	var respBody *xhttp.Body
	if h2CaptureBody {
		bodySize := DefaultBodySize
		if opts := h.recorderOptions; opts != nil && opts.MaxBodySize > 0 {
			bodySize = opts.MaxBodySize
		}
		if bodySize > MaxBodySize {
			bodySize = MaxBodySize
		}
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	io.Copy(w, resp.Body)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if h.onHTTPRoundTrip != nil || GlobalHTTPRoundTripHook != nil {
		containerName := string(xctx.ClientIDFromContext(r.Context()))
		if containerName == "" {
			containerName = ro.ClientID
		}
		info := HTTPRoundTripInfo{
			Host:            r.Host,
			Method:          r.Method,
			URI:             r.RequestURI,
			Proto:           r.Proto,
			StatusCode:      resp.StatusCode,
			RequestHeaders:  ro.HTTP.Request.Header,
			ResponseHeaders: ro.HTTP.Response.Header,
			ContainerName:   containerName,
			DurationMs:      time.Since(ro.Time).Milliseconds(),
		}
		if reqBody != nil {
			info.RequestBody = reqBody.Content()
		}
		if respBody != nil {
			info.ResponseBody = respBody.Content()
		}
		if h.onHTTPRoundTrip != nil {
			h.onHTTPRoundTrip(info)
		}
		if GlobalHTTPRoundTripHook != nil {
			GlobalHTTPRoundTripHook(info)
		}
	}
}

func (h *h2Handler) setHeader(w http.ResponseWriter, header http.Header) {
	for k, v := range header {
		for i := range v {
			w.Header().Add(k, v[i])
		}
	}
}
