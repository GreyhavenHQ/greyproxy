package sniffing

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	tls_util "github.com/greyhavenhq/greyproxy/internal/gostx/internal/util/tls"
	xrecorder "github.com/greyhavenhq/greyproxy/internal/gostx/recorder"
)

// nopLogger satisfies logger.Logger for tests.
type nopLogger struct{}

func (nopLogger) WithFields(map[string]any) logger.Logger { return nopLogger{} }
func (nopLogger) Trace(args ...any)                        {}
func (nopLogger) Tracef(format string, args ...any)        {}
func (nopLogger) Debug(args ...any)                        {}
func (nopLogger) Debugf(format string, args ...any)        {}
func (nopLogger) Info(args ...any)                         {}
func (nopLogger) Infof(format string, args ...any)         {}
func (nopLogger) Warn(args ...any)                         {}
func (nopLogger) Warnf(format string, args ...any)         {}
func (nopLogger) Error(args ...any)                        {}
func (nopLogger) Errorf(format string, args ...any)        {}
func (nopLogger) Fatal(args ...any)                        {}
func (nopLogger) Fatalf(format string, args ...any)        {}
func (nopLogger) GetLevel() logger.LogLevel                { return logger.LogLevel("") }
func (nopLogger) IsLevelEnabled(logger.LogLevel) bool      { return false }

var testLog logger.Logger = nopLogger{}

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newTestSniffer(cert *x509.Certificate, key *ecdsa.PrivateKey) *Sniffer {
	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(cert)
	return &Sniffer{
		Certificate:     cert,
		PrivateKey:      key,
		CertPool:        tls_util.NewMemoryCertPool(),
		ReadTimeout:     5 * time.Second,
		UpstreamRootCAs: upstreamCAs,
	}
}

type tlsClientResult struct {
	conn *tls.Conn
	err  error
}

// startTLSClient starts a TLS handshake on one end of a net.Pipe and returns
// the other end (carrying the raw TLS ClientHello) plus a channel for the result.
func startTLSClient(t *testing.T, serverName string, rootCAs *x509.CertPool) (serverSide net.Conn, result <-chan tlsClientResult) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	ch := make(chan tlsClientResult, 1)
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName: serverName,
			RootCAs:    rootCAs,
		})
		err := tlsConn.Handshake()
		ch <- tlsClientResult{conn: tlsConn, err: err}
		if err != nil {
			clientConn.Close()
		}
	}()
	return serverConn, ch
}

func TestHandleTLS_NoCert(t *testing.T) {
	s := &Sniffer{ReadTimeout: 5 * time.Second}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	serverSide, clientResult := startTLSClient(t, "example.com", nil)
	ro := &xrecorder.HandlerRecorderObject{Host: "example.com:443"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	upstreamConn, err := net.Dial("tcp", upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.HandleTLS(ctx, "tcp", serverSide,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return upstreamConn, nil
			}),
			WithRecorderObject(ro),
			WithLog(testLog),
		)
	}()

	res := <-clientResult
	if res.conn != nil {
		res.conn.Close()
	}
	serverSide.Close()
	cancel()
	wg.Wait()

	if ro.MitmSkipReason != "no_cert" {
		t.Errorf("MitmSkipReason = %q, want %q", ro.MitmSkipReason, "no_cert")
	}
}

func TestHandleTLS_MitmDisabled(t *testing.T) {
	ca, caKey := generateTestCA(t)
	s := newTestSniffer(ca, caKey)

	SetGlobalMitmEnabled(false)
	defer SetGlobalMitmEnabled(true)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	serverSide, clientResult := startTLSClient(t, "example.com", nil)
	ro := &xrecorder.HandlerRecorderObject{Host: "example.com:443"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	upstreamConn, err := net.Dial("tcp", upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.HandleTLS(ctx, "tcp", serverSide,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return upstreamConn, nil
			}),
			WithRecorderObject(ro),
			WithLog(testLog),
		)
	}()

	res := <-clientResult
	if res.conn != nil {
		res.conn.Close()
	}
	serverSide.Close()
	cancel()
	wg.Wait()

	if ro.MitmSkipReason != "mitm_disabled" {
		t.Errorf("MitmSkipReason = %q, want %q", ro.MitmSkipReason, "mitm_disabled")
	}
}

func TestHandleTLS_SuccessfulMitm(t *testing.T) {
	origHoldHook := GlobalHTTPRequestHoldHook
	GlobalHTTPRequestHoldHook = nil
	defer func() { GlobalHTTPRequestHoldHook = origHoldHook }()

	ca, caKey := generateTestCA(t)
	s := newTestSniffer(ca, caKey)

	var capturedMethod string
	origRTHook := GlobalHTTPRoundTripHook
	GlobalHTTPRoundTripHook = func(info HTTPRoundTripInfo) {
		capturedMethod = info.Method
	}
	defer func() { GlobalHTTPRoundTripHook = origRTHook }()

	// Create upstream TLS server with a cert signed by our test CA for "example.com".
	upstreamCert, err := tls_util.GenerateCertificate("example.com", 24*time.Hour, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{upstreamCert.Raw},
			PrivateKey:  caKey,
		}},
	}
	upstream.StartTLS()
	defer upstream.Close()

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)
	serverSide, clientResult := startTLSClient(t, "example.com", caPool)
	ro := &xrecorder.HandlerRecorderObject{Host: "example.com:443"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var handleErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleErr = s.HandleTLS(ctx, "tcp", serverSide,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			WithRecorderObject(ro),
			WithLog(testLog),
		)
	}()

	res := <-clientResult
	if res.err != nil {
		t.Fatalf("client TLS handshake failed: %v", res.err)
	}

	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req.Write(res.conn)
	resp, err := http.ReadResponse(bufio.NewReader(res.conn), req)
	if err != nil {
		t.Fatalf("client HTTP read failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	res.conn.Close()
	wg.Wait()

	if handleErr != nil {
		t.Errorf("HandleTLS returned error: %v", handleErr)
	}
	if ro.MitmSkipReason != "" {
		t.Errorf("MitmSkipReason = %q, want empty (successful MITM)", ro.MitmSkipReason)
	}
	if capturedMethod != "GET" {
		t.Errorf("GlobalHTTPRoundTripHook captured method = %q, want %q", capturedMethod, "GET")
	}
}

func TestHandleTLS_ClientRejectsCert(t *testing.T) {
	// When the client rejects the forged cert, HandleTLS returns an error.
	// The sniffer does NOT set MitmSkipReason -- the handler layer must set "mitm_error".
	origHoldHook := GlobalHTTPRequestHoldHook
	GlobalHTTPRequestHoldHook = nil
	defer func() { GlobalHTTPRequestHoldHook = origHoldHook }()

	ca, caKey := generateTestCA(t)
	s := newTestSniffer(ca, caKey)

	// Upstream TLS server with cert signed by our test CA.
	upstreamCert, err := tls_util.GenerateCertificate("example.com", 24*time.Hour, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{upstreamCert.Raw},
			PrivateKey:  caKey,
		}},
	}
	upstream.StartTLS()
	defer upstream.Close()

	// Client uses an empty CA pool — it will reject the forged cert.
	emptyPool := x509.NewCertPool()
	serverSide, clientResult := startTLSClient(t, "example.com", emptyPool)
	ro := &xrecorder.HandlerRecorderObject{Host: "example.com:443"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var handleErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleErr = s.HandleTLS(ctx, "tcp", serverSide,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			WithRecorderObject(ro),
			WithLog(testLog),
		)
	}()

	res := <-clientResult
	if res.err == nil {
		res.conn.Close()
		t.Fatal("expected client TLS handshake to fail")
	}
	serverSide.Close()
	wg.Wait()

	if handleErr == nil {
		t.Error("expected HandleTLS to return error when client rejects cert")
	}
	// Sniffer does NOT set skip reason on error -- handler must set "mitm_error".
	if ro.MitmSkipReason != "" {
		t.Errorf("MitmSkipReason = %q, want empty (sniffer should not set it on TLS error)", ro.MitmSkipReason)
	}
}

func TestHandleTLS_NonHTTPAfterTLS(t *testing.T) {
	origHoldHook := GlobalHTTPRequestHoldHook
	GlobalHTTPRequestHoldHook = nil
	defer func() { GlobalHTTPRequestHoldHook = origHoldHook }()

	ca, caKey := generateTestCA(t)
	s := newTestSniffer(ca, caKey)

	// Upstream: plain TLS server that echoes data (not HTTP)
	upstreamLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLis.Close()

	upstreamCert, err := tls_util.GenerateCertificate("example.com", 24*time.Hour, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := upstreamLis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{upstreamCert.Raw},
				PrivateKey:  caKey,
			}},
		})
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		io.Copy(tlsConn, tlsConn)
	}()

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)
	serverSide, clientResult := startTLSClient(t, "example.com", caPool)
	ro := &xrecorder.HandlerRecorderObject{Host: "example.com:443"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var handleErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleErr = s.HandleTLS(ctx, "tcp", serverSide,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstreamLis.Addr().String())
			}),
			WithRecorderObject(ro),
			WithLog(testLog),
		)
	}()

	res := <-clientResult
	if res.err != nil {
		t.Fatalf("client TLS handshake failed: %v", res.err)
	}

	// Send binary (non-HTTP) data
	res.conn.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04})
	res.conn.Close()
	wg.Wait()

	if handleErr != nil {
		t.Errorf("HandleTLS returned error: %v (expected nil with pipe fallback)", handleErr)
	}
	if ro.MitmSkipReason != "non_http_after_tls" {
		t.Errorf("MitmSkipReason = %q, want %q", ro.MitmSkipReason, "non_http_after_tls")
	}
}
